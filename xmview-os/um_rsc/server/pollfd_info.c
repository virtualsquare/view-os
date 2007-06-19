/*   
 *   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   pollfd_info.c: Data structure used to trace server's clients 
 *   
 *   Copyright (C) 2007 Andrea Forni
 *   
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License, version 2, as
 *   published by the Free Software Foundation.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA.
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <sys/poll.h>
#include "pollfd_info.h"
#include "aconv.h"


/**************************************************************/
/* Client elements                                            */
/**************************************************************/
#ifdef GDEBUG_ENABLED
static char *client_state_str[] = {
  "waiting architecture",
  "sending architecture",
  "connected: reading header",
  "connected: reading body",
  "connected: sending response",
  "connected: sending ack"
};

static char *client_type_str[] = {
  "request response",
  "event subscribe",
  "registered fd"
};
#endif

struct msg *buff_enq(struct buffer *b, void *data, int tot) {
  struct msg *m;
  m = calloc(1, sizeof(struct msg));
  if(m == NULL)
    return m;
  m->data = data;
  m->tot = tot;
  if(b->first == NULL)
    b->first = b->last = m;
  else {
    b->last->next = m;
    b->last = m;
  }
  return m;
}

/* Free the first buffer in 'bs' and returns its data */
void *buff_deq(struct buffer *b) {
  void *data;
  struct msg *m;
  if(b->first == NULL)
    return NULL;
  data = b->first->data;
  /* Is las element? */
  m = b->first;
  if(b->first->next == NULL) {
    b->first = b->last = NULL;
  } else {
    b->first = b->first->next;
  }

  free(m);
  return data;
}
static void free_msg(struct msg *m) {
  free(m->data);
  free(m);
}
/* Free client c and all the messages into the 2 buffers */
static void free_client(struct client *c){
  struct msg *m, *next;
  if(c->rbuf != NULL) {
    m = c->rbuf->first;
    while(m) {
      next = m->next;
      free_msg(m);
      m = next;
    }
  }
  if(c->wbuf != NULL) {
    m = c->wbuf->first;
    while(m) {
      next = m->next;
      free_msg(m);
      m = next;
    }
  }
  free(c->rbuf);
  free(c->wbuf);

  free(c);
}
struct client *create_client(int fd, enum client_type type, enum client_state state) {
  struct client *client;

  client = calloc (1, sizeof(struct client));
  if(client == NULL)
    return NULL;
  client->rbuf = calloc(1, sizeof(struct buffer));
  client->wbuf = calloc(1, sizeof(struct buffer));
  if(client->rbuf == NULL) {
    free(client);
    return NULL;
  }
  if(client->wbuf == NULL) {
    free(client->rbuf);
    free(client);
    return NULL;
  }
  
  client->fd = fd;
  client->type = type;
  client->arch = ACONV_ARCH_ERROR;
  client->state = state;

  return client;
}
/**************************************************************/
/* Pollfd management                                          */
/**************************************************************/

static void init_empty_entry(struct pollfd_info *p, int i) {
  p->pollfd[i].fd     = -1; 
  p->pollfd[i].events  = 0; 
  p->pollfd[i].revents = 0; 
  p->clients[i] = NULL;
}

struct pollfd_info *pollfd_init() {
  int i;
  struct pollfd_info *p;
  p = calloc(1, sizeof(struct pollfd_info));
  if(p == NULL) 
    return NULL;
  p->pollfd = calloc(POLLFD_INITIAL_SIZE, sizeof(struct pollfd));
  if(p->pollfd == NULL) {
    free(p);
    return NULL;
  }
  p->clients = calloc(POLLFD_INITIAL_SIZE, sizeof(struct client *));
  if(p->pollfd == NULL) {
    free(p->pollfd); free(p);
    return NULL;
  }
  
  p->nfds = 0;
  p->size = POLLFD_INITIAL_SIZE;
  for(i = 0; i < p->size; i++) {
    init_empty_entry(p, i);
  }

  return p;
}

void pollfd_add(struct pollfd_info *p, int fd, short events, struct client *c) {
  int empty_i = -1;
  /* I have to enlarge the array */
  if(p->nfds >= p->size) {
    int i;
    p->size += POLLFD_INITIAL_SIZE;
    p->pollfd  = realloc(p->pollfd,  p->size * sizeof(struct pollfd));
    p->clients = realloc(p->clients, p->size * sizeof(struct client *));
    assert(p->pollfd != NULL && p->clients != NULL);
    /* I init the new entries created */
    for(i = p->nfds; i < p->size; i++) {
      init_empty_entry(p, i);
    }
    empty_i = p->nfds;
  } else {
    int i;
    for(i = 0; i < p->size; i++)
      if(p->pollfd[i].fd == -1) {
        empty_i = i;
        break;
      }
  }
 
 p->pollfd[empty_i].fd       = fd;
 p->pollfd[empty_i].events   = events;
 p->pollfd[empty_i].revents  = 0;
 p->clients[empty_i]         = c;

 p->nfds += 1;
}

void pollfd_del(struct pollfd_info *p, int i) {
  if(i < 0 || i >= p->size)
    return;
  free_client(p->clients[i]);
  init_empty_entry(p, i);
  p->nfds -= 1;
}

void pollfd_compact(struct pollfd_info *p) {
  int i, j;
  for(i = 0, j = 0; i < p->size; i++) {
    if(p->pollfd[i].fd == -1) {
      continue;
    } else {
      if(j < i) {
        p->pollfd[j] = p->pollfd[i];
        p->clients[j] = p->clients[i];
        init_empty_entry(p, i);
      }
      j++;
    }
  }
}

#ifdef GDEBUG_ENABLED
static char *client_state_2_str(enum client_state state) {
  return client_state_str[state - 1];
}

static char *client_type_2_str(enum client_type type) {
  return client_type_str[type - 1];
}
static void print_buffer(struct buffer *b, char *name) {
  struct msg *m;
  fprintf(stderr, "\t\t%s (first = %p; last = %p):\n", name, b->first, b->last);
  m = b->first;
  while(m) {
    fprintf(stderr, "\t\t\t- (%p): data = %p (%d/%d bytes), next = %p\n", 
        m, m->data, m->n, m->tot, m->next);
    m = m->next;
  }
}
static void print_client(struct client *client) {
  if(client == NULL) 
    fprintf(stderr, "NO_CLIENT");
  else {
    fprintf(stderr, "(%p): ", client);
    switch(client->type) {
      case REQ_RESP:
        fprintf(stderr, "FD = '%d'; TYPE = '%s'; ARCH = '%s'; STATE = '%s'\n", client->fd, 
          client_type_2_str(client->type),
          aconv_arch2str(client->arch),         
          client_state_2_str(client->state));
          print_buffer(client->rbuf, "Read buffer");
          print_buffer(client->wbuf, "Write buffer");
        break;
      case EVENT_SUB:
        fprintf(stderr, "FD = '%d'; TYPE = '%s'; STATE = '%s''\n", client->fd, 
            client_type_2_str(client->type), client_state_2_str(client->state));
        print_buffer(client->rbuf, "Read buffer");
        print_buffer(client->wbuf, "Write buffer");
        break;
      default:
        fprintf(stderr, "DATA_FD = '%d'; TYPE = '%s'; EVENT SUB FD INDEX = %d", 
            client->fd, client_type_2_str(client->type), client->esfd_index);
        break;
    }
  }
}

void print_pollfd_info(struct pollfd_info *p) {
  int i;
  fprintf(stderr, "Pollfd info: nfds = %d, size = %d:\n", p->nfds, p->size);
  for(i = 0; i < p->size; i++) {
    fprintf(stderr, "\t%d", i);
    if(p->pollfd[i].fd != -1)
      fprintf(stderr, ". (FD = %.2d, E = %hX): ", p->pollfd[i].fd, p->pollfd[i].events);
    else
      fprintf(stderr, ". ");
    print_client(p->clients[i]);
    fprintf(stderr, "\n");
  }
}
#endif
