/*   
 *   This is part of Remote System Call (RSC) Library.
 *
 *   event_monitor.c: server event subscription management
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
#define __USE_LARGEFILE64
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <poll.h>
#include <arpa/inet.h>
#include <assert.h>
#include <strings.h>

#include "debug.h"
#include "rsc_messages.h"
#include "generic_list.h"
/*************************************************/
/*     Static structures and local constants     */
/*************************************************/
static struct list *rscs_es_list;
#define RSCEM_EV_OCCURRED     0x01
#define RSCEM_EV_NOT_OCCURRED 0x02
struct rscs_es_listel {
 /* event subscriber fd, used to distinguish between two different 
  * event subscriber with same mfd and event */
 int esfd;  
 int mfd; /* monitored fd */
 short event;
 /* Show if the event 'event' is occurred or not */
 u_int8_t state; 
};
/****************************/
/*     Static functions     */
/****************************/
static int rscs_es_list_compare(void *el, void *arg) {
  struct rscs_es_listel *a = el;
  struct rscs_es_listel *b = arg;

  return ((a->esfd  == b->esfd) && 
          (a->mfd   == b->mfd)  &&
          (a->event == b->event));
}
static int is_a_regular_file(int fd) {
  struct stat64 stat;
  if(fstat64(fd, &stat) == -1)
    return 0;
  return S_ISREG(stat.st_mode);
}

#ifdef RSCDEBUG
# define PRINT_RSCEM_LIST(list) PRINT_LIST(list, print_rscel)
static void print_rscel(void *element) {
  struct rscs_es_listel *el = element;
  char *str;
  switch(el->state) {
    case RSCEM_EV_OCCURRED:
      str = "event occurred"; break;
    case RSCEM_EV_NOT_OCCURRED:
      str = "event not occurred"; break;
    default:
      str = "state error"; break;
  }
}

#else
# define PRINT_RSCEM_LIST(list)
#endif

/****************************/
/*     Global functions     */
/****************************/

void rscs_es_init() {
  rscs_es_list = init_list(10);
}
/* The function takes in input the file descriptor of the connection 
 * with the client (esfd) and the data read by the server (data), 
 * then analyzes the kind of message contained in data, executes an 
 * immediate test using a poll with timeout set to zero, creates a 
 * acknowledgment message based on the poll result and returns it.
 * */
struct rsc_es_ack *rscs_es_manage_msg(int esfd, void *data) {
  struct pollfd testfd[1];
  struct rsc_es_hdr *hdr = (struct rsc_es_hdr *)data;
  struct rsc_es_ack *ack;
  int ret = 0;
  assert(hdr->type == EVENT_SUB_REQ || hdr->type == EVENT_SUB_DEREG);
  ack = calloc(1, sizeof(struct rsc_es_ack));
  assert(ack != NULL);
  if(hdr->type == EVENT_SUB_REQ) {
    /* It's a event subscription */
    struct rsc_es_req *req = (struct rsc_es_req *)data;
    int is_regfile;
	  RSC_DEBUG(1, "It's a event subscribe request\n");
	  req->fd = ntohl(req->fd);
	  req->how = ntohl(req->how);
	
	  /* I test if is a fd of a regular file. A regular file 
     * never block during reading so I can sand back a 
     * positive ACK.  */
    if(!(is_regfile = is_a_regular_file(req->fd)) || req->how != POLLIN) {
	    bzero(&testfd[0], sizeof(struct pollfd));
	    testfd[0].fd = req->fd;
	    testfd[0].events = req->how;
	    ret = poll(testfd, 1, 0);
    } 
	  ack->type = EVENT_SUB_ACK;
	  ack->fd = htonl(req->fd);
	  ack->how = htonl(req->how);
	  if(is_regfile || (ret == 1 && testfd[0].revents == req->how)) {
	    RSC_DEBUG(1, "fd %d is ready for event %d, I send a positive ACK\n", req->fd, req->how);
	    ack->response = ACK_FD_READY;
	  } else {
	    RSC_DEBUG(1, "fd %d is NOT ready for event %d, I send a negative ACK \n", req->fd, req->how);
	    ack->response = ACK_FD_REG;
	  }
	  /* The fd isn't ready so I have to register it */
	  if(ack->response == ACK_FD_REG) {
      struct rscs_es_listel *el;
      el = calloc(1, sizeof(struct rscs_es_listel));
      assert(el != NULL);
      el->esfd = esfd;
      el->mfd = req->fd;
      el->event = req->how;
      el->state = RSCEM_EV_NOT_OCCURRED;
      RSC_DEBUG(1, "Before insert new element:");
      PRINT_RSCEM_LIST(rscs_es_list);
      list_add(rscs_es_list, el);
      RSC_DEBUG(1, "After inserted the new element:");
      PRINT_RSCEM_LIST(rscs_es_list);
	  }
  } else if(hdr->type == EVENT_SUB_DEREG) {
    struct rsc_es_dereg *rmev = (struct rsc_es_dereg *)data;
    int resp = ACK_FD_DEREG_NOT_READY;
    int index;
    struct rscs_es_listel *res;
    struct rscs_es_listel el;
	  RSC_DEBUG(1, "It's a event subscribe remove event. Before manage it:\n");
    rmev->fd = ntohl(rmev->fd);
    rmev->how = ntohl(rmev->how);
    bzero(&el, sizeof(struct rscs_es_listel));
    el.esfd = esfd;
    el.mfd = rmev->fd;
    el.event = rmev->how;
    RSC_DEBUG(1, "Before searching for esfd = %d, mfd = %d, event = %d:", el.esfd, el.mfd, el.event);
    PRINT_RSCEM_LIST(rscs_es_list);
    index = list_search(rscs_es_list, rscs_es_list_compare, &el);
    RSC_DEBUG(1, "index = %d:", index);
    res = list_getel(rscs_es_list, index);
    if( res != NULL) {
      /* Found, I remove and I send back an ACK with the result of the poll */
	    bzero(&testfd[0], sizeof(struct pollfd));
	    testfd[0].fd = res->mfd;
	    testfd[0].events = res->event;
	    ret = poll(testfd, 1, 0);
      if(ret == 1 && testfd[0].revents == res->event)
        resp = ACK_FD_DEREG_READY;
      /* I remove and free the element */
      free(list_del(rscs_es_list, index));
      RSC_DEBUG(1, "After deletion");
      PRINT_RSCEM_LIST(rscs_es_list);
    }
    /* Now I send the ACK back */
    ack->type = EVENT_SUB_ACK;
    ack->fd = htonl(rmev->fd);
    ack->how = htonl(rmev->how);
    ack->response = resp;
  }

  return ack;
}

/* It search the entry with the given values, changes
 * the state from RSCEM_EV_NOT_OCCURRED to RSCEM_EV_OCCURRED and
 * returns a response to send back to the event subscriber.
 * If the state was already RSCEM_EV_OCCURRED, NULL is returned.
 * */
struct rsc_es_resp *rscs_es_event_occurred(int esfd, int mfd, int event) {
  struct rscs_es_listel el, *res;
  struct rsc_es_resp *resp;
  int index;
	RSC_DEBUG(1, "Event %d occurred for fd 0x%X:\n", event, mfd);
  el.esfd = esfd;
  el.mfd = mfd;
  el.event = event;
  index = list_search(rscs_es_list, rscs_es_list_compare, &el);
  res = list_getel(rscs_es_list, index);
  if(res == NULL)
    return NULL;
  if(res->state == RSCEM_EV_OCCURRED)
    return NULL;
  res->state = RSCEM_EV_OCCURRED;
  resp = calloc(1, sizeof(struct rsc_es_resp));
  assert(resp != NULL);
  resp->type = EVENT_SUB_RESP;
  resp->fd = htonl(res->mfd);
  resp->how = htonl(res->event);
	RSC_DEBUG(1, "Created the response fd = %d, how = %d\n", ntohl(resp->fd), ntohl(resp->how));
  return resp;

} 
