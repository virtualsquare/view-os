/*   
 *   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   pollfd_info.h: Data structure used to trace server's clients 
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

#ifndef __POLLFD_INFO_HEADER__
#define __POLLFD_INFO_HEADER__
#include <sys/poll.h>
#include "aconv.h"

enum client_state {
  WAITING_ARCH = 1,
  SENDING_ARCH,
  CONN_READING_HDR,
  CONN_READING_BODY,
  CONN_SENDING_RESP
};

enum client_type {
  REQ_RESP = 1,
  EVENT_SUB,
  SUBSCRIBED_FD
};

struct buffer {
  struct msg *first;
  struct msg *last;
};
struct msg {
  void *data;    /* the pointer to data */
  unsigned int n; /* number of byte of data into the buffer */
  unsigned int tot; /* total number of bytes to read/write */
  struct msg *next;
};

struct client {
  int fd;
  enum arch arch;
  enum client_type type;
  enum client_state state;
  struct buffer *rbuf; /* reading buffer */
  struct buffer *wbuf; /* writing buffer */
  int esfd_index;
};


#define   POLLFD_INITIAL_SIZE   10
struct pollfd_info {
  struct pollfd *pollfd;
  /* The number of used entries into 'pollfd' and 'clients' */
  int nfds;
  /* The size of 'pollfd' and 'clients'*/
  int size;
  /* The i-th file descriptor in 'pollfd' belongs to the i-th client 
   * in 'clients' */
  struct client **clients;
};

struct pollfd_info *pollfd_init();
void pollfd_add(struct pollfd_info *p, int fd, short events, struct client *c);
void pollfd_del(struct pollfd_info *p, int i);
void pollfd_compact(struct pollfd_info *p);

struct msg *buff_enq(struct buffer *b, void *data, int tot);
void *buff_deq(struct buffer *b);
struct client *create_client(int fd, enum client_type type, enum client_state state);
#ifdef GDEBUG_ENABLED
# define  PRINT_POLLFDINFO(p)   print_pollfd_info(p)

void print_pollfd_info(struct pollfd_info *p);
#else
# define  PRINT_POLLFDINFO(p)
#endif
#endif /* __POLLFD_INFO_HEADER__ */
