/*   
 *   This is part of Remote System Call (RSC) Library.
 *
 *   event_subscription.c: client event subscription management
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
#include <pthread.h>
#include <errno.h>
#include <strings.h>
#include <assert.h>
#include <arpa/inet.h>
#include "utils.h"
#include "debug.h"
#include "rsc_client.h"
#include "registered_callbacks.h"

/******************************************/
/*     Local functions and structures     */
/******************************************/
static pthread_mutex_t reg_cbs_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t reg_cbs_cond = PTHREAD_COND_INITIALIZER;
/* Structure with the arguments passed to the thread */
struct rscc_es_thread_args {
  struct reg_cbs *reg_cbs;
  int event_sub_fd;
}; 

/* The thread wait to read a response, delete the entry
 * from 'reg_cbs' and execute the system call. */
static void *rscc_es_thread(void *thread_arg) {
  struct rscc_es_thread_args *args = (struct rscc_es_thread_args *)thread_arg;
  struct reg_cbs *reg_cbs = args->reg_cbs;
  int event_sub_fd = args->event_sub_fd;
  void (* cb)();
  void *arg;
  struct rsc_es_resp resp;
  struct rsc_es_ack ack;
  struct rsc_es_hdr hdr;
  int ret, i;

  
  while(1) {
    RSC_DEBUG(RSCD_EVENT_SUB, "thread before read: reg_cbs = %p, event_sub_fd = %d", reg_cbs, event_sub_fd);

    ret = read_n_bytes(event_sub_fd, &hdr, sizeof(hdr));
    RSC_DEBUG(RSCD_EVENT_SUB, "After read:");
	  pthread_mutex_lock(&reg_cbs_mutex);
    PRINT_REGCBS(reg_cbs);
	  pthread_mutex_unlock(&reg_cbs_mutex);
    /* Connection closed, I return */
    if(ret == 0) {
      RSC_DEBUG(RSCD_EVENT_SUB, "ret == 0, I close the thread");
      return 0;
    }

    if(ret == sizeof(hdr)) {
      RSC_DEBUG(RSCD_EVENT_SUB, "hdr.type = %d", hdr.type);
      /* ACK or response management */
      if(hdr.type == EVENT_SUB_ACK) {
        int size = sizeof(ack) - sizeof(hdr);
        int reg_cbs_size;
        ack.type = hdr.type;
        RSC_DEBUG(RSCD_EVENT_SUB, "It's an ACK");
        ret = read_n_bytes(event_sub_fd, ((char *)&ack) + sizeof(hdr), size);
        if(ret == size) {
          ack.fd = ntohl(ack.fd);
          ack.how = ntohl(ack.how);
          RSC_DEBUG(RSCD_EVENT_SUB, "ACK fields: response = %d, fd = %d, how = %d",
              ack.response, ack.fd, ack.how);

	        pthread_mutex_lock(&reg_cbs_mutex);
          for(i = 0; i < reg_cbs->size; i++)
            if(reg_cbs->v[i].fd == ack.fd && reg_cbs->v[i].how == ack.how) {
              reg_cbs->v[i].ack = ack.response;
              RSC_DEBUG(RSCD_EVENT_SUB, "Found entry: fd = %d, how = %d. I changed ack to %d", 
                 reg_cbs->v[i].fd, reg_cbs->v[i].how, reg_cbs->v[i].ack);
              break;
            }
          reg_cbs_size = reg_cbs->size;
          /* If I don't find the entry, I discard the ACK */
          if(i < reg_cbs_size) {
            RSC_DEBUG(RSCD_EVENT_SUB, "The entry was found and changed, so I can inform the  event_subscribe()");
            if((ret = pthread_cond_signal(&reg_cbs_cond)) != 0)
              fprintf(stderr, "pthread_cond_signal error %d\n", ret);
	          pthread_mutex_unlock(&reg_cbs_mutex);
            RSC_DEBUG(RSCD_EVENT_SUB, "Informed");
          } else
	          pthread_mutex_unlock(&reg_cbs_mutex);
        }
      } else if(hdr.type == EVENT_SUB_RESP) {
        int size = sizeof(resp) - sizeof(hdr);
        RSC_DEBUG(RSCD_EVENT_SUB, "It's an subscription response ");
        resp.type = hdr.type;
        ret = read_n_bytes(event_sub_fd, ((char *)&resp) + sizeof(hdr), size);
        if(ret == size) {
          resp.fd  = ntohl(resp.fd);
          resp.how = ntohl(resp.how);
		      cb = arg = NULL;
		      /* I search the entry */
		      RSC_DEBUG(RSCD_EVENT_SUB, "searching entry for fd = %d, how = %d", resp.fd, resp.how);
		      pthread_mutex_lock(&reg_cbs_mutex);
		      PRINT_REGCBS(reg_cbs);
		      for(i = 0; i < reg_cbs->size; i++) 
		        if(reg_cbs->v[i].fd == resp.fd && reg_cbs->v[i].how == resp.how) {
		          /* found, I maintain the entry, but I set the flag to avoid the re-execution of the cb */
              if(!reg_cbs->v[i].cb_executed) {
		            cb = reg_cbs->v[i].cb;
		            arg = reg_cbs->v[i].arg;
                reg_cbs->v[i].cb_executed = 1;
              }

		          
		          break;
		        }
		      pthread_mutex_unlock(&reg_cbs_mutex);
		      
		      /* I execute the callback */
		      if(cb != NULL) {
		        RSC_DEBUG(RSCD_EVENT_SUB, "found entry for fd = %d. cb = %p, arg = %p. I execute the callback", resp.fd, cb, arg);
		        PRINT_REGCBS(reg_cbs);
		        cb(arg);
		      }
        }
      } else { /* else: error, I do nothing */
        printf("Error, hdr.type = %d\n", hdr.type);
      }
      
    }
  }
  return NULL;
}

/****************************/
/*     Global functions     */
/****************************/
struct reg_cbs *rscc_es_init(int event_sub_fd) {
  struct reg_cbs *reg_cbs;
  struct rscc_es_thread_args *args;
  pthread_t thread;
  /* I init the registered callbacks list */
  if((reg_cbs = init_reg_cb()) == NULL)
    return NULL;

  RSC_DEBUG(RSCD_EVENT_SUB, "After init of reg_cbs: ");
  PRINT_REGCBS(reg_cbs);

  /* I create a thread that receives the server's
   * response and calls the right callback. */
  args = calloc(1, sizeof(struct rscc_es_thread_args));
  args->reg_cbs = reg_cbs;
  args->event_sub_fd = event_sub_fd;
  pthread_create(&thread, NULL, rscc_es_thread, args);
  
  return reg_cbs;
}

/* It sends the request to the 'server_fd' and it waits the answer. 
 * If the ACK is positive, the informations are store into 'reg_cbs' */
int rscc_es_send_req(struct reg_cbs *reg_cbs, int server_fd, int event_sub_fd, int how, void (* cb)(), void *arg) {
  int i, ret = 0;
    
  RSC_DEBUG(RSCD_EVENT_SUB, "send_event_sub_req (fd = %d):", server_fd);
  /* If 'cb' == NULL the previous registration for the callback must be deleted */
  if(cb == NULL) {
    struct rsc_es_dereg rmev;
    
    RSC_DEBUG(RSCD_EVENT_SUB, "cb == NULL. reg_cbs->nentry = %d", reg_cbs->nentry);
    if(reg_cbs->nentry > 0) {
	    pthread_mutex_lock(&reg_cbs_mutex);
      for(i = 0; i < reg_cbs->size; i++)
        if(reg_cbs->v[i].fd == event_sub_fd && reg_cbs->v[i].how == how )
         break; 
      /* found? */
      if( i < reg_cbs->size) {
	      /* I send a request to se server to rm the registered event */
	      bzero(&rmev, sizeof(rmev));
	      rmev.type = EVENT_SUB_DEREG;
	      rmev.fd = htonl(event_sub_fd);
	      rmev.how = htonl(how);
		    ret = write_n_bytes(server_fd, &rmev, sizeof(rmev));
		    RSC_DEBUG(RSCD_EVENT_SUB, "I've sent the remove request for fd = %d, how = %d", event_sub_fd, how);
		    if(ret != sizeof(rmev))
		      return -1;
		    RSC_DEBUG(RSCD_EVENT_SUB, "Now I wait the ACK read by the thread" );
	      if((ret = pthread_cond_wait(&reg_cbs_cond, &reg_cbs_mutex)) != 0)
	        fprintf(stderr, "pthread_cond_wait error %d\n", ret);
	      RSC_DEBUG(RSCD_EVENT_SUB, "The thread unblocked me, maybe the ACK is arrived:");
	      PRINT_REGCBS(reg_cbs);
	      switch(reg_cbs->v[i].ack) {
	        case ACK_FD_DEREG_NOT_READY:
	          /* the fd isn't ready so it was registered by the server,
	           *  I return a zero value */
	          RSC_DEBUG(RSCD_EVENT_SUB, "The FD wasn't ready and was de-registered");
	          ret = 0;
	          break;
	        case ACK_FD_DEREG_READY:
	          /* the fd is ready, I remove the entry from the list and 
	           * I return a non-zero value */
	          RSC_DEBUG(RSCD_EVENT_SUB, "The FD was ready and was de-registered");
	          ret = reg_cbs->v[i].how;
	          break;
	      }
        reg_cb_del(reg_cbs, i);
	      RSC_DEBUG(RSCD_EVENT_SUB, "I've removed the entry #%d", i);
        PRINT_REGCBS(reg_cbs);
      }
	    pthread_mutex_unlock(&reg_cbs_mutex);
      return ret;
    }
    return 0;

  } else {
    struct rsc_es_req req;
    int index;
	  /* I send the request */
	  pthread_mutex_lock(&reg_cbs_mutex);
    if(reg_cbs->nentry > 0) {
      for(i = 0; i < reg_cbs->size; i++)
        if(reg_cbs->v[i].fd == event_sub_fd && reg_cbs->v[i].how == how )
          break;
      if(i < reg_cbs->size) {
        /* Found, don't do anything, I return */
	      RSC_DEBUG(RSCD_EVENT_SUB, "Already registered: fd = %d, how = %d", event_sub_fd, how);
	      PRINT_REGCBS(reg_cbs);
	      pthread_mutex_unlock(&reg_cbs_mutex);
        return 1;
      }
    }
    bzero(&req, sizeof(req));
	  req.type = EVENT_SUB_REQ;
	  req.fd = htonl(event_sub_fd);
	  req.how = htonl(how);
    /* I don't have an already registered fd */

	  RSC_DEBUG(RSCD_EVENT_SUB, "New request: type = %d, fd = %d, how = %d",
        req.type, ntohl(req.fd), ntohl(req.how));
	  ret = write_n_bytes(server_fd, &req, sizeof(struct rsc_es_req));
	  if(ret != sizeof(struct rsc_es_req))
	    return -1;
	  index = reg_cb_add(reg_cbs, cb, arg, event_sub_fd, how);
    assert(index != -1);
	  RSC_DEBUG(RSCD_EVENT_SUB, "Req sent, I've added a new entry to reg_cbs: ");
	  PRINT_REGCBS(reg_cbs);
	  RSC_DEBUG(RSCD_EVENT_SUB, "Now I wait the ACK read by the thread" );
    if((ret = pthread_cond_wait(&reg_cbs_cond, &reg_cbs_mutex)) != 0)
      fprintf(stderr, "pthread_cond_wait error %d\n", ret);
    RSC_DEBUG(RSCD_EVENT_SUB, "The thread unblocked me, maybe the ACK is arrived:");
    PRINT_REGCBS(reg_cbs);


    switch(reg_cbs->v[index].ack) {
      case ACK_FD_REG:
        /* the fd isn't ready so it was registered by the server,
         *  I return a zero value */
        RSC_DEBUG(RSCD_EVENT_SUB, "The FD was registered");
        ret = 0;
        break;
      case ACK_FD_READY:
        /* the fd is ready, I remove the entry from the list and 
         * I return a non-zero value */
        ret = reg_cbs->v[index].how;
        reg_cb_del(reg_cbs, index);
        RSC_DEBUG(RSCD_EVENT_SUB, "The FD is ready, I've deleted the entry:");
        PRINT_REGCBS(reg_cbs);
        break;
    }
	  pthread_mutex_unlock(&reg_cbs_mutex);
    return ret;
  } 
  return ret;
}
