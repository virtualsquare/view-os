/*   
 *   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   rsc_server.c: UMView Remote System Call module's server 
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
#include <string.h>
#include <errno.h>
#define __USE_LARGEFILE64
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <getopt.h>
#include <libgen.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/poll.h>
#include <sys/stat.h>
#include "gdebug.h"

#include "rsc_server.h"

#include "handshake.h"
#include "pollfd_info.h"

/* For ioctl requests */
#include <asm/sockios.h>
#include <asm/termios.h>
#include <asm/ioctls.h>
#include <linux/serial.h>
#include <linux/fd.h>
#include <linux/fs.h>
#include <linux/hdreg.h>
/**********************/

/*####################################################################*/
/*# Constants                                                         #*/
/*####################################################################*/
#define SERVER_ADDR "0.0.0.0"
#define SERVER_PORT "8050"
#define SERVER_PORT_EVENT_SUB "8051"
#define MAX_CONNECTIONS 5

/*####################################################################*/
/*# Global Variables                                                 #*/
/*####################################################################*/
static enum arch my_arch;
static struct pollfd_info *pfdinfo;

/*####################################################################*/
/*# Local Functions                                                  #*/
/*####################################################################*/

/*******************/
/* Other Functions */
/*******************/
static void print_addr_port(int fd)
{
    struct sockaddr_in info4;
    struct sockaddr_in6 info6;
    struct sockaddr *info;
    void *addr;
    u_int16_t *port;
    u_int16_t family;
    
    socklen_t info_len;
    char str_addr[INET6_ADDRSTRLEN];
   
    /* I get the family (AF_INET, AF_INET6, ...) of the socket */
    info = malloc(sizeof(struct sockaddr));
    info_len = sizeof(struct sockaddr);
    if( getsockname(fd, info, &info_len) != 0 )
      fprintf(stderr, "getsockname() error: %s\n", strerror(errno));

    family = info->sa_family;
    free(info);
    
    /* Now that I have the family, I set the fields for
     * the query based on the family type */
    if(family == AF_INET) {
      
      bzero(&info4, sizeof(info4));
      info_len = sizeof(info4);
      info = (struct sockaddr *)(&info4);
      addr = &(info4.sin_addr);
      port = &(info4.sin_port);
    
    } else if(family == AF_INET6) {
      
      bzero(&info6, sizeof(info6));
      info_len = sizeof(info6);
      info = (struct sockaddr *)(&info6);
      addr = &(info6.sin6_addr);
      port = &(info6.sin6_port);
    
    } else {
      /* If the family isn't AF_INET or AF_INET6 I clear the variables,
       * in this way the functions that will use them, will genereate 
       * an error*/
      info_len = 0;
      info = addr = port = NULL;
    }
    
    /* I get the info ...*/
    if( getsockname(fd, info, &info_len) != 0 )
      fprintf(stderr, "getsockname() error: %s\n", strerror(errno));
    
    /* ... and I print them. */
    if( inet_ntop(family, addr, str_addr, INET6_ADDRSTRLEN ) == NULL )
      fprintf(stderr, "inet_ntop() error: %s\n", strerror(errno));

    GDEBUG(1, "<%s, %d>", str_addr, ntohs(*port));
}


static int create_listening_fd(char *server_addr, char *server_port) {
  struct addrinfo hint, *res;
  int fd, ret, on;
  
  bzero(&hint, sizeof(hint));
  hint.ai_socktype = SOCK_STREAM;
  if( (ret = getaddrinfo(server_addr, server_port, &hint, &res))  != 0) {
    fprintf(stderr, "I cannot getaddrinfo(): %s\n", gai_strerror(ret));
    return -1;
  }

  /* Creation of the listening socket  */
  if ((fd = socket(res->ai_family, res->ai_socktype, 0)) == -1 ) {
    fprintf(stderr, "I cannot create the listen socket: %s\n", strerror(errno));
    return -1;
  }
  
  /* Setting the "reuse address" option */
  on = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)); 

  /* Binding */
  if (bind(fd, res->ai_addr, res->ai_addrlen) != 0 ) {
    fprintf(stderr, "I cannot bind the listen socket: %s\n", strerror(errno));
    return -1;
  }
  
  /* Listening */
  if(listen(fd, MAX_CONNECTIONS) == -1) {
    fprintf(stderr, "I cannot accept the connections: %s\n", strerror(errno));
    return -1;
  }
  
  GDEBUG(1, "Server listening on "); print_addr_port(fd); GDEBUG(1, " (fd = %d).\n", fd);

  freeaddrinfo(res);

  return fd;
}

static void init_ioctl_register_request(void) {
  /* asm/sockios.h */
  rscs_ioctl_register_request(FIOSETOWN, IOCTL_R, sizeof(const int));
  rscs_ioctl_register_request(SIOCSPGRP, IOCTL_R, sizeof(const int));
  rscs_ioctl_register_request(FIOGETOWN, IOCTL_W, sizeof(int));
  rscs_ioctl_register_request(SIOCGPGRP, IOCTL_W, sizeof(int));
  rscs_ioctl_register_request(SIOCATMARK, IOCTL_W, sizeof(int));
  rscs_ioctl_register_request(SIOCGSTAMP, IOCTL_W, sizeof(struct timeval));
  /* asm/termios.h */
  /* asm/ioctls.h */
  /* linux/serial.h */
  rscs_ioctl_register_request(TCGETS, IOCTL_W, sizeof(struct termios));
  rscs_ioctl_register_request(TCSETS, IOCTL_R, sizeof(const struct termios));
  rscs_ioctl_register_request(TCSETSW, IOCTL_R, sizeof(const struct termios));
  rscs_ioctl_register_request(TCSETSF, IOCTL_R, sizeof(const struct termios));
  rscs_ioctl_register_request(TCGETA, IOCTL_W, sizeof(struct termio));
  rscs_ioctl_register_request(TCSETA, IOCTL_R, sizeof(const struct termio));
  rscs_ioctl_register_request(TCSETAW, IOCTL_R, sizeof(const struct termio));
  rscs_ioctl_register_request(TCSETAF, IOCTL_R, sizeof(const struct termio));
  rscs_ioctl_register_request(TCSBRK, IOCTL_W, sizeof(int));
  rscs_ioctl_register_request(TCXONC, IOCTL_W, sizeof(int));
  rscs_ioctl_register_request(TCFLSH, IOCTL_W, sizeof(int));
  rscs_ioctl_register_request(TIOCSCTTY, IOCTL_W, sizeof(int));
  rscs_ioctl_register_request(TIOCGPGRP, IOCTL_W, sizeof(pid_t));
  rscs_ioctl_register_request(TIOCSPGRP, IOCTL_R, sizeof(const pid_t));
  rscs_ioctl_register_request(TIOCOUTQ, IOCTL_W, sizeof(int));
  rscs_ioctl_register_request(TIOCSTI, IOCTL_R, sizeof(const char));
  rscs_ioctl_register_request(TIOCGWINSZ, IOCTL_W, sizeof(struct winsize));
  rscs_ioctl_register_request(TIOCSWINSZ, IOCTL_R, sizeof(const struct winsize));
  rscs_ioctl_register_request(TIOCMGET, IOCTL_W, sizeof(int));
  rscs_ioctl_register_request(TIOCMBIS, IOCTL_R, sizeof(const int));
  rscs_ioctl_register_request(TIOCMBIC, IOCTL_R, sizeof(const int));
  rscs_ioctl_register_request(TIOCMSET, IOCTL_R, sizeof(const int));
  rscs_ioctl_register_request(TIOCGSOFTCAR, IOCTL_W, sizeof(int));
  rscs_ioctl_register_request(TIOCSSOFTCAR, IOCTL_R, sizeof(const int));
  rscs_ioctl_register_request(FIONREAD, IOCTL_W, sizeof(int));
  rscs_ioctl_register_request(TIOCINQ, IOCTL_W, sizeof(int));
  rscs_ioctl_register_request(TIOCGSERIAL, IOCTL_W, sizeof(struct serial_struct));
  rscs_ioctl_register_request(TIOCSSERIAL, IOCTL_R, sizeof(const struct serial_struct));
  rscs_ioctl_register_request(TIOCPKT, IOCTL_R, sizeof(const int));
  rscs_ioctl_register_request(FIONBIO, IOCTL_R, sizeof(const int));
  rscs_ioctl_register_request(TIOCSETD, IOCTL_R, sizeof(const int));
  rscs_ioctl_register_request(TIOCGETD, IOCTL_W, sizeof(int));
  rscs_ioctl_register_request(TCSBRKP, IOCTL_W, sizeof(int));
  rscs_ioctl_register_request(FIOASYNC, IOCTL_R, sizeof(const int));
  rscs_ioctl_register_request(TIOCSERGWILD, IOCTL_W, sizeof(int));
  rscs_ioctl_register_request(TIOCSERSWILD, IOCTL_R, sizeof(const int));
  rscs_ioctl_register_request(TIOCGLCKTRMIOS, IOCTL_W, sizeof(struct termios));
  rscs_ioctl_register_request(TIOCSLCKTRMIOS, IOCTL_R, sizeof(const struct termios));
  rscs_ioctl_register_request(TIOCSERGETLSR, IOCTL_W, sizeof(int));
  rscs_ioctl_register_request(TIOCSERGETMULTI, IOCTL_W, sizeof(struct serial_multiport_struct));
  rscs_ioctl_register_request(TIOCSERSETMULTI, IOCTL_R, sizeof(const struct serial_multiport_struct));
  /* linux/fd.h */
  rscs_ioctl_register_request(FDSETPRM, IOCTL_R, sizeof(const struct floppy_struct));
  rscs_ioctl_register_request(FDDEFPRM, IOCTL_R, sizeof(const struct floppy_struct));
  rscs_ioctl_register_request(FDGETPRM, IOCTL_W, sizeof(struct floppy_struct));
  rscs_ioctl_register_request(FDFMTTRK, IOCTL_R, sizeof(const struct format_descr));
  rscs_ioctl_register_request(FDSETEMSGTRESH, IOCTL_W, sizeof(int));
  rscs_ioctl_register_request(FDSETMAXERRS, IOCTL_R, sizeof(const struct floppy_max_errors));
  rscs_ioctl_register_request(FDGETMAXERRS, IOCTL_W, sizeof(struct floppy_max_errors));
  rscs_ioctl_register_request(FDGETDRVTYP, IOCTL_W, 16);
  rscs_ioctl_register_request(FDSETDRVPRM, IOCTL_R, sizeof(const struct floppy_drive_params));
  rscs_ioctl_register_request(FDGETDRVPRM, IOCTL_W, sizeof(struct floppy_drive_params));
  rscs_ioctl_register_request(FDGETDRVSTAT, IOCTL_W, sizeof(struct floppy_drive_struct));
  rscs_ioctl_register_request(FDPOLLDRVSTAT, IOCTL_W, sizeof(struct floppy_drive_struct));
  rscs_ioctl_register_request(FDRESET, IOCTL_W, sizeof(int));
  rscs_ioctl_register_request(FDGETFDCSTAT, IOCTL_W, sizeof(struct floppy_fdc_state));
  rscs_ioctl_register_request(FDWERRORGET, IOCTL_W, sizeof(struct floppy_write_errors));
  /* linux/fs.h */
  rscs_ioctl_register_request(BLKROSET, IOCTL_R, sizeof(const int));
  rscs_ioctl_register_request(BLKROGET, IOCTL_W, sizeof(int));
  rscs_ioctl_register_request(BLKGETSIZE, IOCTL_W, sizeof(int));
  rscs_ioctl_register_request(BLKRASET, IOCTL_W, sizeof(int));
  rscs_ioctl_register_request(BLKRAGET, IOCTL_W, sizeof(int));
  rscs_ioctl_register_request(FIBMAP, IOCTL_RW, sizeof(int));
  rscs_ioctl_register_request(FIGETBSZ, IOCTL_W, sizeof(int));
  /* linux/hdreg.h */
  rscs_ioctl_register_request(HDIO_GETGEO, IOCTL_W, sizeof(struct hd_geometry));
  rscs_ioctl_register_request(HDIO_GET_UNMASKINTR, IOCTL_W, sizeof(int));
  rscs_ioctl_register_request(HDIO_GET_MULTCOUNT, IOCTL_W, sizeof(int));
  rscs_ioctl_register_request(HDIO_GET_IDENTITY, IOCTL_W, sizeof(struct hd_driveid));
  rscs_ioctl_register_request(HDIO_GET_KEEPSETTINGS, IOCTL_W, sizeof(int));
  rscs_ioctl_register_request(HDIO_GET_NOWERR, IOCTL_W, sizeof(int));
  rscs_ioctl_register_request(HDIO_GET_DMA, IOCTL_W, sizeof(int));
  rscs_ioctl_register_request(HDIO_DRIVE_CMD, IOCTL_RW, sizeof(int));
  rscs_ioctl_register_request(HDIO_SET_MULTCOUNT, IOCTL_W, sizeof(int));
  rscs_ioctl_register_request(HDIO_SET_UNMASKINTR, IOCTL_W, sizeof(int));
  rscs_ioctl_register_request(HDIO_SET_KEEPSETTINGS, IOCTL_W, sizeof(int));
  rscs_ioctl_register_request(HDIO_SET_NOWERR, IOCTL_W, sizeof(int));
  rscs_ioctl_register_request(HDIO_SET_DMA, IOCTL_W, sizeof(int));
}

static int set_non_blocking(int fd) {
  int flags;
  if((flags = fcntl(fd, F_GETFL)) == -1) 
    return 0;
  flags |= O_NONBLOCK;
  if((flags = fcntl(fd, F_SETFL, flags)) == -1) 
    return 0;
  return 1;
}


static int
init(char *server_addr, char *server_port, char *event_sub_server_port, int *listen_fd, int *event_sub_fd) {
  int ret;

  *listen_fd = create_listening_fd(server_addr, server_port);
  if(*listen_fd == -1) {
    fprintf(stderr, "I cannot create the listening socket\n");
    return -1;
  }
  if(set_non_blocking(*listen_fd) == 0)
    return -1;

  *event_sub_fd = create_listening_fd(server_addr, event_sub_server_port);
  if(*event_sub_fd == -1) {
    fprintf(stderr, "I cannot create the event subscribe listening socket\n");
    return -1;
  }
  if(set_non_blocking(*event_sub_fd) == 0)
    return -1;

  /* I get my architecture */
  if( (my_arch = aconv_get_host_arch()) == ACONV_ARCH_ERROR ) {
    fprintf(stderr, "I cannot get my architecture\n");
    return -1;
  }
  /* I init the librsc module */ 
  ret = rscs_init(my_arch);
  if(ret == -1) {
    fprintf(stderr, "I cannot initialize the RSC module\n");
    return -1;
  }
  GDEBUG(1, "My architecture is %s\n", aconv_arch2str(my_arch));
  
  /* I set the list of ioctl request I support AFTER the initialization
   * of the rsc_module (otherwise segfault)*/
  init_ioctl_register_request();
  
  /* I Init the pollfd structure */
  if((pfdinfo = pollfd_init()) == NULL) {
    fprintf(stderr, "I cannot init the pollfd structure\n");
    return -1;
  }
  
  return 0;
}

/* Close the connection of the i-th fd */
static void close_connection(struct pollfd_info *p, int i) {
	GDEBUG(1, "Connection closed: fd = %d", p->pollfd[i].fd);
  close(p->pollfd[i].fd);
  pollfd_del(p, i);
  /* compact pfdinfo */
  PRINT_POLLFDINFO(p);
}

static void 
main_loop(int listen_fd, int event_sub_fd) {
  int i, nready;
  int new_fd;
  int deleted_entry;

  struct sockaddr_in client_addr;
  socklen_t client_len;

  pollfd_add(pfdinfo, listen_fd, POLLIN, NULL); 
  pollfd_add(pfdinfo, event_sub_fd, POLLIN, NULL); 

  /* Main loop */
  while(1) {
    deleted_entry = 0;
		GDEBUG(1, "Before poll():");
    PRINT_POLLFDINFO(pfdinfo);

    /* Poll */
    nready = poll(pfdinfo->pollfd, pfdinfo->nfds, -1);
    /* There is an error? */
    if(nready == -1) {
      fprintf(stderr, "poll() error: %s; I continue.\n", strerror(errno));
      continue;
    }

    for(i = 0; i < pfdinfo->nfds; i++) {
      if(pfdinfo->pollfd[i].revents == 0)
        continue;
      GDEBUG(1, "fd = %d is ready for event 0x%X\n", pfdinfo->pollfd[i].fd, pfdinfo->pollfd[i].revents);
      /* If there is an error, I close the connection */
      if( pfdinfo->pollfd[i].revents & POLLERR || pfdinfo->pollfd[i].revents & POLLHUP || 
          pfdinfo->pollfd[i].revents & POLLNVAL) {
          /* printf("Error, getchar():\n"); getchar(); */
          close_connection(pfdinfo, i);
          deleted_entry = 1;
          if(--nready < 0) break;
          continue;
      }

	    /*********************************************/
	    /* New Connection/Event Subscribe management */
	    /*********************************************/
	    if((pfdinfo->pollfd[i].fd == listen_fd || pfdinfo->pollfd[i].fd == event_sub_fd) 
          && pfdinfo->pollfd[i].revents & POLLIN) {
        enum client_type type;
        int size;
        enum client_state state;
        if(pfdinfo->pollfd[i].fd == listen_fd) {
          type = REQ_RESP;
          size = sizeof(struct handshake);
          state = WAITING_ARCH;
        } else {
          type = EVENT_SUB;
          size = sizeof(struct rsc_es_hdr);
          state = CONN_READING_HDR;
        }
        
	      bzero(&client_addr, sizeof(client_addr));
	      client_len = sizeof(client_addr);
	
	      /* I accept the new connection */
	      new_fd = accept(pfdinfo->pollfd[i].fd, (struct sockaddr *)&client_addr, &client_len); 
	
	      if(new_fd == -1) {
	        fprintf(stderr, "Accept() error: %s\n", strerror(errno));
	      } else {
	        /* I create the new client structure */
	        struct client *new_client;
          void *data;
	        new_client = create_client(new_fd, type, state);
          data = malloc(sizeof(struct handshake));
          if(data == NULL) {
            close(new_fd);
            if(--nready < 0) break;
            continue;
          }

	        if(new_client == NULL || data == NULL) {
	          fprintf(stderr, "I cannot create a new client struct for fd %d\n", new_fd);
            if(new_client == NULL)
              free(new_client);
            if(data == NULL);
              free(data);
	          close(new_fd);
	        } else {
            buff_enq(new_client->rbuf, data, size);
			      GDEBUG(1, "Accepting new connection from "); print_addr_port(new_client->fd); GDEBUG(1, " (fd = %d).\n", new_client->fd);
            pollfd_add(pfdinfo, new_client->fd, POLLIN, new_client);
	        }
	      }
	      if(--nready <= 0) break;
        /*************************************************************************/
        /* Management of descriptors ready to read of type REQ_RESP or EVENT_SUB */
        /*************************************************************************/
      } else if(pfdinfo->clients[i]->type == REQ_RESP || pfdinfo->clients[i]->type == EVENT_SUB) {
        struct client *client = pfdinfo->clients[i];
        /***********************************************/
        /*  POLLIN                                     */
        /***********************************************/
        if(pfdinfo->pollfd[i].revents &  POLLIN) {
	        void *buf;
	        int size, nread;
          /* If there are data to read, but the read buffer is empty 
           * I create a new message */
          if(client->rbuf->first == NULL) {
            int size = 0;
            void *data;
            if(pfdinfo->clients[i]->type == REQ_RESP && 
                pfdinfo->clients[i]->state == CONN_READING_HDR)
              size = sizeof(struct req_header);
            else if(pfdinfo->clients[i]->type == EVENT_SUB && 
                pfdinfo->clients[i]->state == CONN_READING_HDR)
              size = sizeof(struct rsc_es_hdr);
            if(size != 0) {
              data = malloc(size);
              if(data == NULL) {
                close_connection(pfdinfo, i);
                deleted_entry = 1;
                if(--nready < 0) break;
                continue;
              }

              buff_enq(client->rbuf, data, size);
            }
          }
		      GDEBUG(1, "There are data ready do be read for fd %d", pfdinfo->pollfd[i].fd);
          /* I read the data from the first message */
	        buf = client->rbuf->first->data + client->rbuf->first->n;
	        size = client->rbuf->first->tot - client->rbuf->first->n;
			    nread = read(client->fd, buf, size);
	        if(nread <= 0 ) {
	          /* If there is an error or the connection was close,
             * I close the connection from my side */
            close_connection(pfdinfo, i);
            deleted_entry = 1;
            if(--nready <= 0) break;
            continue;
          } else {
	          client->rbuf->first->n += nread;
          }
			    
          /* If I've read all the data, I remove the buffer from client->rbuf
           * and I process the data */
			    if(client->rbuf->first->n == client->rbuf->first->tot) {
            void *read_data = buff_deq(client->rbuf);
	          if(pfdinfo->clients[i]->type == REQ_RESP) {
				      if(client->state == WAITING_ARCH) {
			          /* I read the architecture of the client */
					      struct handshake *client_arch, *server_arch;
			          client_arch = (struct handshake *)read_data;
				
						    client->arch = ntohl(client_arch->arch);
						    GDEBUG(1, "Client (%d) architecture is %s\n", client->fd, aconv_arch2str(client->arch));
                free(read_data);
						    
						    /* Now I can send my architecture */
		            client->state = SENDING_ARCH;
		            server_arch = calloc(1, sizeof(struct handshake));
		            if(server_arch == NULL) {
                  close_connection(pfdinfo, i);
                  deleted_entry = 1;
                  if(--nready < 0) break;
                  continue;
                }
                server_arch->arch = htonl(my_arch);
		            buff_enq(client->wbuf, server_arch, sizeof(struct handshake));
                pfdinfo->pollfd[i].events |=  POLLOUT;
                client->state = SENDING_ARCH;
				      }else if(client->state == CONN_READING_HDR) {
			          struct req_header *req_hd;
                struct msg *m;
		            int req_size;
                void *new_data;
		            /* I've read all the request header, now I've to read all the request body */
                client->state = CONN_READING_BODY;
		            req_hd = (struct req_header *)read_data;
			          req_size = rsc_req_msg_size(req_hd);
                new_data = realloc(read_data, req_size);
                if(new_data == NULL) {
                  close_connection(pfdinfo, i);
                  deleted_entry = 1;
                  if(--nready < 0) break;
                  continue;
                }

		            m = buff_enq(client->rbuf, new_data, req_size);
                /* I've already read the req_header, so I need to update m->n field */
                m->n = sizeof(struct req_header);
		          }else if(client->state == CONN_READING_BODY) {
			          /* Now I've read all the request and I can pass it to RSC function */
                struct iovec *resp;
					      resp = rscs_manage_request(client->arch, read_data);
                /* If there is an error, I close the connection */
                if(resp == NULL) {
                  close_connection(pfdinfo, i);
                  deleted_entry = 1;
                  if(--nready < 0) break;
                  continue;
                }
		            buff_enq(client->wbuf, resp[0].iov_base, resp[0].iov_len);
                pfdinfo->pollfd[i].events |=  POLLOUT;
                client->state = CONN_SENDING_RESP;
                free(read_data);
              }
            } else {
	            /* type == EVENT_SUB */
				      if(client->state == CONN_READING_HDR) {
	              struct rsc_es_hdr *hdr;
	              int size;
                void *new_data;
                struct msg *m;
	              hdr = (struct rsc_es_hdr *)read_data;
	              size = rsc_es_msg_size(hdr->type);
	              if(size == -1) {
                  close_connection(pfdinfo, i);
                  deleted_entry = 1;
                  if(--nready < 0) break;
                  continue;
                }
                new_data = realloc(read_data, size);
                if(new_data == NULL) {
                  close_connection(pfdinfo, i);
                  deleted_entry = 1;
                  if(--nready < 0) break;
                  continue;
                }
                m = buff_enq(client->rbuf, new_data, size);
                m->n = sizeof(struct rsc_es_hdr);
                client->state = CONN_READING_BODY;
	            } else if(client->state == CONN_READING_BODY) {
	              struct rsc_es_ack *ack;
	              ack = rscs_es_manage_msg(client->fd, read_data);
                free(read_data);
			          /* I take the appropriate action based on ack->response field.
			           * If the response is ACK_FD_REG I've to insert the fd into the
			           * pollfd set. If the response is ACK_FD_DEREG_NOT_READY or ACK_FD_READY,
			           * I remove the fd from the pollfd. */
			          if(ack->response == ACK_FD_REG) {
				          struct client *c;
			            /* Into the client structure I insert the stream fd and not the 
			             * fd to subscribe, In this way I can know where to send data */
			            c = create_client(client->fd, SUBSCRIBED_FD, CONN_SENDING_RESP);
                  if(c == NULL) {
                    close_connection(pfdinfo, i);
                    deleted_entry = 1;
                    if(--nready < 0) break;
                    continue;
                  }
                  c->esfd_index = i;
			            pollfd_add(pfdinfo, ntohl(ack->fd), ntohl(ack->how), c);
			          } else if(ack->response == ACK_FD_DEREG_NOT_READY || ack->response == ACK_FD_DEREG_READY) {
			            int j;
			            for(j = 0; j < pfdinfo->size; j++) 
			              if( pfdinfo->pollfd[j].fd != -1 &&
			                  pfdinfo->clients[j] != NULL &&
			                  pfdinfo->clients[j]->type == SUBSCRIBED_FD &&
			                  pfdinfo->clients[j]->fd == client->fd && 
			                  pfdinfo->pollfd[j].fd == ntohl(ack->fd) && 
			                  pfdinfo->pollfd[j].events == ntohl(ack->how))
			                break;
			            if(j < pfdinfo->size)
			              pollfd_del(pfdinfo, j);
			          }
			          GDEBUG(1, "After rscem_manage_msg:");
			          PRINT_POLLFDINFO(pfdinfo);
	              /* Now I can send ack back */
                buff_enq(client->wbuf, ack, sizeof(struct rsc_es_ack));
                pfdinfo->pollfd[i].events |=  POLLOUT;
                /* It's not an error, I don't need to keep trace of the sending state */
                client->state = CONN_READING_HDR;
	            }
	          }
          }
          /***********************************************/
          /*  POLLOUT                                    */
          /***********************************************/
        } else if(pfdinfo->pollfd[i].revents & POLLOUT) {
	        void *buf;
	        int size, nwrite;
          /* If write buffer is empty, I remove the POLLOUT event and I continue */
          if(client->wbuf->first == NULL) {
            pfdinfo->pollfd[i].events &= (~POLLOUT);
            if(--nready <= 0) 
              break;
            continue;
          }
		      GDEBUG(1, "There are data ready do be written for fd %d", pfdinfo->pollfd[i].fd);
	        buf = client->wbuf->first->data + client->wbuf->first->n;
	        size = client->wbuf->first->tot - client->wbuf->first->n;
			    nwrite = write(client->fd, buf, size);
          if(nwrite < 0) {
            close_connection(pfdinfo, i);
            deleted_entry = 1;
            if(--nready < 0) break;
            continue;
          } else {
            client->wbuf->first->n += nwrite;
          }
			    if(client->wbuf->first->n == client->wbuf->first->tot) {
            /* I remove the message from the buffer and I free it */
            void *data = buff_deq(client->wbuf);
            free(data);
            /* If it's a request/response fd and I've sent an arch or response message,
             * I change my state to reading header */
	          if( pfdinfo->clients[i]->type == REQ_RESP && 
                ( client->state == SENDING_ARCH || client->state == CONN_SENDING_RESP) )
              client->state = CONN_READING_HDR;
	          /* if client->type is EVENT_SUB  there is nothing to do: I need only
            * to continue to send the buffered data */
          }
        }
        if(--nready <= 0) break;
      /*******************************************/
      /* An event subscribed fd is waken up      */
      /*******************************************/
      /* The event is occurred, I send back a response I didn't it before */
      }else if(pfdinfo->clients[i]->type == SUBSCRIBED_FD) {
        struct rsc_es_resp *resp;
        int esfd_index = pfdinfo->clients[i]->esfd_index;

        resp = rscs_es_event_occured(pfdinfo->pollfd[esfd_index].fd, pfdinfo->pollfd[i].fd, pfdinfo->pollfd[i].revents);
        if(resp != NULL) {
          buff_enq(pfdinfo->clients[esfd_index]->wbuf, resp, sizeof(struct rsc_es_resp)); 
          pfdinfo->pollfd[esfd_index].events |=  POLLOUT;
        } 
	      if(--nready <= 0) break;
      }
    } /* for(i = 0; i < nready; i++) */
    /* If I've deleted a pfdinfo, I compact it */
    if(deleted_entry)
      pollfd_compact(pfdinfo);
  } /* while(1) */
}

static void usage(char *s, int exit_code) {
  fprintf(stderr, "Usage: %s [OPTIONS]\n"
      "OPTIONS are:\n"
      "\t-h, --help                       print this help message.\n"
      "\t-a ADDRESS, --address ADDRESS    bind the server to ADDRESS.\n"
      "\t-p PORT, --port PORT             set the port for syscall execution.\n"
      "\t-e PORT, --es_port PORT          set the port for event subscription.\n",
      basename(s));

  exit(exit_code);
}

/*####################################################################*/
/*# Main Function                                                    #*/
/*####################################################################*/

int
main (int argc, char *argv[])
{
  int listen_fd, event_sub_fd;
  int c;
  char *server_addr, *server_port, *event_sub_server_port;
  
  /* I parse the command-line arguments */
  server_addr = SERVER_ADDR;
  server_port = SERVER_PORT;
  event_sub_server_port = SERVER_PORT_EVENT_SUB;

  while(1) {
    int option_index = 0;
    static struct option long_option[] = {
      {"address", 1, NULL, 'a'},
      {"port", 1, NULL, 'p'},
      {"es_port", 1, NULL, 'e'},
      {"help", 0, NULL, 'h'}
    };
    
    c = getopt_long(argc, argv, "a:p:e:h", long_option, &option_index);
    
    if(c == -1) break;
    switch(c) {
      case 'h':
        usage(argv[0], 0);
        break;
      case 'a':
        server_addr = optarg;
        break;
      case 'p':
        server_port= optarg;
        break;
      case 'e':
        event_sub_server_port = optarg;
        break;
      default:
        usage(argv[0], -1);
        break;
    }
  }

  GDEBUG(1, "Server <addr, port>: <%s, %s>\n", server_addr, server_port);
  
  /* I initialize the server */
  if(init(server_addr, server_port, event_sub_server_port, &listen_fd, &event_sub_fd) < 0) {
    fprintf(stderr, "Error during the initialization of the server.\n");
    exit(-1);
  }

  /* Main loop */
  main_loop(listen_fd, event_sub_fd);

  return 0;
}
/**/
