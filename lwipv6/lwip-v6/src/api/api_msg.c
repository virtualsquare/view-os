/*   This is part of LWIPv6
 *   Developed for the Ale4NET project
 *   Application Level Environment for Networking
 *   
 *   Copyright 2004,2011 Renzo Davoli University of Bologna - Italy
 *   
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */   
/*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
 * All rights reserved. 
 * 
 * Redistribution and use in source and binary forms, with or without modification, 
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED 
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT 
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, 
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT 
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING 
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY 
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 * 
 * Author: Adam Dunkels <adam@sics.se>
 *
 */

#include "lwip/opt.h"
#include "lwip/arch.h"
#include "lwip/api_msg.h"
#include "lwip/memp.h"
#include "lwip/sys.h"
#include "lwip/tcpip.h"

static inline void pending_conn_mbox(struct netconn *conn)
{
	conn->ack_pending = 1;
}

static inline void ack_conn_mbox(struct netconn *conn)
{
	conn->ack_pending = 0;
	sys_mbox_post(conn->mbox, NULL);
}

#if LWIP_RAW
static void
recv_raw(void *arg, struct raw_pcb *pcb, struct pbuf *p,
    struct ip_addr *addr, u16_t protocol)
{
  struct netbuf *buf;
  struct netconn *conn;


  conn = arg;
  if (!conn) return;

  if (conn->recvmbox != SYS_MBOX_NULL) {
    if (!(buf = memp_malloc(MEMP_NETBUF))) {
      return;
    }
    buf->p = p;
    buf->ptr = p;
    memcpy(&(buf->fromaddr),addr,sizeof(struct ip_addr));
    buf->fromport = protocol;
  /*printf("RAW netbuf_fromaddr %x:%x:%x:%x buf %x port %d %x %x %d\n",
		  buf->fromaddr.addr[0],
		  buf->fromaddr.addr[1],
		  buf->fromaddr.addr[2],
		  buf->fromaddr.addr[3], buf, buf->fromport, p, p, p->tot_len);*/

    /* IPV6 does not include headers in received RAW packets.
     * IPV4 need IP headers (to be verified XXX)
     */
    if (! ip_addr_is_v4comp(addr)){
	    pbuf_header(p,-IP_HLEN); 
    }
    conn->recv_avail += p->tot_len;
    /* Register event with callback */
    if (conn->callback)
        (*conn->callback)(conn, NETCONN_EVT_RCVPLUS, p->tot_len);
    sys_mbox_post(conn->recvmbox, buf);
  }
}
#endif
#if LWIP_PACKET
static void
recv_packet(void *arg, struct raw_pcb *pcb, struct pbuf *p,
    struct ip_addr *addr, u16_t protocol)
{
  struct netbuf *buf;
  struct netconn *conn;

  conn = arg;
  if (!conn) return;

  if (conn->recvmbox != SYS_MBOX_NULL) {
    if (!(buf = memp_malloc(MEMP_NETBUF))) {
      return;
    }
    buf->p = p;
    buf->ptr = p;
    memcpy(&(buf->fromaddr),addr,sizeof(struct ip_addr));
    buf->fromport = protocol;
  /*printf("PACKET netbuf_fromaddr %lx:%lx:%lx:%lx buf %p port %x %p %d\n",
		  buf->fromaddr.addr[0],
		  buf->fromaddr.addr[1],
		  buf->fromaddr.addr[2],
		  buf->fromaddr.addr[3], buf, buf->fromport, p, p->tot_len); */

    conn->recv_avail += p->tot_len;
    /* Register event with callback */
    if (conn->callback)
        (*conn->callback)(conn, NETCONN_EVT_RCVPLUS, p->tot_len);
    sys_mbox_post(conn->recvmbox, buf);
  }
}
#endif
#if LWIP_UDP
static void
recv_udp(void *arg, struct udp_pcb *pcb, struct pbuf *p,
   struct ip_addr *addr, u16_t port)
{
  struct netbuf *buf;
  struct netconn *conn;

  conn = arg;
  
  if (conn == NULL) {
    pbuf_free(p);
    return;
  }
  if (conn->recvmbox != SYS_MBOX_NULL) {
    buf = memp_malloc(MEMP_NETBUF);
    if (buf == NULL) {
      pbuf_free(p);
      return;
    } else {
      buf->p = p;
      buf->ptr = p;
      memcpy(&(buf->fromaddr),addr,sizeof(struct ip_addr));
  /*printf("UDP netbuf_fromaddr %x:%x:%x:%x\n",
		  buf->fromaddr.addr[0],
		  buf->fromaddr.addr[1],
		  buf->fromaddr.addr[2],
		  buf->fromaddr.addr[3]);*/

      buf->fromport = port;
    }

  conn->recv_avail += p->tot_len;
    /* Register event with callback */
    if (conn->callback)
        (*conn->callback)(conn, NETCONN_EVT_RCVPLUS, p->tot_len);
    sys_mbox_post(conn->recvmbox, buf);
  }
}
#endif /* LWIP_UDP */
#if LWIP_TCP

static err_t
recv_tcp(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
  struct netconn *conn;
  u16_t len;
  
  conn = arg;

  if (conn == NULL) {
    pbuf_free(p);
    return ERR_VAL;
  }

  if (conn->recvmbox != SYS_MBOX_NULL) {
        
    conn->err = err;
    if (p != NULL) {
        len = p->tot_len;
        conn->recv_avail += len;
    }
    else
        len = 0;
    /* Register event with callback */
    if (conn->callback)
        (*conn->callback)(conn, NETCONN_EVT_RCVPLUS, len);
    sys_mbox_post(conn->recvmbox, p);
  }  
  return ERR_OK;
}


static err_t
poll_tcp(void *arg, struct tcp_pcb *pcb)
{
  struct netconn *conn;

  conn = arg;
  if (conn != NULL &&
     (conn->state == NETCONN_WRITE || conn->state == NETCONN_CLOSE) &&
     conn->sem != SYS_SEM_NULL) {
    sys_sem_signal(conn->sem);
  }
  return ERR_OK;
}

static err_t
sent_tcp(void *arg, struct tcp_pcb *pcb, u16_t len)
{
  struct netconn *conn;

  conn = arg;
  if (conn != NULL && conn->sem != SYS_SEM_NULL) 
    sys_sem_signal(conn->sem);

  if (conn && conn->callback)
      if (tcp_sndbuf(conn->pcb.tcp) > TCP_SNDLOWAT)
          (*conn->callback)(conn, NETCONN_EVT_SENDPLUS, len);
  
  return ERR_OK;
}

static void
err_tcp(void *arg, err_t err)
{
  struct netconn *conn;

  conn = arg;

  conn->pcb.tcp = NULL;
  
  conn->err = err;
  if (conn->recvmbox != SYS_MBOX_NULL) {
    /* Register event with callback */
    if (conn->callback)
      (*conn->callback)(conn, NETCONN_EVT_RCVPLUS, 0);
    sys_mbox_post(conn->recvmbox, NULL);
  }
	/* NO! this spurious message breaks the dialogue
		 api_lib/api_msg. THere must be exactly one message per
		 request X999*/
  /*if (conn->mbox != SYS_MBOX_NULL) {
		ack_conn_mbox(conn);
	}*/
	/* new version X1010 */
	if (conn->ack_pending)
		ack_conn_mbox(conn);
  if (conn->acceptmbox != SYS_MBOX_NULL) {
     /* Register event with callback */
    if (conn->callback)
      (*conn->callback)(conn, NETCONN_EVT_RCVPLUS, 0);
    sys_mbox_post(conn->acceptmbox, NULL);
  }
  if (conn->sem != SYS_SEM_NULL) {
    sys_sem_signal(conn->sem);
  }
}

static void
setup_tcp(struct netconn *conn)
{
  struct tcp_pcb *pcb;
  
  pcb = conn->pcb.tcp;
  tcp_arg(pcb, conn);
  tcp_recv(pcb, recv_tcp);
  tcp_sent(pcb, sent_tcp);
  tcp_poll(pcb, poll_tcp, 4);
  tcp_err(pcb, err_tcp);
}

static err_t
accept_function(void *arg, struct tcp_pcb *newpcb, err_t err)
{
  sys_mbox_t mbox;
  struct netconn *newconn;
  struct netconn *conn;
  
  //printf("accept fun\n");
#if API_MSG_DEBUG
#if TCP_DEBUG
  tcp_debug_print_state(newpcb->state);
#endif /* TCP_DEBUG */
#endif /* API_MSG_DEBUG */
  conn = (struct netconn *)arg;
  mbox = conn->acceptmbox;
  newconn = memp_malloc(MEMP_NETCONN);
  if (newconn == NULL) {
	  //printf("NO mem?\n");
    return ERR_MEM;
  }
  
  /* FIX MULTISTACK: newpcb->stack == conn->stack */
  newconn->stack = newpcb->stack;  
  
  newconn->type = NETCONN_TCP;
  newconn->pcb.tcp = newpcb;
  setup_tcp(newconn);
  newconn->recvmbox = sys_mbox_new();
  if (newconn->recvmbox == SYS_MBOX_NULL) {
    memp_free(MEMP_NETCONN, newconn);
    return ERR_MEM;
  }
  newconn->mbox = sys_mbox_new();
  if (newconn->mbox == SYS_MBOX_NULL) {
    sys_mbox_free(newconn->recvmbox);
    memp_free(MEMP_NETCONN, newconn);
    return ERR_MEM;
  }
	/* why? */
	/* X1005 */
  /*newconn->sem = sys_sem_new(0);
  if (newconn->sem == SYS_SEM_NULL) {
    sys_mbox_free(newconn->recvmbox);
    sys_mbox_free(newconn->mbox);
    memp_free(MEMP_NETCONN, newconn);
    return ERR_MEM;
  }*/
	newconn->sem = SYS_SEM_NULL;
	/* end of X1005 */
  newconn->acceptmbox = SYS_MBOX_NULL;
  newconn->ack_pending = 0;
  newconn->err = err;
  newconn->recv_avail = 0;
  newconn->socket = conn->socket;
	newconn->callback = conn->callback;
	if (newconn->callback) 
		(*newconn->callback)(newconn, NETCONN_EVT_ACCEPTPLUS, 0);
  //printf("conn->acceptmbox post!\n");
  sys_mbox_post(mbox, newconn);
  /* Register event with callback */
  if (conn->callback)
    (*conn->callback)(conn, NETCONN_EVT_RCVPLUS, 0);
  return ERR_OK;
}
#endif /* LWIP_TCP */

static void
do_newconn(struct api_msg_msg *msg)
{
	pending_conn_mbox(msg->conn);
   if(msg->conn->pcb.tcp != NULL) {
   /* This "new" connection already has a PCB allocated. */
   /* Is this an error condition? Should it be deleted? 
      We currently just are happy and return. */
		 ack_conn_mbox(msg->conn);
     return;
   }

   msg->conn->err = ERR_OK;

   /* Allocate a PCB for this connection */
   switch(msg->conn->type) {
#if LWIP_RAW
   case NETCONN_RAW:
      msg->conn->pcb.raw = raw_new(msg->conn->stack, msg->msg.bc.port); /* misusing the port field */
      raw_recv(msg->conn->pcb.raw, recv_raw, msg->conn);
     break;
#endif
#if LWIP_UDP
   case NETCONN_UDPLITE:
      msg->conn->pcb.udp = udp_new(msg->conn->stack);
      if(msg->conn->pcb.udp == NULL) {
         msg->conn->err = ERR_MEM;
         break;
      }
      udp_setflags(msg->conn->pcb.udp, UDP_FLAGS_UDPLITE);
      udp_recv(msg->conn->pcb.udp, recv_udp, msg->conn);
      break;
   case NETCONN_UDPNOCHKSUM:
      msg->conn->pcb.udp = udp_new(msg->conn->stack);
      if(msg->conn->pcb.udp == NULL) {
         msg->conn->err = ERR_MEM;
         break;
      }
      udp_setflags(msg->conn->pcb.udp, UDP_FLAGS_NOCHKSUM);
      udp_recv(msg->conn->pcb.udp, recv_udp, msg->conn);
      break;
   case NETCONN_UDP:
      msg->conn->pcb.udp = udp_new(msg->conn->stack);
      if(msg->conn->pcb.udp == NULL) {
         msg->conn->err = ERR_MEM;
         break;
      }
      udp_recv(msg->conn->pcb.udp, recv_udp, msg->conn);
      break;
#endif /* LWIP_UDP */
#if LWIP_TCP
   case NETCONN_TCP:
      msg->conn->pcb.tcp = tcp_new(msg->conn->stack);
      if(msg->conn->pcb.tcp == NULL) {
         msg->conn->err = ERR_MEM;
         break;
      }
      setup_tcp(msg->conn);
      break;
#endif
    default:
      break;
   }
   
  
	 ack_conn_mbox(msg->conn);
}


static void
do_delconn(struct api_msg_msg *msg)
{
	pending_conn_mbox(msg->conn);
  if (msg->conn->pcb.tcp != NULL) {
    switch (msg->conn->type) {
#if LWIP_RAW
    case NETCONN_RAW:
      raw_remove(msg->conn->pcb.raw);
      break;
#endif
#if LWIP_PACKET
		case NETCONN_PACKET_RAW:
		case NETCONN_PACKET_DGRAM:
      packet_remove(msg->conn->pcb.raw);
      break;
#endif
#if LWIP_UDP
    case NETCONN_UDPLITE:
      /* FALLTHROUGH */
    case NETCONN_UDPNOCHKSUM:
      /* FALLTHROUGH */
    case NETCONN_UDP:
      msg->conn->pcb.udp->recv_arg = NULL;
      udp_remove(msg->conn->pcb.udp);
      break;
#endif /* LWIP_UDP */
#if LWIP_TCP      
    case NETCONN_TCP:
      if (msg->conn->pcb.tcp->state == LISTEN) {
				tcp_arg(msg->conn->pcb.tcp, NULL);
				tcp_accept(msg->conn->pcb.tcp, NULL);  
				tcp_close(msg->conn->pcb.tcp);
			} else {
				tcp_arg(msg->conn->pcb.tcp, NULL);
				tcp_sent(msg->conn->pcb.tcp, NULL);
				tcp_recv(msg->conn->pcb.tcp, NULL);  
				tcp_poll(msg->conn->pcb.tcp, NULL, 0);
				tcp_err(msg->conn->pcb.tcp, NULL);
				if (tcp_close(msg->conn->pcb.tcp) != ERR_OK) {
					tcp_abort(msg->conn->pcb.tcp);
				}
			}
#endif
		default:  
			break;
		}
	}
	/* Trigger select() in socket layer */
  if (msg->conn->callback)
  {
      (*msg->conn->callback)(msg->conn, NETCONN_EVT_RCVPLUS, 0);
      (*msg->conn->callback)(msg->conn, NETCONN_EVT_SENDPLUS, 0);
  }
  
  if (msg->conn->mbox != SYS_MBOX_NULL) {
		ack_conn_mbox(msg->conn);
  }
}

static void
do_bind(struct api_msg_msg *msg)
{
	pending_conn_mbox(msg->conn);
  if (msg->conn->pcb.tcp == NULL) {
    switch (msg->conn->type) {
#if LWIP_RAW
    case NETCONN_RAW:
      msg->conn->pcb.raw = raw_new(msg->conn->stack, msg->msg.bc.port); /* misusing the port field as protocol */
      raw_recv(msg->conn->pcb.raw, recv_raw, msg->conn);
      break;
#endif
#if LWIP_PACKET
    case NETCONN_PACKET_RAW:
      msg->conn->pcb.raw = packet_new(msg->conn->stack, msg->msg.bc.port,0); /* misusing the port field as protocol */
      raw_recv(msg->conn->pcb.raw, recv_packet, msg->conn);
      break;
    case NETCONN_PACKET_DGRAM:
      msg->conn->pcb.raw = packet_new(msg->conn->stack, msg->msg.bc.port,1); /* misusing the port field as protocol */
      raw_recv(msg->conn->pcb.raw, recv_packet, msg->conn);
      break;
#endif
#if LWIP_UDP
    case NETCONN_UDPLITE:
      msg->conn->pcb.udp = udp_new(msg->conn->stack);
      udp_setflags(msg->conn->pcb.udp, UDP_FLAGS_UDPLITE);
      udp_recv(msg->conn->pcb.udp, recv_udp, msg->conn);
      break;
    case NETCONN_UDPNOCHKSUM:
      msg->conn->pcb.udp = udp_new(msg->conn->stack);
      udp_setflags(msg->conn->pcb.udp, UDP_FLAGS_NOCHKSUM);
      udp_recv(msg->conn->pcb.udp, recv_udp, msg->conn);
      break;
    case NETCONN_UDP:
      msg->conn->pcb.udp = udp_new(msg->conn->stack);
      udp_recv(msg->conn->pcb.udp, recv_udp, msg->conn);
      break;
#endif /* LWIP_UDP */
#if LWIP_TCP      
    case NETCONN_TCP:
      msg->conn->pcb.tcp = tcp_new(msg->conn->stack);
      setup_tcp(msg->conn);
#endif /* LWIP_TCP */
    default:  
    break;
    }
  }
  switch (msg->conn->type) {
#if LWIP_RAW
  case NETCONN_RAW:
    msg->conn->err = raw_bind(msg->conn->pcb.raw,msg->msg.bc.ipaddr,msg->msg.bc.port);
    break;
#endif
#if LWIP_PACKET
  case NETCONN_PACKET_RAW:
  case NETCONN_PACKET_DGRAM:
    msg->conn->err = packet_bind(msg->conn->pcb.raw,msg->msg.bc.ipaddr,msg->msg.bc.port);
    break;
#endif
#if LWIP_UDP
  case NETCONN_UDPLITE:
    /* FALLTHROUGH */
  case NETCONN_UDPNOCHKSUM:
    /* FALLTHROUGH */
  case NETCONN_UDP:
    msg->conn->err = udp_bind(msg->conn->pcb.udp, msg->msg.bc.ipaddr, msg->msg.bc.port
#ifdef LWSLIRP
				,NULL
#endif
				);
    break;
#endif /* LWIP_UDP */
#if LWIP_TCP
  case NETCONN_TCP:
    msg->conn->err = tcp_bind(msg->conn->pcb.tcp,
            msg->msg.bc.ipaddr, msg->msg.bc.port);
#endif /* LWIP_TCP */
  default:
    break;
  }
	ack_conn_mbox(msg->conn);
}
#if LWIP_TCP

static err_t
do_connected(void *arg, struct tcp_pcb *pcb, err_t err)
{
  struct netconn *conn;

  conn = arg;

  if (conn == NULL) {
    return ERR_VAL;
  }
  
  conn->err = err;
  if (conn->type == NETCONN_TCP && err == ERR_OK) {
    setup_tcp(conn);
  }    
	ack_conn_mbox(conn);
  return ERR_OK;
}
#endif  

static void
do_connect(struct api_msg_msg *msg)
{
	pending_conn_mbox(msg->conn);
	//printf("do_connect port %d\n",msg->msg.bc.port);
  if (msg->conn->pcb.tcp == NULL) {
    switch (msg->conn->type) {
#if LWIP_RAW
    case NETCONN_RAW:
      msg->conn->pcb.raw = raw_new(msg->conn->stack, msg->msg.bc.port); /* misusing the port field as protocol */
      raw_recv(msg->conn->pcb.raw, recv_raw, msg->conn);
      break;
#endif
#if LWIP_UDP
    case NETCONN_UDPLITE:
      msg->conn->pcb.udp = udp_new(msg->conn->stack);
      if (msg->conn->pcb.udp == NULL) {
				msg->conn->err = ERR_MEM;
				ack_conn_mbox(msg->conn);
				return;
      }
      udp_setflags(msg->conn->pcb.udp, UDP_FLAGS_UDPLITE);
      udp_recv(msg->conn->pcb.udp, recv_udp, msg->conn);
      break;
    case NETCONN_UDPNOCHKSUM:
      msg->conn->pcb.udp = udp_new(msg->conn->stack);
      if (msg->conn->pcb.udp == NULL) {
				msg->conn->err = ERR_MEM;
				ack_conn_mbox(msg->conn);
				return;
      }
      udp_setflags(msg->conn->pcb.udp, UDP_FLAGS_NOCHKSUM);
      udp_recv(msg->conn->pcb.udp, recv_udp, msg->conn);
      break;
    case NETCONN_UDP:
      msg->conn->pcb.udp = udp_new(msg->conn->stack);
      if (msg->conn->pcb.udp == NULL) {
				msg->conn->err = ERR_MEM;
				ack_conn_mbox(msg->conn);
				return;
      }
      udp_recv(msg->conn->pcb.udp, recv_udp, msg->conn);
      break;
#endif /* LWIP_UDP */
#if LWIP_TCP      
    case NETCONN_TCP:
      msg->conn->pcb.tcp = tcp_new(msg->conn->stack);      
      if (msg->conn->pcb.tcp == NULL) {
				msg->conn->err = ERR_MEM;
				ack_conn_mbox(msg->conn);
				return;
      }
#endif
    default:
      break;
    }
  }
  switch (msg->conn->type) {
#if LWIP_RAW
  case NETCONN_RAW:
    raw_connect(msg->conn->pcb.raw, msg->msg.bc.ipaddr,msg->msg.bc.port);
		ack_conn_mbox(msg->conn);
    break;
#endif
#if LWIP_PACKET
  case NETCONN_PACKET_RAW:
  case NETCONN_PACKET_DGRAM:
    packet_connect(msg->conn->pcb.raw,msg->msg.bc.ipaddr,msg->msg.bc.port);
		ack_conn_mbox(msg->conn);
    break;
#endif
#if LWIP_UDP
  case NETCONN_UDPLITE:
    /* FALLTHROUGH */
  case NETCONN_UDPNOCHKSUM:
    /* FALLTHROUGH */
  case NETCONN_UDP:
    udp_connect(msg->conn->pcb.udp, msg->msg.bc.ipaddr, msg->msg.bc.port);
		ack_conn_mbox(msg->conn);
    break;
#endif 
#if LWIP_TCP      
  case NETCONN_TCP:
    /*    tcp_arg(msg->conn->pcb.tcp, msg->conn);*/
    setup_tcp(msg->conn);
    tcp_connect(msg->conn->pcb.tcp, msg->msg.bc.ipaddr, msg->msg.bc.port,
    do_connected);
    /*tcp_output(msg->conn->pcb.tcp);*/
#endif

  default:
    break;
  }
}

static void
do_disconnect(struct api_msg_msg *msg)
{
	pending_conn_mbox(msg->conn);
  switch (msg->conn->type) {
#if LWIP_RAW
  case NETCONN_RAW:
    /* Do nothing as connecting is only a helper for upper lwip layers */
    break;
#endif
#if LWIP_UDP
  case NETCONN_UDPLITE:
    /* FALLTHROUGH */
  case NETCONN_UDPNOCHKSUM:
    /* FALLTHROUGH */
  case NETCONN_UDP:
    udp_disconnect(msg->conn->pcb.udp);
    break;
#endif 
  case NETCONN_TCP:
    break;
	 default:
			break;
  }
	ack_conn_mbox(msg->conn);
}


static void
do_listen(struct api_msg_msg *msg)
{
	pending_conn_mbox(msg->conn);
  if (msg->conn->pcb.tcp != NULL) {
		switch (msg->conn->type) {
#if LWIP_RAW
			case NETCONN_RAW:
				LWIP_DEBUGF(API_MSG_DEBUG, ("api_msg: listen RAW: cannot listen for RAW.\n"));
				break;
#endif
#if LWIP_UDP
			case NETCONN_UDPLITE:
				/* FALLTHROUGH */
			case NETCONN_UDPNOCHKSUM:
				/* FALLTHROUGH */
			case NETCONN_UDP:
				LWIP_DEBUGF(API_MSG_DEBUG, ("api_msg: listen UDP: cannot listen for UDP.\n"));
				break;
#endif /* LWIP_UDP */
#if LWIP_TCP      
			case NETCONN_TCP:
				msg->conn->pcb.tcp = tcp_listen(msg->conn->pcb.tcp);
				if (msg->conn->pcb.tcp == NULL) {
					msg->conn->err = ERR_MEM;
				} else {
					if (msg->conn->acceptmbox == SYS_MBOX_NULL) {
						msg->conn->acceptmbox = sys_mbox_new();
						if (msg->conn->acceptmbox == SYS_MBOX_NULL) {
							msg->conn->err = ERR_MEM;
							break;
							default:
							break;
						}
					}
					tcp_arg(msg->conn->pcb.tcp, msg->conn);
					tcp_accept(msg->conn->pcb.tcp, accept_function);
				}
#endif
		}
	}
	ack_conn_mbox(msg->conn);
}

static void
do_accept(struct api_msg_msg *msg)
{
	pending_conn_mbox(msg->conn);
  if (msg->conn->pcb.tcp != NULL) {
    switch (msg->conn->type) {
#if LWIP_RAW
    case NETCONN_RAW:
      LWIP_DEBUGF(API_MSG_DEBUG, ("api_msg: accept RAW: cannot accept for RAW.\n"));
      break;
#endif
#if LWIP_UDP
    case NETCONN_UDPLITE:
      /* FALLTHROUGH */
    case NETCONN_UDPNOCHKSUM:
      /* FALLTHROUGH */
    case NETCONN_UDP:    
      LWIP_DEBUGF(API_MSG_DEBUG, ("api_msg: accept UDP: cannot accept for UDP.\n"));
      break;
#endif /* LWIP_UDP */
    case NETCONN_TCP:
      break;
		default:
			break;
    }
  }
}

static void
do_send(struct api_msg_msg *msg)
{
	pending_conn_mbox(msg->conn);
  if (msg->conn->pcb.tcp != NULL) {
    switch (msg->conn->type) {
#if LWIP_RAW
    case NETCONN_RAW:
      raw_send(msg->conn->pcb.raw, msg->msg.p);
      break;
#endif
#if LWIP_PACKET
    case NETCONN_PACKET_RAW:
    case NETCONN_PACKET_DGRAM:
      packet_send(msg->conn->pcb.raw, msg->msg.p);
      break;
#endif
#if LWIP_UDP
    case NETCONN_UDPLITE:
      /* FALLTHROUGH */
    case NETCONN_UDPNOCHKSUM:
      /* FALLTHROUGH */
    case NETCONN_UDP:
      udp_send(msg->conn->pcb.udp, msg->msg.p);
      break;
#endif /* LWIP_UDP */
    case NETCONN_TCP:
      break;
		default:
			break;
    }
  }
	ack_conn_mbox(msg->conn);
}

static void
do_recv(struct api_msg_msg *msg)
{
	pending_conn_mbox(msg->conn);
#if LWIP_TCP
  if (msg->conn->pcb.tcp != NULL) {
    if (msg->conn->type == NETCONN_TCP) {
      tcp_recved(msg->conn->pcb.tcp, msg->msg.len);
    }
  }
#endif  
	ack_conn_mbox(msg->conn);
}

static void
do_write(struct api_msg_msg *msg)
{
#if LWIP_TCP  
  err_t err;
#endif  
	pending_conn_mbox(msg->conn);
  if (msg->conn->pcb.tcp != NULL) {
    switch (msg->conn->type) {
#if LWIP_RAW
    case NETCONN_RAW:
      msg->conn->err = ERR_VAL;
      break;
#endif
#if LWIP_UDP 
    case NETCONN_UDPLITE:
      /* FALLTHROUGH */
    case NETCONN_UDPNOCHKSUM:
      /* FALLTHROUGH */
    case NETCONN_UDP:
      msg->conn->err = ERR_VAL;
      break;
#endif /* LWIP_UDP */
#if LWIP_TCP 
    case NETCONN_TCP:      
      err = tcp_write(msg->conn->pcb.tcp, msg->msg.w.dataptr,
                      msg->msg.w.len, msg->msg.w.copy);
      /* This is the Nagle algorithm: inhibit the sending of new TCP
   segments when new outgoing data arrives from the user if any
   previously transmitted data on the connection remains
   unacknowledged. */
      if(err == ERR_OK && (msg->conn->pcb.tcp->unacked == NULL || (msg->conn->pcb.tcp->flags & TF_NODELAY)) ) {
  tcp_output(msg->conn->pcb.tcp);
      }
      msg->conn->err = err;
      if (msg->conn->callback)
          if (err == ERR_OK)
          {
              if (tcp_sndbuf(msg->conn->pcb.tcp) <= TCP_SNDLOWAT)
                  (*msg->conn->callback)(msg->conn, NETCONN_EVT_SENDMINUS, msg->msg.w.len);
          }
#endif
    default:
      break;
    }
  }
	ack_conn_mbox(msg->conn);
}

static void
do_close(struct api_msg_msg *msg)
{
  err_t err;
	pending_conn_mbox(msg->conn);

  err = ERR_OK;

  if (msg->conn->pcb.tcp != NULL) {
    switch (msg->conn->type) {
#if LWIP_RAW
    case NETCONN_RAW:
      break;
#endif
#if LWIP_UDP
    case NETCONN_UDPLITE:
      /* FALLTHROUGH */
    case NETCONN_UDPNOCHKSUM:
      /* FALLTHROUGH */
    case NETCONN_UDP:
      break;
#endif /* LWIP_UDP */
#if LWIP_TCP
    case NETCONN_TCP:
      if (msg->conn->pcb.tcp->state == LISTEN) {
				err = tcp_close(msg->conn->pcb.tcp);
      }
      msg->conn->err = err;      
#endif
    default:      
      break;
    }
  }
	ack_conn_mbox(msg->conn);
}

static void
do_peer(struct api_msg_msg *msg)
{
	struct netconn *conn=msg->conn;
	pending_conn_mbox(msg->conn);

	switch (conn->type) {
		case NETCONN_RAW:
#if LWIP_PACKET
		case NETCONN_PACKET_RAW:
		case NETCONN_PACKET_DGRAM:
#endif
			/* return an error as connecting is only a helper for upper layers */
			msg->err = ERR_CONN;
			break;
		case NETCONN_UDPLITE:
		case NETCONN_UDPNOCHKSUM:
		case NETCONN_UDP:
			if (conn->pcb.udp == NULL ||
					((conn->pcb.udp->flags & UDP_FLAGS_CONNECTED) == 0)) 
				msg->err = ERR_CONN;
			else {
				*(msg->msg.bp.ipaddr) = (conn->pcb.udp->remote_ip);
				*(msg->msg.bp.port) = conn->pcb.udp->remote_port;
			}
			break;
		case NETCONN_TCP:
			if (conn->pcb.tcp == NULL)
				msg->err = ERR_CONN;
			else {
				*(msg->msg.bc.ipaddr) = (conn->pcb.tcp->remote_ip);
				*(msg->msg.bp.port) = conn->pcb.tcp->remote_port;
			}
			break;
		default:
			msg->err = ERR_ARG;
	}
	//fprintf(stderr, "DO_PEER %d\n", msg->err);
	ack_conn_mbox(msg->conn);
}

static void
do_addr(struct api_msg_msg *msg)
{
	struct netconn *conn=msg->conn;
	pending_conn_mbox(msg->conn);

	switch (conn->type) {
		case NETCONN_RAW:
			if (conn->pcb.raw == NULL) 
				msg->err = ERR_CONN;
			else {
				*(msg->msg.bp.ipaddr) = (conn->pcb.raw->local_ip);
				*(msg->msg.bp.port) = conn->pcb.raw->in_protocol;
			}
			break;
		case NETCONN_UDPLITE:
		case NETCONN_UDPNOCHKSUM:
		case NETCONN_UDP:
			if (conn->pcb.udp == NULL)
				msg->err = ERR_CONN;
			else {
				*(msg->msg.bp.ipaddr) = (conn->pcb.udp->local_ip);
				*(msg->msg.bp.port) = conn->pcb.udp->local_port;
			}
			break;
		case NETCONN_TCP:
			if (conn->pcb.tcp == NULL)
				msg->err = ERR_CONN;
			else {
				*(msg->msg.bp.ipaddr) = (conn->pcb.tcp->local_ip);
				*(msg->msg.bp.port) = conn->pcb.tcp->local_port;
			}
			break;
		default:
			msg->err = ERR_ARG;
	}
	//fprintf(stderr, "DO_ADDR %d\n", msg->err);
	ack_conn_mbox(msg->conn);
}

static void
do_callback(struct api_msg_msg *msg)
{
	struct netconn *conn=msg->conn;
	pending_conn_mbox(msg->conn);

	msg->err = msg->msg.cb.fun(conn, msg->msg.cb.arg);

	ack_conn_mbox(msg->conn);
}

typedef void (* api_msg_decode)(struct api_msg_msg *msg);
static api_msg_decode decode[API_MSG_MAX] = {
	do_newconn,
  do_delconn,
  do_bind,
  do_connect,
  do_disconnect,
  do_listen,
  do_accept,
  do_send,
  do_recv,
  do_write,
  do_close,
	do_peer,
	do_addr,
	do_callback
  };

void
api_msg_input(struct api_msg *msg)
{  
  decode[msg->type](&(msg->msg));
}

void
api_msg_post(struct stack *stack, struct api_msg *msg)
{
  tcpip_apimsg(stack, msg);
}



