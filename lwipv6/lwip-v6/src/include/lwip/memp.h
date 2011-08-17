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

#ifndef __LWIP_MEMP_H__
#define __LWIP_MEMP_H__

#include "lwip/opt.h"
#include "lwip/pbuf.h"
#include "lwip/udp.h"
#include "lwip/raw.h"
#include "lwip/tcp.h"
#include "lwip/api.h"
#include "lwip/api_msg.h"
#include "lwip/tcpip.h"


typedef enum {
  MEMP_PBUF,
  MEMP_RAW_PCB,
  MEMP_UDP_PCB,
  MEMP_TCP_PCB,
  MEMP_TCP_PCB_LISTEN,
  MEMP_TCP_SEG,

  MEMP_NETBUF,
  MEMP_NETCONN,
  MEMP_API_MSG,
  MEMP_TCPIP_MSG,

  MEMP_SYS_TIMEOUT,

	MEMP_ROUTE,
	MEMP_ADDR,
	MEMP_REASS,

/* added by Diego Billi */  
#if LWIP_USERFILTER && LWIP_NAT
  MEMP_NAT_PCB,
  MEMP_NAT_RULE,
#endif

  MEMP_MAX
} memp_t;

#ifndef DEBUGMEM
void memp_init(void);

void *memp_malloc(memp_t type);
void memp_free(memp_t type, void *mem);
#else
void memp_d_init(char *file, int line);

void *memp_d_malloc(memp_t type, char *file, int line);
void memp_d_free(memp_t type, void *mem, char *file, int line);

#define memp_init() memp_d_init(__FILE__,__LINE__)
#define memp_malloc(X) memp_d_malloc((X),__FILE__,__LINE__)
#define memp_free(X,Y) memp_d_free((X), (Y), __FILE__,__LINE__)
#endif



#if 0
#define memp_init() ({ ; })
#define memp_free(T,X) ({ printf("MEMP-FREE %x %s %d\n",(X),__FILE__,__LINE__); \
		    free(X); })
#if LWIP_USERFILTER && LWIP_NAT
#include "lwip/nat/nat.h"

#define memp_malloc(T) ({ void *x; \
		u16_t memp_sizes[MEMP_MAX] = {\
		sizeof(struct pbuf),\
		sizeof(struct raw_pcb),\
		sizeof(struct udp_pcb),\
		sizeof(struct tcp_pcb),\
		sizeof(struct tcp_pcb_listen),\
		sizeof(struct tcp_seg),\
		sizeof(struct netbuf),\
		sizeof(struct netconn),\
		sizeof(struct api_msg),\
		sizeof(struct tcpip_msg),\
		sizeof(struct sys_timeout),\
		sizeof(struct ip_addr_list),\
		sizeof(struct ip_reassbuf),\
		sizeof(struct nat_pcb),\
		sizeof(struct nat_rule)\
		};\
		x=malloc(memp_sizes[T]); \
		printf("MEMP-MALLOC %x (T=%d Size=%d) %s %d\n",x,T,memp_sizes[T],__FILE__,__LINE__); \
		x; })
#else
#define memp_malloc(T) ({ void *x; \
		u16_t memp_sizes[MEMP_MAX] = {\
		sizeof(struct pbuf),\
		sizeof(struct raw_pcb),\
		sizeof(struct udp_pcb),\
		sizeof(struct tcp_pcb),\
		sizeof(struct tcp_pcb_listen),\
		sizeof(struct tcp_seg),\
		sizeof(struct netbuf),\
		sizeof(struct netconn),\
		sizeof(struct api_msg),\
		sizeof(struct tcpip_msg),\
		sizeof(struct sys_timeout),\
		sizeof(struct ip_addr_list),\
		sizeof(struct ip_reassbuf)\
		};\
		x=malloc(memp_sizes[T]); \
		printf("MEMP-MALLOC %x (T=%d Size=%d) %s %d\n",x,T,memp_sizes[T],__FILE__,__LINE__); \
		x; })
#endif
#endif
#endif /* __LWIP_MEMP_H__  */

