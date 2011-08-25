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

#include <stdlib.h>
#include "lwip/opt.h"

#include "lwip/mem.h"
#include "lwip/memp.h"

#include "lwip/pbuf.h"
#include "lwip/udp.h"
#include "lwip/raw.h"
#include "lwip/tcp.h"
#include "lwip/api.h"
#include "lwip/tcpip.h"
#include "lwip/netif.h"

#include "lwip/sys.h"
#include "lwip/stats.h"

/* added by Diego Billi */
#if LWIP_USERFILTER && LWIP_NAT
#include "lwip/nat/nat.h"
#endif

/*
 * FIX: This implementation uses malloc() and free() functions.
 *      These functions MUST be thread safe.
 */

static const u32_t memp_sizes[MEMP_MAX] = {
  sizeof(struct pbuf),
  sizeof(struct raw_pcb),
  sizeof(struct udp_pcb),
  sizeof(struct tcp_pcb),
  sizeof(struct tcp_pcb_listen),
  sizeof(struct tcp_seg),
  sizeof(struct netbuf),
  sizeof(struct netconn),
  sizeof(struct tcpip_msg),
  sizeof(struct sys_timeout),
  sizeof(struct ip_route_list),
  sizeof(struct ip_addr_list),
  sizeof(struct netif_fddata)
		
#if IPv4_FRAGMENTATION || IPv6_FRAGMENTATION
  ,
  sizeof(struct ip_reassbuf)
#endif

/* added by Diego Billi */
#if LWIP_USERFILTER && LWIP_NAT
  ,
  sizeof(struct nat_pcb),
  sizeof(struct nat_rule)
#endif
};

#ifndef DEBUGMEM
void
memp_init(void)
{
}

void *
memp_malloc(memp_t type)
{
	return (malloc(memp_sizes[type]));
}

void
memp_free(memp_t type, void *mem)
{
	free(mem);
}

#else
#include <signal.h>

static char *stypes[] = {
	"PBUF",
	"RAW_PCB",
	"UDP_PCB",
	"TCP_PCB",
	"TCP_PCB_LISTEN",
	"TCP_SEG",
	"NETBUF",
	"NETCONN",
	"TCPIP_MSG",
	"SYS_TIMEOUT",
	"ROUTE",
	"ADDR",
	"NETIF_FDDATA",
#if IPv4_FRAGMENTATION || IPv6_FRAGMENTATION
	"REASS",
#endif
#if LWIP_USERFILTER && LWIP_NAT
	"NAT_PCB",
	"NAT_RULE",
#endif
	"MAX"
};

int mempcount[MEMP_MAX];

static void memstat(int signo)
{
	int i;
	for (i=0; i<MEMP_MAX; i++)
		fprintf(stderr,"memp %s -> %d\n",stypes[i],mempcount[i]);
}

void
memp_d_init(char *__file, int __line)
{
	signal(SIGUSR2, memstat);
}

void *
memp_d_malloc(memp_t type, char *__file, int __line)
{
	void *rv=(mem_d_malloc(memp_sizes[type], __file, __line));
	mempcount[type]++;
	//if (type == MEMP_TCP_PCB) fprintf(stderr, "memp_d_malloc MEMP_TCP_PCB %s %d %p\n",__file,__line,rv);
	//if (type == MEMP_TCP_PCB_LISTEN) fprintf(stderr, "memp_d_malloc MEMP_TCP_PCB_LISTEN %s %d\ %pn",__file,__line,rv);
	return rv;
}

void
memp_d_free(memp_t type, void *mem, char *__file, int __line)
{
	mempcount[type]--;
	//if (type == MEMP_TCP_PCB) fprintf(stderr, "memp_d_free MEMP_TCP_PCB %s %d %p\n",__file,__line,mem);
	////if (type == MEMP_TCP_PCB_LISTEN) fprintf(stderr, "memp_d_free MEMP_TCP_PCB_LISTEN %s %d %p\n",__file,__line,mem);
	mem_d_free(mem, __file, __line);
}

#endif
