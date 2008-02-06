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

#include "lwip/memp.h"

#include "lwip/pbuf.h"
#include "lwip/udp.h"
#include "lwip/raw.h"
#include "lwip/tcp.h"
#include "lwip/api.h"
#include "lwip/api_msg.h"
#include "lwip/tcpip.h"

#include "lwip/sys.h"
#include "lwip/stats.h"

/* added by Diego Billi */
#if LWIP_USERFILTER && LWIP_NAT
#include "lwip/nat/nat.h"
#endif


struct memp {
  struct memp *next;
};

static struct memp *memp_tab[MEMP_MAX];

static const u16_t memp_sizes[MEMP_MAX] = {
  MEM_ALIGN_SIZE(sizeof(struct pbuf)),
  MEM_ALIGN_SIZE(sizeof(struct raw_pcb)),
  MEM_ALIGN_SIZE(sizeof(struct udp_pcb)),
  MEM_ALIGN_SIZE(sizeof(struct tcp_pcb)),
  MEM_ALIGN_SIZE(sizeof(struct tcp_pcb_listen)),
  MEM_ALIGN_SIZE(sizeof(struct tcp_seg)),
  MEM_ALIGN_SIZE(sizeof(struct netbuf)),
  MEM_ALIGN_SIZE(sizeof(struct netconn)),
  MEM_ALIGN_SIZE(sizeof(struct api_msg)),
  MEM_ALIGN_SIZE(sizeof(struct tcpip_msg)),
  MEM_ALIGN_SIZE(sizeof(struct sys_timeout))

/* added by Diego Billi */
#if LWIP_USERFILTER && LWIP_NAT
  ,
  MEM_ALIGN_SIZE(sizeof(struct nat_pcb)),
  MEM_ALIGN_SIZE(sizeof(struct nat_rule))
#endif  
};

static const u16_t memp_num[MEMP_MAX] = {
  MEMP_NUM_PBUF,
  MEMP_NUM_RAW_PCB,
  MEMP_NUM_UDP_PCB,
  MEMP_NUM_TCP_PCB,
  MEMP_NUM_TCP_PCB_LISTEN,
  MEMP_NUM_TCP_SEG,
  MEMP_NUM_NETBUF,
  MEMP_NUM_NETCONN,
  MEMP_NUM_API_MSG,
  MEMP_NUM_TCPIP_MSG,
  MEMP_NUM_SYS_TIMEOUT

/* added by Diego Billi */
#if LWIP_USERFILTER && LWIP_NAT
  ,
  MEMP_NUM_NAT_PCB,
  MEMP_NUM_NAT_RULE
#endif	
};

#if !SYS_LIGHTWEIGHT_PROT
static sys_sem_t mutex;
#endif

static struct memp *memp_newpool(int type)
{
	LWIP_DEBUGF(MEMP_DEBUG, ("memp_malloc: newpool %d\n", type));
  LWIP_ASSERT("memp_newpool: size < sizeof(*)", memp_sizes[type] >= sizeof (void *));
	char *newpool=(char *)malloc(memp_sizes[type]*memp_num[type]);
	if (newpool == NULL)
		return NULL;
	else
	{
		char *p=newpool;
		int i;
		for (i=0;i<memp_num[type]-1;i++) 
			p=(char *)((((struct memp *)p)->next)=(struct memp *)(p+memp_sizes[type]));
		((struct memp *)p)->next = NULL;
		return (struct memp *) newpool;
	}
}

void
memp_init(void)
{
  u16_t i;
      
#if MEMP_STATS
  for(i = 0; i < MEMP_MAX; ++i) {
    lwip_stats.memp[i].used = lwip_stats.memp[i].max =
      lwip_stats.memp[i].err = 0;
    lwip_stats.memp[i].avail = memp_num[i];
  }
#endif /* MEMP_STATS */

	for (i=0; i<MEMP_MAX ;i++)
		memp_tab[i]=memp_newpool(i);
#if !SYS_LIGHTWEIGHT_PROT
  mutex = sys_sem_new(1);
#endif
  
}

void *
memp_malloc(memp_t type)
{
  struct memp *memp;
#if SYS_LIGHTWEIGHT_PROT
  SYS_ARCH_DECL_PROTECT(old_level);
#endif
 
	LWIP_DEBUGF(MEMP_DEBUG, ("memp_malloc: malloc %d ...\n", type));
  LWIP_ASSERT("memp_malloc: type < MEMP_MAX", type < MEMP_MAX);

#if SYS_LIGHTWEIGHT_PROT
  SYS_ARCH_PROTECT(old_level);
#else /* SYS_LIGHTWEIGHT_PROT */  
  sys_sem_wait(mutex);
#endif /* SYS_LIGHTWEIGHT_PROT */  

  memp = memp_tab[type];
	if (memp == NULL)
		memp = memp_tab[type] = memp_newpool(type);
  
  if (memp != NULL) {    
    memp_tab[type] = memp->next;    
#if MEMP_STATS
    ++lwip_stats.memp[type].used;
    if (lwip_stats.memp[type].used > lwip_stats.memp[type].max) {
      lwip_stats.memp[type].max = lwip_stats.memp[type].used;
    }
#endif /* MEMP_STATS */
#if SYS_LIGHTWEIGHT_PROT
    SYS_ARCH_UNPROTECT(old_level);
#else /* SYS_LIGHTWEIGHT_PROT */
    sys_sem_signal(mutex);
#endif /* SYS_LIGHTWEIGHT_PROT */  
		LWIP_DEBUGF(MEMP_DEBUG, ("memp_malloc: malloc %d %p\n", type,memp));
    return (void *) memp;
  } else {
    LWIP_DEBUGF(MEMP_DEBUG | 2, ("memp_malloc: out of memory in pool %d\n", type));
#if MEMP_STATS
    ++lwip_stats.memp[type].err;
#endif /* MEMP_STATS */
#if SYS_LIGHTWEIGHT_PROT
  SYS_ARCH_UNPROTECT(old_level);
#else /* SYS_LIGHTWEIGHT_PROT */
  sys_sem_signal(mutex);
#endif /* SYS_LIGHTWEIGHT_PROT */  
    return NULL;
  }
}

void
memp_free(memp_t type, void *mem)
{
  struct memp *memp;
	LWIP_DEBUGF(MEMP_DEBUG, ("memp_free: free %d %p\n", type, mem));
#if SYS_LIGHTWEIGHT_PROT
  SYS_ARCH_DECL_PROTECT(old_level);
#endif /* SYS_LIGHTWEIGHT_PROT */  

  if (mem == NULL) {
    return;
  }
  memp = (struct memp *)(mem);

#if SYS_LIGHTWEIGHT_PROT
    SYS_ARCH_PROTECT(old_level);
#else /* SYS_LIGHTWEIGHT_PROT */  
  sys_sem_wait(mutex);
#endif /* SYS_LIGHTWEIGHT_PROT */  

#if MEMP_STATS
  lwip_stats.memp[type].used--; 
#endif /* MEMP_STATS */
  
  memp->next = memp_tab[type]; 
  memp_tab[type] = memp;

#if MEMP_SANITY_CHECK
  LWIP_ASSERT("memp sanity", memp_sanity());
#endif  

#if SYS_LIGHTWEIGHT_PROT
  SYS_ARCH_UNPROTECT(old_level);
#else /* SYS_LIGHTWEIGHT_PROT */
  sys_sem_signal(mutex);
#endif /* SYS_LIGHTWEIGHT_PROT */  
}
