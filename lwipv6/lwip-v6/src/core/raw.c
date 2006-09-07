/**
 * @file
 * 
 * Implementation of raw protocol PCBs for low-level handling of
 * different types of protocols besides (or overriding) those
 * already available in lwIP.
 *
 */

/*   This is part of LWIPv6
 *   Developed for the Ale4NET project
 *   Application Level Environment for Networking
 *   
 *   Copyright 2004 Renzo Davoli University of Bologna - Italy
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
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
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

#include <string.h>

#include "lwip/opt.h"

#include "lwip/def.h"
#include "lwip/memp.h"
#include "lwip/inet.h"
#include "lwip/ip_addr.h"
#include "lwip/netif.h"
#include "lwip/raw.h"

#include "lwip/stats.h"

#include "arch/perf.h"
#include "lwip/snmp.h"

#if LWIP_RAW

/** The list of RAW PCBs */
static struct raw_pcb *raw_pcbs = NULL;

void
raw_init(void)
{
  raw_pcbs = NULL;
}

/**
 * Determine if in incoming IP packet is covered by a RAW PCB
 * and if so, pass it to a user-provided receive callback function.
 *
 * Given an incoming IP datagram (as a chain of pbufs) this function
 * finds a corresponding RAW PCB and calls the corresponding receive
 * callback function.
 *
 * @param pbuf pbuf to be demultiplexed to a RAW PCB.
 * @param netif network interface on which the datagram was received.
 * @Return - 1 if the packet has been eaten by a RAW PCB receive
 *           callback function. The caller MAY NOT not reference the
 *           packet any longer, and MAY NOT call pbuf_free().
 * @return - 0 if packet is not eaten (pbuf is still referenced by the
 *           caller).
 *
 */
u8_t
raw_input(struct pbuf *p, struct ip_addr_list *inad, struct pseudo_iphdr *piphdr)
{
  struct raw_pcb *pcb;
  u16_t proto;

  LWIP_DEBUGF(RAW_DEBUG, ("raw_input\n"));
	proto = piphdr->proto;

  pcb = raw_pcbs;
  /* loop through all raw pcbs */
  /* this allows multiple pcbs to match against the packet by design */
  while ( (pcb != NULL)) {
    if (pcb->in_protocol == proto) {
      /* receive callback function available? */
      if (pcb->recv != NULL) {
				struct pbuf *r, *q;
				char *ptr;

				r = pbuf_alloc(PBUF_RAW, p->tot_len, PBUF_RAM);

				if (r != NULL) {
					ptr = r->payload;

					for(q = p; q != NULL; q = q->next) {
						memcpy(ptr, q->payload, q->len);
						ptr += q->len;
					}

					pcb->recv(pcb->recv_arg, pcb, r, piphdr->src, proto);
				}
      }
      /* no receive callback function was set for this raw PCB */
      /* drop the packet */
    }
    pcb = pcb->next;
  }
  LWIP_DEBUGF(RAW_DEBUG, ("raw_input leave\n"));
  return 0;
}

/**
 * Bind a RAW PCB.
 *
 * @param pcb RAW PCB to be bound with a local address ipaddr.
 * @param ipaddr local IP address to bind with. Use IP_ADDR_ANY to
 * bind to all local interfaces.
 *
 * @return lwIP error code.
 * - ERR_OK. Successful. No error occured.
 * - ERR_USE. The specified IP address is already bound to by
 * another RAW PCB.
 *
 * @see raw_disconnect()
 */
err_t
raw_bind(struct raw_pcb *pcb, struct ip_addr *ipaddr, u16_t protocol)
{
  ip_addr_set(&pcb->local_ip, ipaddr);
	if (protocol)
		pcb->in_protocol=protocol;
  return ERR_OK;
}

/**
 * Connect an RAW PCB. This function is required by upper layers
 * of lwip. Using the raw api you could use raw_sendto() instead
 *
 * This will associate the RAW PCB with the remote address.
 *
 * @param pcb RAW PCB to be connected with remote address ipaddr and port.
 * @param ipaddr remote IP address to connect with.
 *
 * @return lwIP error code
 *
 * @see raw_disconnect() and raw_sendto()
 */
err_t
raw_connect(struct raw_pcb *pcb, struct ip_addr *ipaddr, u16_t port)
{
  ip_addr_set(&pcb->remote_ip, ipaddr);
  return ERR_OK;
}


/**
 * Set the callback function for received packets that match the
 * raw PCB's protocol and binding. 
 * 
 * The callback function MUST either
 * - eat the packet by calling pbuf_free() and returning non-zero. The
 *   packet will not be passed to other raw PCBs or other protocol layers.
 * - not free the packet, and return zero. The packet will be matched
 *   against further PCBs and/or forwarded to another protocol layers.
 * 
 * @return non-zero if the packet was free()d, zero if the packet remains
 * available for others.
 */
void
raw_recv(struct raw_pcb *pcb,
         void (* recv)(void *arg, struct raw_pcb *upcb, struct pbuf *p,
                      struct ip_addr *addr, u16_t protocol),
         void *recv_arg)
{
  /* remember recv() callback and user data */
  pcb->recv = recv;
  pcb->recv_arg = recv_arg;
}

/**
 * Send the raw IP packet to the given address. Note that actually you cannot
 * modify the IP headers (this is inconsistent with the receive callback where
 * you actually get the IP headers), you can only specify the IP payload here.
 * It requires some more changes in lwIP. (there will be a raw_send() function
 * then.)
 *
 * @param pcb the raw pcb which to send
 * @param p the IP payload to send
 * @param ipaddr the destination address of the IP packet
 *
 */
err_t
raw_sendto(struct raw_pcb *pcb, struct pbuf *p, struct ip_addr *ipaddr)
{
  err_t err;
  struct netif *netif;
  struct ip_addr *src_ip;
  struct pbuf *q; /* q will be sent down the stack */
	struct ip_addr *nexthop;
	int flags;

  
  LWIP_DEBUGF(RAW_DEBUG | DBG_TRACE | 3, ("raw_sendto\n"));
  
	/*fprintf(stderr,"RAW sendto %p %p\n",p,p->payload);*/
	if (! (pcb->so_options & SOF_HDRINCL)) 
	{

		/* not enough space to add an IP header to first pbuf in given p chain? */
		if (pbuf_header(p, ip_addr_is_v4comp(ipaddr)?IP4_HLEN:IP_HLEN)) {
			/* allocate header in new pbuf */
			q = pbuf_alloc(PBUF_IP, 0, PBUF_RAM);
			/* new header pbuf could not be allocated? */
			if (q == NULL) {
				LWIP_DEBUGF(RAW_DEBUG | DBG_TRACE | 2, ("raw_sendto: could not allocate header\n"));
				return ERR_MEM;
			}
			/* chain header q in front of given pbuf p */
			pbuf_chain(q, p);
			/* { first pbuf q points to header pbuf } */
			LWIP_DEBUGF(RAW_DEBUG, ("raw_sendto: added header pbuf %p before given pbuf %p\n", (void *)q, (void *)p));
		}  else {
			/* first pbuf q equals given pbuf */
			q = p;
			pbuf_header(q, - (ip_addr_is_v4comp(ipaddr)?IP4_HLEN:IP_HLEN));
		}
	} else  {
		q =  pbuf_alloc(PBUF_LINK, p->len, PBUF_RAM);
		if (q == NULL) {
			LWIP_DEBUGF(RAW_DEBUG | DBG_TRACE | 2, ("raw_sendto: could not allocate HDRINCL packet\n"));
			return ERR_MEM;
		}
		memcpy(q->payload,p->payload,p->len);
		/*printf("pbuf_header %d %d %d\n",ip_addr_is_v4comp(ipaddr),- (ip_addr_is_v4comp(ipaddr)?IP4_HLEN:IP_HLEN),p->tot_len);
		pbuf_header(q, - (ip_addr_is_v4comp(ipaddr)?IP4_HLEN:IP_HLEN));*/
	}

  /*printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>1\n");*/
  
  ip_addr_debug_print(IP_DEBUG, ipaddr);

  if(ip_route_findpath(ipaddr,&nexthop,&netif,&flags) != ERR_OK) {
    LWIP_DEBUGF(RAW_DEBUG | 1, ("raw_sendto: No route to %p\n", ipaddr->addr));
#if RAW_STATS
    /*    ++lwip_stats.raw.rterr;*/
#endif /* RAW_STATS */
    /* free any temporary header pbuf allocated by pbuf_header() */
    if (q != p) {
      pbuf_free(q);
    }
    return ERR_RTE;
  }

  /*printf("nexthop: "); ip_addr_debug_print(IP_DEBUG, nexthop); printf("\n");*/

  if (ip_addr_isany(&(pcb->local_ip))) {
    /* use outgoing network interface IP address as source address */
    /*src_ip = &(netif->ip_addr);*/
	struct ip_addr_list *el;

	///if ((el=ip_addr_list_maskfind(netif->addrs, nexthop)) != NULL) {
    ///  src_ip= &(el->ipaddr);
	///} else {
	///  src_ip = &(pcb->local_ip);
	///}

    /* Added by Diego Billi */
    /* Get source address */
    if (ip_addr_is_v4comp(&pcb->remote_ip)) 
      el = ip_addr_list_maskfind(netif->addrs, nexthop);
    else 
      el = ip_route_ipv6_select_source(netif, &pcb->remote_ip);

    if (el != NULL) {
      src_ip = &(el->ipaddr);
    }
    else {
      src_ip = &(pcb->local_ip); 
      // FIX: i should do these instead?
      //if (q != p) 
      //  pbuf_free(q);
      //return ERR_RTE;
    }

  } else {
    /* use RAW PCB local IP address as source address */
    src_ip = &(pcb->local_ip);
  }
  /*printf("outping %lx:%lx:%lx:%lx proto=%d\n",
			  ipaddr->addr[0],
			  ipaddr->addr[1],
			  ipaddr->addr[2],
			  ipaddr->addr[3],pcb->out_protocol);*/

  if (pcb->so_options & SOF_IPV6_CHECKSUM) {
	  u16_t *checksump;

	  /*printf("checksum offset %d\n",pcb->checksumoffset);
	  printf("checksum %d len %d \n",pcb->protocol,p->tot_len);*/
	  checksump=(u16_t *) (((u8_t *)p->payload)+pcb->checksumoffset);
	  /*printf("checksum in %x\n",*checksump);*/
	  *checksump=inet6_chksum_pseudo(p, src_ip, ipaddr,
				            pcb->in_protocol, p->tot_len);

  }

  err = ip_output_if (q, src_ip, 
			  (pcb->so_options & SOF_HDRINCL)?IP_LWHDRINCL:ipaddr, 
				pcb->ttl, pcb->tos, pcb->in_protocol, netif, nexthop, flags);

  /* did we chain a header earlier? */
  if (q != p) {
    /* free the header */
    pbuf_free(q);
  }
  return err;
}

/**
 * Send the raw IP packet to the address given by raw_connect()
 *
 * @param pcb the raw pcb which to send
 * @param p the IP payload to send
 * @param ipaddr the destination address of the IP packet
 *
 */
err_t
raw_send(struct raw_pcb *pcb, struct pbuf *p)
{
  return raw_sendto(pcb, p, &pcb->remote_ip);
}

/**
 * Remove an RAW PCB.
 *
 * @param pcb RAW PCB to be removed. The PCB is removed from the list of
 * RAW PCB's and the data structure is freed from memory.
 *
 * @see raw_new()
 */
void
raw_remove(struct raw_pcb *pcb)
{
  struct raw_pcb *pcb2;
  /* pcb to be removed is first in list? */
  if (raw_pcbs == pcb) {
    /* make list start at 2nd pcb */
    raw_pcbs = raw_pcbs->next;
    /* pcb not 1st in list */
  } else for(pcb2 = raw_pcbs; pcb2 != NULL; pcb2 = pcb2->next) {
    /* find pcb in raw_pcbs list */
    if (pcb2->next != NULL && pcb2->next == pcb) {
      /* remove pcb from list */
      pcb2->next = pcb->next;
    }
  }
  memp_free(MEMP_RAW_PCB, pcb);
}

/**
 * Create a RAW PCB.
 *
 * @return The RAW PCB which was created. NULL if the PCB data structure
 * could not be allocated.
 *
 * @param proto the protocol number of the IPs payload (e.g. IP_PROTO_ICMP)
 *
 * @see raw_remove()
 */
struct raw_pcb *
raw_new(u16_t proto) {
  struct raw_pcb *pcb;

  LWIP_DEBUGF(RAW_DEBUG | DBG_TRACE | 3, ("raw_new\n"));

  pcb = memp_malloc(MEMP_RAW_PCB);
  /* could allocate RAW PCB? */
  if (pcb != NULL) {
    /* initialize PCB to all zeroes */
    memset(pcb, 0, sizeof(struct raw_pcb));
    pcb->in_protocol = proto;
    pcb->ttl = RAW_TTL;
    pcb->next = raw_pcbs;
    //pcb->checksumoffset=0; //already 0 for memset
    raw_pcbs = pcb;
  }
  return pcb;
}

#endif /* LWIP_RAW */
