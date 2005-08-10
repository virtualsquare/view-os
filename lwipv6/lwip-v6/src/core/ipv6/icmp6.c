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

/* Some ICMP messages should be passed to the transport protocols. This
   is not implemented. */

#include "lwip/opt.h"

#include "lwip/ip.h"
#include "lwip/icmp.h"
#include "lwip/inet.h"
#include "lwip/def.h"

#include "lwip/stats.h"


void
icmp_input(struct pbuf *p, struct ip_addr_list *inad, struct pseudo_iphdr *piphdr)
{
	unsigned char type;
	struct icmp_echo_hdr *iecho;
	struct icmp_ns_hdr *ins;
	struct ip_hdr *iphdr;
	struct ip4_hdr *ip4hdr;
	struct netif *inp=inad->netif;
	struct ip_addr tmpdest;

#ifdef ICMP_STATS
	++lwip_stats.icmp.recv;
#endif /* ICMP_STATS */

	/* TODO: check length before accessing payload! */
	if (pbuf_header(p, -(piphdr->iphdrlen)) || (p->tot_len < sizeof(u16_t)*2)) {
		LWIP_DEBUGF(ICMP_DEBUG, ("icmp_input: short ICMP (%u bytes) received\n", p->tot_len));
		pbuf_free(p);
		return;
	}

	type = ((char *)p->payload)[0];
	/*printf("type %d %d\n",type,piphdr->iphdrlen);*/

	switch (type | (piphdr->version << 8)) {
		case ICMP6_ECHO | (6 << 8):
			LWIP_DEBUGF(ICMP_DEBUG, ("icmp_input: ping\n"));

			if (p->tot_len < sizeof(struct icmp_echo_hdr)) {
				LWIP_DEBUGF(ICMP_DEBUG, ("icmp_input: bad ICMP echo received\n"));

				pbuf_free(p);
#ifdef ICMP_STATS
				++lwip_stats.icmp.lenerr;
#endif /* ICMP_STATS */

				return;
			}
			iecho = p->payload;
			iphdr = (struct ip_hdr *)((char *)p->payload - IP_HLEN);
			LWIP_DEBUGF(ICMP_DEBUG, ("from ")); 
			ip_addr_debug_print(ICMP_DEBUG,  &(iphdr->src));
			LWIP_DEBUGF(ICMP_DEBUG, ("  to ")); 
			ip_addr_debug_print(ICMP_DEBUG,  &(iphdr->dest));
			LWIP_DEBUGF(ICMP_DEBUG, ("\n")); 
			/* if (inet_chksum_pbuf(p) != 0) { */
			if (inet6_chksum_pseudo(p, &(iphdr->src), &(iphdr->dest), IP_PROTO_ICMP, p->tot_len) != 0) {
				LWIP_DEBUGF(ICMP_DEBUG, ("icmp_input: checksum failed for received ICMP echo (%x)\n", inet6_chksum_pseudo(p, &(iphdr->src), &(iphdr->dest), IP_PROTO_ICMP, p->tot_len)));

#ifdef ICMP_STATS
				++lwip_stats.icmp.chkerr;
#endif /* ICMP_STATS */
				return;
			}
			LWIP_DEBUGF(ICMP_DEBUG, ("icmp: p->len %d p->tot_len %d\n", p->len, p->tot_len));
			ip_addr_set(&tmpdest, piphdr->src);
			iecho->type = ICMP6_ER;

			/*compute the new checksum*/
			iecho->chksum = 0;
			iecho->chksum = inet6_chksum_pseudo(p, &(iphdr->src), &(iphdr->dest), IP_PROTO_ICMP, p->tot_len);
#ifdef ICMP_STATS
			++lwip_stats.icmp.xmit;
#endif /* ICMP_STATS */

			/*    LWIP_DEBUGF("icmp: p->len %u p->tot_len %u\n", p->len, p->tot_len);*/
			/* XXX ECHO must be routed */
			/*ip_output_if (p, &(iphdr->src), IP_HDRINCL,
					IPH_HOPLIMIT(iphdr), 0, IP_PROTO_ICMP, inp,
					&(iphdr->dest), 0);*/
			ip_output (p, &(inad->ipaddr), &tmpdest,
					IPH_HOPLIMIT(iphdr), 0, IP_PROTO_ICMP);
			/*ip_output (p, &(inad->ipaddr), piphdr->src,
					IPH_HOPLIMIT(iphdr), 0, IP_PROTO_ICMP);*/
			break;
		case ICMP6_RA | (6 << 8):
			LWIP_DEBUGF(ICMP_DEBUG, ("icmp_input: router advertisement\n"));
			break;
		case ICMP6_NS | (6 << 8):
			LWIP_DEBUGF(ICMP_DEBUG, ("icmp_input: neighbor solicitation\n"));
			if (p->tot_len < sizeof(struct icmp_echo_hdr)) {
				LWIP_DEBUGF(ICMP_DEBUG, ("icmp_input: bad ICMP neighbor solicitation received\n"));
				pbuf_free(p);
#ifdef ICMP_STATS
				++lwip_stats.icmp.lenerr;
#endif /* ICMP_STATS */
				return;
			}
			ins = p->payload;
			iphdr = (struct ip_hdr *)((char *)p->payload - IP_HLEN);
			LWIP_DEBUGF(ICMP_DEBUG, ("from ")); 
			ip_addr_debug_print(ICMP_DEBUG,  &(iphdr->src));
			LWIP_DEBUGF(ICMP_DEBUG, ("  to ")); 
			ip_addr_debug_print(ICMP_DEBUG,  &(iphdr->dest));
			LWIP_DEBUGF(ICMP_DEBUG, ("  localaddr ")); 
			ip_addr_debug_print(ICMP_DEBUG,  &(inad->ipaddr));
			LWIP_DEBUGF(ICMP_DEBUG, ("\n")); 
			/* it is a multicast, maybe it is not for us! */
			if (! ip_addr_cmp(&inad->ipaddr, (struct ip_addr *)(ins+1))) {
				LWIP_DEBUGF(ICMP_DEBUG, ("icmp_input: not for us\n"));
				pbuf_free(p);
				return;
			}

			/* if (inet6_chksum_pbuf(p) != 0) { */
			if (inet6_chksum_pseudo(p, &(iphdr->src), &(iphdr->dest), IP_PROTO_ICMP, p->tot_len) != 0) {
				LWIP_DEBUGF(ICMP_DEBUG, ("icmp_input: checksum failed for received ICMP NS (%x)\n", inet6_chksum_pseudo(p, &(iphdr->src), &(iphdr->dest), IP_PROTO_ICMP, p->tot_len)));
#ifdef ICMP_STATS
				++lwip_stats.icmp.chkerr;
#endif /* ICMP_STATS */
				pbuf_free(p);
				return;
			}
			{
				ip_addr_set(&(iphdr->dest), &(iphdr->src));
				ip_addr_set(&(iphdr->src), &(inad->ipaddr));
			}
			ins->type = ICMP6_NA;
			ins->chksum = 0;
			ins->flags = 0xe0000000;
			*(((char *)(ins)+sizeof(struct icmp_ns_hdr)+sizeof(struct ip_addr)))=2; /*  XXX options brute-force management! */
			memcpy(((char *)(ins)+sizeof(struct icmp_ns_hdr)+sizeof(struct ip_addr)+2),&(inp->hwaddr),inp->hwaddr_len); /*  XXX options brute-force management! */
			ins->chksum = inet6_chksum_pseudo(p, &(iphdr->src), &(iphdr->dest), IP_PROTO_ICMP, p->tot_len);
			LWIP_DEBUGF(ICMP_DEBUG, ("icmp: p->len %u p->tot_len %u\n", p->len, p->tot_len));
			ip_output_if (p, &(iphdr->src), IP_HDRINCL,
					IPH_HOPLIMIT(iphdr), 0, IP_PROTO_ICMP, inp, &(iphdr->dest), 0);
			break;
		case ICMP6_NA | (6 << 8):
			LWIP_DEBUGF(ICMP_DEBUG, ("icmp_input: neighbor advertisement\n"));
			if (p->tot_len < sizeof(struct icmp_echo_hdr)) {
				LWIP_DEBUGF(ICMP_DEBUG, ("icmp_input: bad ICMP neighbor advertisement received\n"));
				pbuf_free(p);
#ifdef ICMP_STATS
				++lwip_stats.icmp.lenerr;
#endif /* ICMP_STATS */
				return;
			}
			ins = p->payload;
			iphdr = (struct ip_hdr *)((char *)p->payload - IP_HLEN);
			if (inet6_chksum_pseudo(p, &(iphdr->src), &(iphdr->dest), IP_PROTO_ICMP, p->tot_len) != 0) {
				LWIP_DEBUGF(ICMP_DEBUG, ("icmp_input: checksum failed for received ICMP NS (%x)\n", inet6_chksum_pseudo(p, &(iphdr->src), &(iphdr->dest), IP_PROTO_ICMP, p->tot_len)));
#ifdef ICMP_STATS
				++lwip_stats.icmp.chkerr;
#endif /* ICMP_STATS */
				return;
			}
			break;
		case ICMP4_ECHO | (4 << 8):
			/*printf("echo v4\n");*/
			if (ip_addr_is_v4broadcast(piphdr->dest, &(inad->ipaddr), &(inad->netmask)) ||
					ip_addr_ismulticast(piphdr->dest)) {
				LWIP_DEBUGF(ICMP_DEBUG, ("Smurf.\n"));
				ICMP_STATS_INC(icmp.err);
				pbuf_free(p);
				return;
			}

			LWIP_DEBUGF(ICMP_DEBUG, ("icmp_input: ping\n"));
			if (p->tot_len < sizeof(struct icmp_echo_hdr)) {
				LWIP_DEBUGF(ICMP_DEBUG, ("icmp_input: bad ICMP echo received\n"));
				pbuf_free(p);
				ICMP_STATS_INC(icmp.lenerr);
				/*snmp_inc_icmpinerrors();*/

				return;
			}
			iecho = p->payload;
			ip4hdr = (struct ip4_hdr *)((char *)p->payload - piphdr->iphdrlen);
			ip_addr_set(&tmpdest, piphdr->src);
			/*ip4hdr->dest.addr=piphdr->src->addr[3];
			ip4hdr->src.addr=piphdr->dest->addr[3];*/

			iecho->type=ICMP4_ER;	

			if (iecho->chksum >= htons(0xffff - (ICMP4_ECHO << 8))) {
				iecho->chksum += htons(ICMP4_ECHO << 8) + 1;
			} else {
				iecho->chksum += htons(ICMP4_ECHO << 8);
			}
			ICMP_STATS_INC(icmp.xmit);
			/*ip_output_if(p, piphdr->dest, IP_HDRINCL,
					IPH4_TTL(ip4hdr), 0, IP_PROTO_ICMP, inp,
					piphdr->src, 0);*/
			ip_output(p, &(inad->ipaddr), &tmpdest,
					IPH4_TTL(ip4hdr), 0, IP_PROTO_ICMP4);
			break;
		default:
			LWIP_DEBUGF(ICMP_DEBUG, ("icmp_input: ICMP type %d not supported.\n", (int)type));
#ifdef ICMP_STATS
			++lwip_stats.icmp.proterr;
			++lwip_stats.icmp.drop;
#endif /* ICMP_STATS */
	}

	pbuf_free(p);
}

void
icmp_neighbor_solicitation(struct ip_addr *ipaddr, struct ip_addr_list *inad)
{
	struct pbuf *q;

	struct icmp_ns_hdr *ins;
	char *opts;
	struct ip_addr targetaddr;
	struct netif *inp=inad->netif;
	LWIP_ASSERT("ICMP_NEIGHBOR_SOLICITATION NULL interface",inp != NULL);
	LWIP_ASSERT("ICMP_NEIGHBOR_SOLICITATION NULL HWADDR",inp->hwaddr != NULL);
	/*printf("icmp_neighbor_solicitation %x:%x:%x:%x from %x:%x:%x:%x\n",
			ipaddr->addr[0],
			ipaddr->addr[1],
			ipaddr->addr[2],
			ipaddr->addr[3],
			inad->ipaddr.addr[0],
			inad->ipaddr.addr[1],
			inad->ipaddr.addr[2],
			inad->ipaddr.addr[3]
			);*/

	targetaddr.addr[0]=htonl(0xff020000);
	targetaddr.addr[1]=0;
	targetaddr.addr[2]=htonl(1);
	targetaddr.addr[3]=ipaddr->addr[3] | htonl(0xff000000);
	q=pbuf_alloc(PBUF_IP, sizeof(struct icmp_ns_hdr)+sizeof(struct ip_addr)+8, PBUF_RAM);
	LWIP_ASSERT("icmp_neighbor_solicitation pbuf_alloc != NULL",q!=NULL);
	ins=q->payload;
	ins->type=ICMP6_NS;
	ins->icode=0;
	ins->chksum=0;
	ins->flags=0;
	memcpy(((char *)(ins+1)),(char *)ipaddr,sizeof(struct ip_addr));
	opts=((char *)(ins+1))+sizeof(struct ip_addr);
	*opts++=1;
	*opts++=1;
	memcpy(opts,&(inp->hwaddr),inp->hwaddr_len); /*  XXX options brute-force management! */
	ins->chksum = 0;
	ins->chksum = inet6_chksum_pseudo(q, &(inad->ipaddr), &(targetaddr), IP_PROTO_ICMP, q->tot_len);
	/*printf("icmp_neighbor_solicitation %x:%x:%x:%x from %x:%x:%x:%x\n",
			targetaddr.addr[0],
			targetaddr.addr[1],
			targetaddr.addr[2],
			targetaddr.addr[3],
			inad->ipaddr.addr[0],
			inad->ipaddr.addr[1],
			inad->ipaddr.addr[2],
			inad->ipaddr.addr[3]
			);*/
	ip_output_if (q, &(inad->ipaddr), &targetaddr,
					255, 0, IP_PROTO_ICMP, inp, &(targetaddr), 0);
#if 0
	/*  LOOP! ip_output_if does not recognize mcastv6 */
	ip_output_if (q, &(inp->ip_addr), NULL,
					255, 0, IP_PROTO_ICMP, inp);
	ip_output_if (q, IP_ADDR_ANY, NULL,
					255, 0, IP_PROTO_ICMP, inp);
#endif
	
	pbuf_free(q);
}

void
icmp_dest_unreach(struct pbuf *p, enum icmp_dur_type t)
{
	struct pbuf *q;
	struct ip_hdr *iphdr;
	struct icmp_dur_hdr *idur;

	q = pbuf_alloc(PBUF_IP, 8 + IP_HLEN + 8, PBUF_RAM);
	/* ICMP header + IP header + 8 bytes of data */

	iphdr = p->payload;

	idur = q->payload;
	idur->type = (char)ICMP6_DUR;
	idur->icode = (char)t;

	memcpy((char *)q->payload + 8, p->payload, IP_HLEN + 8);

	/* calculate checksum */
	idur->chksum = 0;
	idur->chksum = inet_chksum(idur, q->len);
#ifdef ICMP_STATS
	++lwip_stats.icmp.xmit;
#endif /* ICMP_STATS */

	ip_output(q, NULL,
			(struct ip_addr *)&(iphdr->src), ICMP_TTL, 0, IP_PROTO_ICMP);
	pbuf_free(q);
}

void
icmp_time_exceeded(struct pbuf *p, enum icmp_te_type t)
{
	struct pbuf *q;
	struct ip_hdr *iphdr;
	struct icmp_te_hdr *tehdr;

	LWIP_DEBUGF(ICMP_DEBUG, ("icmp_time_exceeded\n"));

	q = pbuf_alloc(PBUF_IP, 8 + IP_HLEN + 8, PBUF_RAM);

	iphdr = p->payload;

	tehdr = q->payload;
	tehdr->type = (char)ICMP6_TE;
	tehdr->icode = (char)t;

	/* copy fields from original packet */
	memcpy((char *)q->payload + 8, (char *)p->payload, IP_HLEN + 8);

	/* calculate checksum */
	tehdr->chksum = 0;
	tehdr->chksum = inet_chksum(tehdr, q->len);
#ifdef ICMP_STATS
	++lwip_stats.icmp.xmit;
#endif /* ICMP_STATS */
	ip_output(q, NULL,
			(struct ip_addr *)&(iphdr->src), ICMP_TTL, 0, IP_PROTO_ICMP);
	pbuf_free(q);
}
