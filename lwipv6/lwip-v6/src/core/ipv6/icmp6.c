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
 *   51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
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

#include "lwip/debug.h"


#include "lwip/ip.h"
#include "lwip/icmp.h"
#include "lwip/inet.h"
#include "lwip/def.h"

#include "lwip/stats.h"

#if IPv6_AUTO_CONFIGURATION
#include "lwip/ip_autoconf.h"
#endif

/*--------------------------------------------------------------------------*/

/*
 * Handle ICMP input packets.
 *   p      = ICMP packet
 *   inad   = Interface destination Address
 *   piphdr = IP pseudo header
 */
void
icmp_input(struct stack *stack, struct pbuf *p, struct ip_addr_list *inad, struct pseudo_iphdr *piphdr)
{
	struct ip_hdr  *iphdr;
	struct ip4_hdr *ip4hdr;
	unsigned char type;
	struct icmp_echo_hdr *iecho;
	struct icmp_ns_hdr   *ins;
	struct icmp_na_hdr   *ina;

	struct icmp_opt_addr   *opt;

	struct ip_addr tmpdest;

	struct netif *inp = inad->netif;

	/* FIX: remove 'stack' and use only inp->stack */
	LWIP_ASSERT("STACK !=  NETIFSTACK \n", stack == inp->stack); 


	ICMP_STATS_INC(icmp.recv);

	/* TODO: check length before accessing payload! */
	if (pbuf_header(p, -(piphdr->iphdrlen)) || (p->tot_len < sizeof(u16_t)*2)) {
		LWIP_DEBUGF(ICMP_DEBUG, ("icmp_input: short ICMP (%u bytes) received\n", p->tot_len));
		pbuf_free(p);
		return;
	}

	type = ((char *)p->payload)[0];
	switch (type | (piphdr->version << 8)) {

		case ICMP6_ECHO | (6 << 8):
			LWIP_DEBUGF(ICMP_DEBUG, ("icmp_input:  icmp6 ping\n"));
			if (p->tot_len < sizeof(struct icmp_echo_hdr)) {
				LWIP_DEBUGF(ICMP_DEBUG, ("icmp_input: bad ICMP echo received\n"));
				pbuf_free(p);
				ICMP_STATS_INC(icmp.lenerr);
				return;
			}
			iecho = p->payload;
			iphdr = (struct ip_hdr *)((char *)p->payload - IP_HLEN);
			LWIP_DEBUGF(ICMP_DEBUG, ("from ")); ip_addr_debug_print(ICMP_DEBUG,  &(iphdr->src));
			LWIP_DEBUGF(ICMP_DEBUG, ("  to ")); ip_addr_debug_print(ICMP_DEBUG,  &(iphdr->dest));
			LWIP_DEBUGF(ICMP_DEBUG, ("\n")); 

			if (inet6_chksum_pseudo(p, &(iphdr->src), &(iphdr->dest), IP_PROTO_ICMP, p->tot_len) != 0) {
				LWIP_DEBUGF(ICMP_DEBUG, ("icmp_input: checksum failed for received ICMP echo (%x)\n", inet6_chksum_pseudo(p, &(iphdr->src), &(iphdr->dest), IP_PROTO_ICMP, p->tot_len)));
				ICMP_STATS_INC(icmp.chkerr);
				return;
			}
			LWIP_DEBUGF(ICMP_DEBUG, ("icmp: p->len %d p->tot_len %d\n", p->len, p->tot_len));


			/* Reuse packet and set up echo response */

			ip_addr_set(&tmpdest, piphdr->src);
			iecho->type = ICMP6_ER;

			/*compute the new checksum*/
			iecho->chksum = 0;
			iecho->chksum = inet6_chksum_pseudo(p, &(iphdr->src), &(iphdr->dest), IP_PROTO_ICMP, p->tot_len);

			ICMP_STATS_INC(icmp.xmit);

			/* XXX ECHO must be routed */
			ip_output (stack, p, &(inad->ipaddr), &tmpdest, IPH_HOPLIMIT(iphdr), 0, IP_PROTO_ICMP);
			break;

		/*
		 * Neighbor Sollicitation protocol
		 */
		case ICMP6_NS | (6 << 8):
			LWIP_DEBUGF(ICMP_DEBUG, ("icmp_input: icmp6 neighbor solicitation\n"));
			if (p->tot_len < sizeof(struct icmp_ns_hdr)) {
				LWIP_DEBUGF(ICMP_DEBUG, ("icmp_input: bad ICMP neighbor solicitation received\n"));
				pbuf_free(p);
				ICMP_STATS_INC(icmp.lenerr);
				return;
			}
			ins = p->payload;
			iphdr = (struct ip_hdr *)((char *)p->payload - IP_HLEN);
			if (inet6_chksum_pseudo(p, &(iphdr->src), &(iphdr->dest), IP_PROTO_ICMP, p->tot_len) != 0) {
				LWIP_DEBUGF(ICMP_DEBUG, ("icmp_input: checksum failed for received ICMP NS (%x)\n", inet6_chksum_pseudo(p, &(iphdr->src), &(iphdr->dest), IP_PROTO_ICMP, p->tot_len)));
				ICMP_STATS_INC(icmp.chkerr);
				pbuf_free(p);
				return;
			}

			LWIP_DEBUGF(ICMP_DEBUG, ("FROM ")); ip_addr_debug_print(ICMP_DEBUG,  &(iphdr->src));
			LWIP_DEBUGF(ICMP_DEBUG, ("  TO ")); ip_addr_debug_print(ICMP_DEBUG,  &(iphdr->dest));
			LWIP_DEBUGF(ICMP_DEBUG, ("  LOCALADDR ")); ip_addr_debug_print(ICMP_DEBUG,  &(inad->ipaddr));
			LWIP_DEBUGF(ICMP_DEBUG, ("\n")); 
			LWIP_DEBUGF(ICMP_DEBUG, ("TARGETIP ")); ip_addr_debug_print(ICMP_DEBUG, (struct ip_addr *) &ins->targetip );
			LWIP_DEBUGF(ICMP_DEBUG, ("\n")); 

                       	if (ip_addr_list_deliveryfind(inad->netif->addrs, (struct ip_addr *) &ins->targetip, &(iphdr->src)) == NULL) {
					LWIP_DEBUGF(ICMP_DEBUG, ("icmp_input: not for us\n"));
					pbuf_free(p);
					return;

			}

			/* Reuse packet and create response */

			ina = p->payload;
			opt = p->payload + sizeof(struct icmp_na_hdr);			
			if (pbuf_header(p, IP_HLEN)) {
				LWIP_DEBUGF(ICMP_DEBUG, ("icmp_input: NA alloc ERR\n"));
				pbuf_free(p);
				return;
			}

			iphdr = (struct ip_hdr *)(p->payload);

			/* Set IP header */
			ip_addr_set(&(iphdr->dest), &(iphdr->src));
			ip_addr_set(&(iphdr->src), &(inad->ipaddr));

			/* Set ICMP NA fields */
			ina->type = ICMP6_NA;
			ina->icode = 0;
			/* FIX: why R bit set ? */
			ina->rso_flags = (ICMP6_NA_S | ICMP6_NA_O | ICMP6_NA_R);
			bzero(ina->reserved, 3);

			/* ina->targetip   Don't touch this field. For solicited 
			   advertisements, the Target Address field in the Neighbor 
			   Solicitation message that prompted this advertisement. */

			/* Set Target link-layer address */
			opt->type = ICMP6_OPT_DESTADDR;
			opt->len  = ICMP6_OPT_LEN_ETHER;
			memcpy( &opt->addr, &(inp->hwaddr), inp->hwaddr_len);

			pbuf_header(p, - IP_HLEN);
			/* Calculate checksum */
			ins->chksum = 0;
			ins->chksum = inet6_chksum_pseudo(p, &(iphdr->src), &(iphdr->dest), IP_PROTO_ICMP, p->tot_len);
			pbuf_header(p, IP_HLEN);

			LWIP_DEBUGF(ICMP_DEBUG, ("icmp: p->len %u p->tot_len %u\n", p->len, p->tot_len));
			LWIP_DEBUGF(ICMP_DEBUG, ("icmp: send Neighbor Advertisement\n"));

			ip_output_if (stack, p, &(iphdr->src), IP_LWHDRINCL, IPH_HOPLIMIT(iphdr), 0, IP_PROTO_ICMP, inp, &(iphdr->dest), 0);
			break;

		case ICMP6_NA | (6 << 8):
			LWIP_DEBUGF(ICMP_DEBUG, ("icmp_input:  icmp6 neighbor advertisement\n"));
			if (p->tot_len < sizeof(struct icmp_na_hdr)) {
				LWIP_DEBUGF(ICMP_DEBUG, ("icmp_input: bad ICMP neighbor advertisement received\n"));
				pbuf_free(p);
				ICMP_STATS_INC(icmp.lenerr);
				return;
			}
			ina = p->payload;
			opt = p->payload + sizeof(struct icmp_na_hdr);			
			iphdr = (struct ip_hdr *)((char *)p->payload - IP_HLEN);
			if (inet6_chksum_pseudo(p, &(iphdr->src), &(iphdr->dest), IP_PROTO_ICMP, p->tot_len) != 0) {
				LWIP_DEBUGF(ICMP_DEBUG, ("icmp_input: checksum failed for received ICMP NS (%x)\n", inet6_chksum_pseudo(p, &(iphdr->src), &(iphdr->dest), IP_PROTO_ICMP, p->tot_len)));
				ICMP_STATS_INC(icmp.chkerr);
				return;
			}

			/* The sender is a router? */
			if (ina->rso_flags & ICMP6_NA_R) {
				/* TODO: */
			}

			/* override an existing cache  entry and update the cached link-layer address? */
			if (ina->rso_flags & ICMP6_NA_O) {
				/* TODO */
			}

#if IPv6_AUTO_CONFIGURATION  
			/* FIX: add MULTISTACK */

			/* Check Target IP for Duplicate Address Detection protocol */
			ip_autoconf_handle_na(inad->netif, p, iphdr, ina);
#endif

#if IPv6_PMTU_DISCOVERY
			/* FIX: this function is 'static' in etharp.c 
			update_arp_entry(inp, & ina->targetip, & opt->addr, 0); 
			*/
#endif
			break;

		/*
		 * Router Advertisement Protocol 
		 */
		case ICMP6_RS | (6 << 8):
#if IPv6_ROUTER_ADVERTISEMENT
			{
			struct icmp_rs_hdr   *irs;

			LWIP_DEBUGF(ICMP_DEBUG, ("icmp_input: icmp6 Route Solicitation \n"));
			if (p->tot_len < sizeof(struct icmp_rs_hdr)) {
				LWIP_DEBUGF(ICMP_DEBUG, ("icmp_input: bad ICMP Router solicitation received\n"));
				pbuf_free(p);
				ICMP_STATS_INC(icmp.lenerr);
				return;
			}

			iphdr = (struct ip_hdr *)((char *)p->payload - IP_HLEN);
			irs = p->payload;
			if (inet6_chksum_pseudo(p, &(iphdr->src), &(iphdr->dest), IP_PROTO_ICMP, p->tot_len) != 0) {
				LWIP_DEBUGF(ICMP_DEBUG, ("icmp_input: checksum failed for received ICMP RS (%x)\n", inet6_chksum_pseudo(p, &(iphdr->src), &(iphdr->dest), IP_PROTO_ICMP, p->tot_len)));
				ICMP_STATS_INC(icmp.chkerr);
				return;
			}

			/* FIX: add MULTISTACK */
			ip_radv_handle_rs(inad->netif, p, iphdr, irs);
			}
#else
			LWIP_DEBUGF(ICMP_DEBUG, ("icmp_input: icmp6 router Solicitation. Not supported!\n"));
#endif


			break;

		case ICMP6_RA | (6 << 8):
#if IPv6_AUTO_CONFIGURATION  
			{
			struct icmp_ra_hdr   *ira;

			LWIP_DEBUGF(ICMP_DEBUG, ("icmp_input: icmp6 Route Advertisement \n"));
			if (p->tot_len < sizeof(struct icmp_ra_hdr)) {
				LWIP_DEBUGF(ICMP_DEBUG, ("icmp_input: bad ICMP Router advertisement received\n"));
				pbuf_free(p);
				ICMP_STATS_INC(icmp.lenerr);
				return;
			}

			iphdr = (struct ip_hdr *)((char *)p->payload - IP_HLEN);
			ira = p->payload;
			if (inet6_chksum_pseudo(p, &(iphdr->src), &(iphdr->dest), IP_PROTO_ICMP, p->tot_len) != 0) {
				LWIP_DEBUGF(ICMP_DEBUG, ("icmp_input: checksum failed for received ICMP NS (%x)\n", inet6_chksum_pseudo(p, &(iphdr->src), &(iphdr->dest), IP_PROTO_ICMP, p->tot_len)));
				ICMP_STATS_INC(icmp.chkerr);
				return;
			}

			/* Try autoconfiguration */
			ip_autoconf_handle_ra(inad->netif, p, iphdr, ira);
			}
#else
			LWIP_DEBUGF(ICMP_DEBUG, ("icmp_input: icmp6 Route Advertisement. Not supported \n"));
#endif

			break;

		/*
		 * IPv4
		 */
		case ICMP4_ECHO | (4 << 8):
			LWIP_DEBUGF(ICMP_DEBUG, ("icmp_input: icmp4 echo\n"));
			if (ip_addr_is_v4broadcast(piphdr->dest, &(inad->ipaddr), &(inad->netmask)) ||
					ip_addr_ismulticast(piphdr->dest)) {
				LWIP_DEBUGF(ICMP_DEBUG, ("Smurf.\n"));
				ICMP_STATS_INC(icmp.err);
				pbuf_free(p);
				return;
			}

			if (p->tot_len < sizeof(struct icmp_echo_hdr)) {
				LWIP_DEBUGF(ICMP_DEBUG, ("icmp_input: bad ICMP echo received\n"));
				ICMP_STATS_INC(icmp.lenerr);
				pbuf_free(p);
				return;
			}

			/* Set up echo response */

			iecho = p->payload;
			ip4hdr = (struct ip4_hdr *)((char *)p->payload - piphdr->iphdrlen);
			ip_addr_set(&tmpdest, piphdr->src);

			iecho->type=ICMP4_ER;	

			if (iecho->chksum >= htons(0xffff - (ICMP4_ECHO << 8))) {
				iecho->chksum += htons(ICMP4_ECHO << 8) + 1;
			} else {
				iecho->chksum += htons(ICMP4_ECHO << 8);
			}
			ICMP_STATS_INC(icmp.xmit);
			ip_output(stack, p, &(inad->ipaddr), &tmpdest, IPH4_TTL(ip4hdr), 0, IP_PROTO_ICMP4);
			break;
		default:
			LWIP_DEBUGF(ICMP_DEBUG, ("icmp_input: ICMP type %d not supported.\n", (int)type));
			ICMP_STATS_INC(icmp.proterr);
			ICMP_STATS_INC(icmp.drop);

	}
	pbuf_free(p);
}

/*
 * Send a Duplicate Address Detection message
 * See seciont 4.3. of RFC 2461. 
 */
void
icmp_send_dad(struct stack *stack, struct ip_addr_list *targetip, struct netif *srcnetif)
{
	struct ip_addr_list src;

	LWIP_DEBUGF(ICMP_DEBUG, ("icmp_send_dad: sending DAD\n"));

	/* Setup source interface and address for this packet.*/
	IP6_ADDR_UNSPECIFIED(&(src.ipaddr));
	src.netif = srcnetif;

	icmp_neighbor_solicitation(stack, &(targetip->ipaddr), &src);
}


/*
 * Send a Neighbor Solicitation message. 
 *  - ipaddr = target ip
 *  - inad   = outgoing netif + ip
 *
 * FIX: See seciont 4.3. of RFC 2461. Must use unicast address 
 *      when the node seeks to verify the reachability of a neighbor (not yet implemented).
 */
void
icmp_neighbor_solicitation(struct stack *stack, struct ip_addr *ipaddr, struct ip_addr_list *inad)
{
	struct pbuf *q;

	struct icmp_ns_hdr   *ins;
	struct icmp_opt_addr *iopt;
	struct ip_addr targetaddr;
	struct netif *inp = inad->netif;

	LWIP_DEBUGF(ICMP_DEBUG, ("icmp_neighbor_solicitation: sending NS\n"));

	/* Setup a Solicited-Node Address multicast address  */
	IP6_ADDR_SOLICITED(&targetaddr, ipaddr);

	/* ICMP header + [SrcAddr option+Ethernet address] */
	q = pbuf_alloc(PBUF_IP, sizeof(struct icmp_ns_hdr) + sizeof(struct icmp_opt_addr) + 6, PBUF_RAM);

	/* Fill icmp header */
	ins = q->payload;
	ins->type  = ICMP6_NS;
	ins->icode = 0;
	ins->reserved = 0;

	/* The IP address of the target of the solicitation.
	It MUST NOT be a multicast address. */
	memcpy(&ins->targetip, ipaddr, sizeof(struct ip_addr));

	LWIP_DEBUGF(ICMP_DEBUG, ("\ttargetip: ")); 
		ip_addr_debug_print(ICMP_DEBUG, (struct ip_addr *) &ins->targetip);
		LWIP_DEBUGF(ICMP_DEBUG, ("\n")); 

	/* Fill option header with interface's link-layer address */
	iopt = q->payload + sizeof(struct icmp_ns_hdr);
	iopt->type = ICMP6_OPT_SRCADDR;
	iopt->len  = ICMP6_OPT_LEN_ETHER;
	memcpy(&iopt->addr, &(inp->hwaddr), inp->hwaddr_len);

	/* Calculate checksum */
	ins->chksum = 0;
	ins->chksum = inet6_chksum_pseudo(q, &(inad->ipaddr), &(targetaddr), IP_PROTO_ICMP, q->tot_len);

	ip_output_if(stack, q, &(inad->ipaddr), &targetaddr, 255, 0, IP_PROTO_ICMP, inp, &(targetaddr), 0);

	pbuf_free(q);
}

/*
 * Send a Neighbor Solicitation message.
 * See seciont 4.3. of RFC 2461. 
 */
void
icmp_router_solicitation(struct stack *stack, struct ip_addr *ipaddr, struct ip_addr_list *inad)
{
	struct pbuf *q;

	struct icmp_rs_hdr  *irs;
	struct icmp_opt_addr *iopt;
	struct ip_addr       targetaddr;
	struct netif *inp = inad->netif;

	LWIP_DEBUGF(ICMP_DEBUG, ("icmp_router_solicitation: sending RS\n"));

	/* Setup a All-router multicast address */
	IP6_ADDR_ALLROUTER(&targetaddr, IP6_LINKLOCAL);

	/* ICMP header + [SrcAddr option+Ethernet address] */
	q = pbuf_alloc(PBUF_IP, sizeof(struct icmp_rs_hdr) + sizeof(struct icmp_opt_addr) + 6, PBUF_RAM);

	/* Fill icmp header */
	irs = q->payload;
	irs->type     = ICMP6_RS;
	irs->icode    = 0;
	irs->reserved = 0;

	/* Fill option header with our link-layer address */
	iopt = q->payload + sizeof(struct icmp_rs_hdr);
	iopt->type = ICMP6_OPT_SRCADDR;
	iopt->len  = ICMP6_OPT_LEN_ETHER;
	memcpy(&iopt->addr, &(inp->hwaddr), inp->hwaddr_len);

	/* Calculate checksum */
	irs->chksum = 0;
	irs->chksum = inet6_chksum_pseudo(q, &(inad->ipaddr), &(targetaddr), IP_PROTO_ICMP, q->tot_len);

	ip_output_if (stack, q, &(inad->ipaddr), &targetaddr, 255, 0, IP_PROTO_ICMP, inp, &(targetaddr), 0);

	pbuf_free(q);
}

void
icmp_dest_unreach(struct stack *stack, struct pbuf *p, enum icmp_dur_type t)
{
	struct pbuf *q;
	struct ip_hdr *iphdr;
	struct icmp_dur_hdr *idur;

	/* ICMP header + IP header + 8 bytes of data */
	q = pbuf_alloc(PBUF_IP, sizeof(struct icmp_dur_hdr) + IP_HLEN + 8, PBUF_RAM);

	iphdr = p->payload;

	idur = q->payload;
	idur->type = (char)ICMP6_DUR;
	idur->icode = (char)t;

	memcpy((char *)q->payload + sizeof(struct icmp_dur_hdr), p->payload, IP_HLEN + 8);

	/* calculate checksum */
	idur->chksum = 0;
	idur->chksum = inet_chksum(idur, q->len);
	ICMP_STATS_INC(icmp.xmit);

	ip_output(stack, q, NULL, (struct ip_addr *)&(iphdr->src), ICMP_TTL, 0, IP_PROTO_ICMP);

	pbuf_free(q);
}

void
icmp_time_exceeded(struct stack *stack, struct pbuf *p, enum icmp_te_type t)
{
	struct pbuf *q;
	struct ip_hdr *iphdr;
	struct icmp_te_hdr *tehdr;
	
	q = pbuf_alloc(PBUF_IP, sizeof(struct icmp_te_hdr) + IP_HLEN + 8, PBUF_RAM);
	
	iphdr = p->payload;
	
	tehdr = q->payload;
	tehdr->type = (char)ICMP6_TE;
	tehdr->icode = (char)t;
	
	/* copy fields from original packet */
	memcpy((char *)q->payload + sizeof(struct icmp_te_hdr), (char *)p->payload, IP_HLEN + 8);
	
	/* calculate checksum */
	tehdr->chksum = 0;
	tehdr->chksum = inet_chksum(tehdr, q->len);
	
	ICMP_STATS_INC(icmp.xmit);
	
	ip_output(stack, q, NULL, (struct ip_addr *)&(iphdr->src), ICMP_TTL, 0, IP_PROTO_ICMP);

	pbuf_free(q);
}

void
icmp_packet_too_big(struct stack *stack, struct pbuf *p, u16_t mtu)
{
	struct pbuf *q;
	struct ip_hdr *iphdr;
	struct icmp_ptb_hdr *ptbhdr;
	
	q = pbuf_alloc(PBUF_IP, 8 + IP_HLEN + 8, PBUF_RAM);
	
	/* Fill ICMP header */
	ptbhdr        = q->payload;
	ptbhdr->type  = (char)ICMP6_PTB;
	ptbhdr->icode = 0;
	ptbhdr->mtu   = htons(mtu);
	
	/* copy fields from original packet */
	iphdr = p->payload;
	memcpy((char *)q->payload + 8, (char *)p->payload, IP_HLEN + 8);
	
	/* calculate ICMP checksum */
	ptbhdr->chksum = 0;
	ptbhdr->chksum = inet_chksum(ptbhdr, q->len);
	
	ICMP_STATS_INC(icmp.xmit);
	
	/* Send */
	ip_output(stack, q, NULL, (struct ip_addr *)&(iphdr->src), ICMP_TTL, 0, IP_PROTO_ICMP);

	pbuf_free(q);
}


/* added by Diego Billi */

void
icmp4_dest_unreach(struct stack *stack, struct pbuf *p, enum icmp_dur_type t, u16_t nextmtu )
{
	struct pbuf *q;
	struct ip4_hdr *iphdr;
	struct icmp_dur_hdr *idur;
	struct ip_addr tmpdest;

	q = pbuf_alloc(PBUF_IP, sizeof(struct icmp_dur_hdr) + IP4_HLEN + 8, PBUF_RAM);
	
	iphdr = p->payload;
	
	idur = q->payload;
	idur->type = (char)ICMP4_DUR;
	idur->icode = (char)t;
	memcpy((char *)q->payload + sizeof(struct icmp_dur_hdr), p->payload, IP4_HLEN + 8);
	
	/* calculate checksum */
	idur->chksum = 0;
	idur->chksum = inet_chksum(idur, q->len);
	
	ICMP_STATS_INC(icmp.xmit);
	
	IP64_CONV(&tmpdest, &iphdr->src);
	ip_output(stack, q, NULL, &tmpdest, ICMP_TTL, 0, IP_PROTO_ICMP4);
	
	pbuf_free(q);
}

void
icmp4_time_exceeded(struct stack *stack, struct pbuf *p, enum icmp_te_type t)
{
	struct pbuf *q;
	struct ip4_hdr *iphdr;
	struct icmp_te_hdr *tehdr;
	struct ip_addr tmpdest;
	
	q = pbuf_alloc(PBUF_IP, sizeof(struct icmp_te_hdr) + IP4_HLEN + 8, PBUF_RAM);
	
	iphdr = p->payload;
	
	tehdr = q->payload;
	tehdr->type = (char)ICMP4_TE;
	tehdr->icode = (char)t;
	/* copy fields from original packet */
	memcpy((char *)q->payload + sizeof(struct icmp_te_hdr), (char *)p->payload, IP4_HLEN + 8);
	
	/* calculate checksum */
	tehdr->chksum = 0;
	tehdr->chksum = inet_chksum(tehdr, q->len);
	
	ICMP_STATS_INC(icmp.xmit);
	
	IP64_CONV(&tmpdest, &iphdr->src);
	
	ip_output(stack, q, NULL, &tmpdest, ICMP_TTL, 0, IP_PROTO_ICMP4);
	
	pbuf_free(q);
}

