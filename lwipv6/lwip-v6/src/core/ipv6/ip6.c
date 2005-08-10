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



/* ip.c
 *
 * This is the code for the IP layer for IPv6.
 *
 */

#include "lwip/opt.h"

#include "lwip/def.h"
#include "lwip/mem.h"
#include "lwip/ip.h"
#include "lwip/inet.h"
#include "lwip/netif.h"
#include "lwip/icmp.h"
#include "lwip/raw.h"
#include "lwip/udp.h"
#include "lwip/tcp.h"

#include "lwip/stats.h"
#include "lwip/ip_frag.h"

#include "arch/perf.h"

/* ip_init:
 *
 * Initializes the IP layer.
 */

void
ip_init(void)
{
}

/* ip_forward:
 *
 * Forwards an IP packet. It finds an appropriate route for the packet, decrements
 * the TTL value of the packet, adjusts the checksum and outputs the packet on the
 * appropriate interface.
 */

static void
ip_forward(struct pbuf *p, struct ip_hdr *iphdr, struct netif *netif, struct ip_addr *nexthop)
{
  PERF_START;

  /* Decrement TTL and send ICMP if ttl == 0. */
  IPH_HOPLIMIT_SET(iphdr, IPH_HOPLIMIT(iphdr) -1);
  /*if (--iphdr->hoplim == 0) {*/
  if (IPH_HOPLIMIT(iphdr) <= 0) {
    /* Don't send ICMP messages in response to ICMP messages */
    /*if (iphdr->nexthdr != IP_PROTO_ICMP) {*/
    if (IPH_NEXTHDR(iphdr) != IP_PROTO_ICMP) {
      icmp_time_exceeded(p, ICMP_TE_TTL);
    }
    pbuf_free(p);
    return;
  }

  LWIP_DEBUGF(IP_DEBUG, ("ip_forward: forwarding packet to "));
#if IP_DEBUG
  ip_addr_debug_print(IP_DEBUG, &(iphdr->dest));
#endif /* IP_DEBUG */
  LWIP_DEBUGF(IP_DEBUG, (" via %c%c%d\n",netif->name[0],netif->name[1],netif->num));

#ifdef IP_STATS
  ++lwip_stats.ip.fw;
  ++lwip_stats.ip.xmit;
#endif /* IP_STATS */

  PERF_STOP("ip_forward");

  /* netif->output(netif, p, (struct ip_addr *)&(iphdr->dest)); */
  netif->output(netif, p, nexthop);
}

/* ip_input:
 *
 * This function is called by the network interface device driver when an IP packet is
 * received. The function does the basic checks of the IP header such as packet size
 * being at least larger than the header size etc. If the packet was not destined for
 * us, the packet is forwarded (using ip_forward). The IP checksum is always checked.
 *
 * Finally, the packet is sent to the upper layer protocol input function.
 */

void
/*ip_inpacket(struct ip_addr_list *addr, struct pbuf *p, int nexthdr) {*/
ip_inpacket(struct ip_addr_list *addr, struct pbuf *p, struct pseudo_iphdr *piphdr) {
  /* send to upper layers */
#if IP_DEBUG
  LWIP_DEBUGF(IP_DEBUG,("ip_input: \n"));
  ip_debug_print(IP_DEBUG, p);
  LWIP_DEBUGF(IP_DEBUG,("ip_input: p->len %u p->tot_len %u\n", p->len, p->tot_len));
#endif /* IP_DEBUG */

#if LWIP_RAW
  raw_input(p, addr, piphdr);
#endif /* LWIP_RAW */

  switch (piphdr->proto + (piphdr->version << 8)) {
  case IP_PROTO_UDP + (4 << 8):
  case IP_PROTO_UDP + (6 << 8):
		LWIP_DEBUGF(IP_DEBUG,("->UDP\n"));
    udp_input(p, addr, piphdr);
    break;
  case IP_PROTO_TCP + (4 << 8):
  case IP_PROTO_TCP + (6 << 8):
		LWIP_DEBUGF(IP_DEBUG,("->TCP\n"));
    tcp_input(p, addr, piphdr);
    break;
  case IP_PROTO_ICMP + (6 << 8):
  case IP_PROTO_ICMP4 + (4 << 8):
		LWIP_DEBUGF(IP_DEBUG,("->ICMP\n"));
    icmp_input(p, addr, piphdr);
    break;
  default:
    /* send ICMP destination protocol unreachable */
    icmp_dest_unreach(p, ICMP_DUR_PROTO);
    pbuf_free(p);
    LWIP_DEBUGF(IP_DEBUG, ("Unsupported transport protocol %u\n",
          piphdr->proto));
#ifdef IP_STATS
    ++lwip_stats.ip.proterr;
    ++lwip_stats.ip.drop;
#endif /* IP_STATS */

  }
}

void
ip_input(struct pbuf *p, struct netif *inp) {
  struct ip_hdr *iphdr;
  struct ip4_hdr *ip4hdr;
  struct netif *netif;
  struct ip_addr_list *addrel;
#ifdef IP_FORWARD
  struct ip_addr *nexthop;
  int fwflags;
#endif
  struct pseudo_iphdr piphdr;
  struct ip_addr src4,dest4;

  PERF_START;

#if IP_DEBUG
  ip_debug_print(IP_DEBUG, p);
#endif /* IP_DEBUG */

#ifdef IP_STATS
  ++lwip_stats.ip.recv;
#endif /* IP_STATS */

  /* identify the IP header */
  iphdr = p->payload;

  piphdr.version=IPH_V(iphdr);
  if (piphdr.version == 6) {
	  piphdr.proto=IPH_NEXTHDR(iphdr);
	  piphdr.iphdrlen=IP_HLEN;
	  piphdr.src=&(iphdr->src);
	  piphdr.dest=&(iphdr->dest);
  }
  else if (piphdr.version == 4) {
	  ip4hdr = p->payload;
	  piphdr.proto=IPH4_PROTO(ip4hdr);
	  piphdr.iphdrlen=IPH4_HL(ip4hdr) * 4;
	  IP64_CONV(&src4,&(ip4hdr->src));
	  IP64_CONV(&dest4,&(ip4hdr->dest));
	  piphdr.src=&src4;
	  piphdr.dest=&dest4;
	  /*printf("v4 p=%d src=%x dst=%x\n",piphdr.proto,src4.addr[3],dest4.addr[3]);*/
  }
  else {
    LWIP_DEBUGF(IP_DEBUG, ("IP packet dropped due to bad version number\n"));
#if IP_DEBUG
    ip_debug_print(IP_DEBUG, p);
#endif /* IP_DEBUG */
    pbuf_free(p);
#ifdef IP_STATS
    ++lwip_stats.ip.err;
    ++lwip_stats.ip.drop;
#endif /* IP_STATS */
    return;
  }

  /*printf("received packet v%d hlen=%d\n",piphdr.version,piphdr.iphdrlen);*/

  /*if ((addrel = ip_addr_list_deliveryfind(inp->addrs, &(iphdr->dest), &(iphdr->src))) != NULL)*/
  if ((addrel = ip_addr_list_deliveryfind(inp->addrs, piphdr.dest, piphdr.src)) != NULL)
  { /*local address*/
	if (piphdr.version == 6)
		pbuf_realloc(p, IP_HLEN + ntohs(iphdr->len)); 
	else
		pbuf_realloc(p, ntohs(IPH4_LEN(ip4hdr)));
	/*ip_inpacket(addrel, p, iphdr->nexthdr);*/
	ip_inpacket(addrel, p, &piphdr);
  }
#ifdef IP_FORWARD
  /*else if (ip_route_findpath(&(iphdr->dest), &nexthop, &netif, &fwflags) == ERR_OK &&*/
  else if (ip_route_findpath(piphdr.dest, &nexthop, &netif, &fwflags) == ERR_OK &&
		  netif != inp)
  { /* forwarding */
	  ip_forward(p, iphdr, netif, nexthop);
	  pbuf_free(p);
  }
#endif
  else
  { /*discard*/  
	  pbuf_free(p);
  }

  PERF_STOP("ip_input");
}




/* ip_output_if:
 *
 * Sends an IP packet on a network interface. This function constructs the IP header
 * and calculates the IP header checksum. If the source IP address is NULL,
 * the IP address of the outgoing network interface is filled in as source address.
 */

err_t
ip_output_if (struct pbuf *p, struct ip_addr *src, struct ip_addr *dest,
       u8_t ttl, u8_t tos,
       u8_t proto, struct netif *netif, struct ip_addr *nexthop, int flags)
{
  struct ip_hdr *iphdr;
  struct ip4_hdr *ip4hdr;
  u8_t version;
  static u16_t ip_id = 0;
 
  if (src == NULL) {
	  return ERR_BUF;
  }
  PERF_START;
  version=ip_addr_is_v4comp(src)?4:6;
  /*printf("ip_output_if %x:%x:%x:%x v%d\n",
		  src->addr[0],
		  src->addr[1],
		  src->addr[2],
		  src->addr[3],
		  version); */

  if (pbuf_header(p, version==6?IP_HLEN:IP4_HLEN)) {
    LWIP_DEBUGF(IP_DEBUG, ("ip_output: not enough room for IP header in pbuf\n"));
#ifdef IP_STATS
    ++lwip_stats.ip.err;
#endif /* IP_STATS */

    return ERR_BUF;
  }

  if(version == 6) {
	  iphdr = p->payload;

	  if (dest != IP_HDRINCL) {
		  /*iphdr->hoplim = ttl;
		    iphdr->nexthdr = proto;*/
		  iphdr->_v_cl_fl=0;
		  IPH_NEXT_HOP_SET(iphdr, proto, ttl);

		  iphdr->len = htons(p->tot_len - IP_HLEN);

		  /*iphdr->v = 6;*/
		  IPH_V_SET(iphdr, 6);
		  ip_addr_set(&(iphdr->dest), dest);

		  /* if (ip_addr_isany(src)) {
		     ip_addr_set(&(iphdr->src), &(netif->ip_addr));
		     } else {
		     ip_addr_set(&(iphdr->src), src);
		     } */
		  ip_addr_set(&(iphdr->src), src);
	  } else {
		  dest = &(iphdr->dest);
	  }
  } else /* IPv4 */
  {
	  ip4hdr = p->payload;
	  if (dest != IP_HDRINCL) {
		  IPH4_TTL_SET(ip4hdr, ttl);
		  IPH4_PROTO_SET(ip4hdr, proto);
		  ip64_addr_set(&(ip4hdr->dest), dest);
		  IPH4_VHLTOS_SET(ip4hdr, 4, IP4_HLEN / 4, tos);
		  IPH4_LEN_SET(ip4hdr, htons(p->tot_len));
		  IPH4_OFFSET_SET(ip4hdr, htons(IP_DF));
		  IPH4_ID_SET(ip4hdr, htons(ip_id));
		  ++ip_id;
		  ip64_addr_set(&(ip4hdr->src), src);
		  IPH4_CHKSUM_SET(ip4hdr, 0);
		  IPH4_CHKSUM_SET(ip4hdr, inet_chksum(ip4hdr, IP4_HLEN));
	  } else {
		  /*dest = &(ip4hdr->dest)*/;
	  }
  }

#ifdef IP_STATS
  ++lwip_stats.ip.xmit;
#endif /* IP_STATS */

  LWIP_DEBUGF(IP_DEBUG, ("ip_output_if: %c%c (len %u)\n", netif->name[0], netif->name[1], p->tot_len));
#if IP_DEBUG
  ip_debug_print(IP_DEBUG, p);
#endif /* IP_DEBUG */

  PERF_STOP("ip_output_if");

#if 0 
  /* FRAGMENTATION ! */
  printf("ip_output_if %d %d\n",p->tot_len,netif->mtu);
  if (netif->mtu && (p->tot_len > netif->mtu))
	  return ip_frag(p,netif,dest);
#endif

	if (ip_addr_cmp(src,dest)) {
		struct pbuf *q, *r;
		u8_t *ptr;
		//printf("IT IS 4 ME!\n");
		if (! (netif->flags & NETIF_FLAG_UP)) {
			return ERR_OK;
		}
		r = pbuf_alloc(PBUF_RAW, p->tot_len, PBUF_RAM);
		if (r != NULL) {
			ptr = r->payload;

			for(q = p; q != NULL; q = q->next) {
				memcpy(ptr, q->payload, q->len);
				ptr += q->len;
			}
			netif->input( r, netif );
		}
		return ERR_OK;
	} else
  //printf("outputoutput dest\n");
  return netif->output(netif, p, nexthop);
}

/* ip_output:
 *
 * Simple interface to ip_output_if. It finds the outgoing network interface and
 * calls upon ip_output_if to do the actual work.
 */

err_t
ip_output(struct pbuf *p, struct ip_addr *src, struct ip_addr *dest,
    u8_t ttl, u8_t tos, u8_t proto)
{
  struct netif *netif;
  struct ip_addr *nexthop;
  int flags;
	//printf("IP OUTPUT\n");
  if (ip_route_findpath(dest,&nexthop,&netif,&flags)!=ERR_OK) {
    LWIP_DEBUGF(IP_DEBUG, ("ip_output: No route to XXX \n" ));
#ifdef IP_STATS
    ++lwip_stats.ip.rterr;
#endif /* IP_STATS */
    return ERR_RTE;
  }
  else {
	  return ip_output_if (p, src, dest, ttl, tos, proto, netif, nexthop, flags);
  }
}

#if IP_DEBUG
static	void
ip4_debug_print(struct pbuf *p)
{
	struct ip4_hdr *iphdr = p->payload;
	u8_t *payload;

	payload = (u8_t *)iphdr + IP4_HLEN;

	LWIP_DEBUGF(IP_DEBUG, ("IP header:\n"));
	LWIP_DEBUGF(IP_DEBUG, ("+-------------------------------+\n"));
	LWIP_DEBUGF(IP_DEBUG, ("|%2d |%2d |  0x%02x |     %5u     | (v, hl, tos, len)\n",
				IPH4_V(iphdr),
				IPH4_HL(iphdr),
				IPH4_TOS(iphdr),
				ntohs(IPH4_LEN(iphdr))));
	LWIP_DEBUGF(IP_DEBUG, ("+-------------------------------+\n"));
	LWIP_DEBUGF(IP_DEBUG, ("|    %5u      |%u%u%u|    %4u   | (id, flags, offset)\n",
				ntohs(IPH4_ID(iphdr)),
				ntohs(IPH4_OFFSET(iphdr)) >> 15 & 1,
				ntohs(IPH4_OFFSET(iphdr)) >> 14 & 1,
				ntohs(IPH4_OFFSET(iphdr)) >> 13 & 1,
				ntohs(IPH4_OFFSET(iphdr)) & IP_OFFMASK));
	LWIP_DEBUGF(IP_DEBUG, ("+-------------------------------+\n"));
	LWIP_DEBUGF(IP_DEBUG, ("|  %3u  |  %3u  |    0x%04x     | (ttl, proto, chksum)\n",
				IPH4_TTL(iphdr),
				IPH4_PROTO(iphdr),
				ntohs(IPH4_CHKSUM(iphdr))));
	LWIP_DEBUGF(IP_DEBUG, ("+-------------------------------+\n"));
	LWIP_DEBUGF(IP_DEBUG, ("|  %3ld  |  %3ld  |  %3ld  |  %3ld  | (src)\n",
				ntohl(iphdr->src.addr) >> 24 & 0xff,
				ntohl(iphdr->src.addr) >> 16 & 0xff,
				ntohl(iphdr->src.addr) >> 8 & 0xff,
				ntohl(iphdr->src.addr) & 0xff));
	LWIP_DEBUGF(IP_DEBUG, ("+-------------------------------+\n"));
	LWIP_DEBUGF(IP_DEBUG, ("|  %3ld  |  %3ld  |  %3ld  |  %3ld  | (dest)\n",
				ntohl(iphdr->dest.addr) >> 24 & 0xff,
				ntohl(iphdr->dest.addr) >> 16 & 0xff,
				ntohl(iphdr->dest.addr) >> 8 & 0xff,
				ntohl(iphdr->dest.addr) & 0xff));
	LWIP_DEBUGF(IP_DEBUG, ("+-------------------------------+\n"));
}

static	void
ip6_debug_print(int how, struct pbuf *p)
{
	struct ip_hdr *iphdr = p->payload;
	char *payload;

	payload = (char *)iphdr + IP_HLEN;

	LWIP_DEBUGF(IP_DEBUG, ("IP header:\n"));
	LWIP_DEBUGF(IP_DEBUG, ("+-------------------------------+\n"));
	LWIP_DEBUGF(IP_DEBUG, ("|%2d |  %x  |      %x           | (v, traffic class, flow label)\n",
				IPH_V(iphdr),
				IPH_CL(iphdr),
				IPH_FLOW(iphdr)));
	LWIP_DEBUGF(IP_DEBUG, ("+-------------------------------+\n"));
	LWIP_DEBUGF(IP_DEBUG, ("|    %5u      | %2u  |  %2u   | (len, nexthdr, hoplim)\n",
				ntohs(iphdr->len),
				IPH_NEXTHDR(iphdr),
				IPH_HOPLIMIT(iphdr)));
	LWIP_DEBUGF(IP_DEBUG, ("+-------------------------------+\n"));
	LWIP_DEBUGF(IP_DEBUG, ("|       %4lx      |       %4lx     | (src)\n",
				ntohl(iphdr->src.addr[0]) >> 16 & 0xffff,
				ntohl(iphdr->src.addr[0]) & 0xffff));
	LWIP_DEBUGF(IP_DEBUG, ("|       %4lx      |       %4lx     | (src)\n",
				ntohl(iphdr->src.addr[1]) >> 16 & 0xffff,
				ntohl(iphdr->src.addr[1]) & 0xffff));
	LWIP_DEBUGF(IP_DEBUG, ("|       %4lx      |       %4lx     | (src)\n",
				ntohl(iphdr->src.addr[2]) >> 16 & 0xffff,
				ntohl(iphdr->src.addr[2]) & 0xffff));
	LWIP_DEBUGF(IP_DEBUG, ("|       %4lx      |       %4lx     | (src)\n",
				ntohl(iphdr->src.addr[3]) >> 16 & 0xffff,
				ntohl(iphdr->src.addr[3]) & 0xffff));
	LWIP_DEBUGF(IP_DEBUG, ("+-------------------------------+\n"));
	LWIP_DEBUGF(IP_DEBUG, ("|       %4lx      |       %4lx     | (dest)\n",
				ntohl(iphdr->dest.addr[0]) >> 16 & 0xffff,
				ntohl(iphdr->dest.addr[0]) & 0xffff));
	LWIP_DEBUGF(IP_DEBUG, ("|       %4lx      |       %4lx     | (dest)\n",
				ntohl(iphdr->dest.addr[1]) >> 16 & 0xffff,
				ntohl(iphdr->dest.addr[1]) & 0xffff));
	LWIP_DEBUGF(IP_DEBUG, ("|       %4lx      |       %4lx     | (dest)\n",
				ntohl(iphdr->dest.addr[2]) >> 16 & 0xffff,
				ntohl(iphdr->dest.addr[2]) & 0xffff));
	LWIP_DEBUGF(IP_DEBUG, ("|       %4lx      |       %4lx     | (dest)\n",
				ntohl(iphdr->dest.addr[3]) >> 16 & 0xffff,
				ntohl(iphdr->dest.addr[3]) & 0xffff));
	LWIP_DEBUGF(IP_DEBUG, ("+-------------------------------+\n"));
	LWIP_DEBUGF(IP_DEBUG, ("%x %x %x %x %x %x %x %x\n",
				*(payload+0), *(payload+1), *(payload+2), *(payload+3),
				*(payload+4), *(payload+5), *(payload+6), *(payload+7)));
}

void
ip_debug_print(int how, struct pbuf *p)
{
	struct ip_hdr *iphdr = p->payload;

	if (IPH_V(iphdr) == 4)
		ip4_debug_print(p);
	else
		ip6_debug_print(how,p);

}

#endif /* IP_DEBUG */
