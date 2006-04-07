/*   This is part of LWIPv6
 *   Developed for the Ale4NET project
 *   Application Level Environment for Networking
 *   
 *   Copyright 2004 Diego Billi - Italy
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

#ifdef LWIP_NAT

#include "lwip/debug.h"

#include "lwip/memp.h" /* MEMP_NAT_RULE */

#include "lwip/inet.h"
#include "lwip/ip.h"
#include "lwip/udp.h"
#include "lwip/tcp.h"
#include "lwip/icmp.h"
#include "lwip/tcpip.h"
#include "netif/etharp.h"

#include "netif/vdeif.h"
#include "netif/tunif.h"
#include "netif/tapif.h"

#include "lwip/sockets.h"
#include "lwip/if.h"
#include "lwip/sys.h"



#ifndef NAT_DEBUG
#define NAT_DEBUG   DBG_OFF
#endif

#include "lwip/nat/nat.h"
#include "lwip/nat/nat_tables.h"


#define NAT_IDLE_UDP_TIMEOUT        (30  * SECOND)
#define NAT_IDLE_UDP_STREAM_TIMEOUT (180 * SECOND)


int track_udp_tuple(struct ip_tuple *tuple, void *hdr)
{ 
	struct udp_hdr       *udphdr  = NULL;
	udphdr = (struct udp_hdr *) hdr;
	tuple->src.proto.udp.port = udphdr->src;
	tuple->dst.proto.udp.port = udphdr->dest;
	return 1;
}
int track_udp_inverse(struct ip_tuple *reply, struct ip_tuple *tuple)  
{ 
	reply->src.proto.udp.port = tuple->dst.proto.udp.port;
	reply->dst.proto.udp.port = tuple->src.proto.udp.port;
	return 1;
}


int track_udp_new(struct nat_pcb *pcb, struct pbuf *p, void *iphdr, int iplen) 
{ 
	pcb->proto.udp.isstream = 0;
	pcb->timeout  = NAT_IDLE_UDP_TIMEOUT;

	return 1;
}


int track_udp_handle(uf_verdict_t *verdict, struct nat_pcb *pcb, struct pbuf *p, conn_dir_t direction)
{ 
	struct udp_hdr       *udphdr  = NULL;
	struct ip_hdr *iphdr;
	struct ip4_hdr *ip4hdr;
	//u16_t iphdrlen;

	ip4hdr = p->payload;
	iphdr  = p->payload;
	if (IPH_V(iphdr) == 6)      udphdr = p->payload + IP_HLEN;
	else if (IPH_V(iphdr) == 4) udphdr = p->payload + IPH4_HL(ip4hdr) * 4;


	if (direction == CONN_DIR_REPLY) {
		LWIP_DEBUGF(NAT_DEBUG, ("%s: Maybe this is a UDP stream.\n", __func__));
		pcb->proto.udp.isstream = 1;
		pcb->timeout = NAT_IDLE_UDP_STREAM_TIMEOUT;
	}

	conn_refresh_timer(pcb->timeout, pcb);

	*verdict = UF_ACCEPT;

	return 1;
}


int nat_udp_manip (nat_type_t type, void *iphdr, int iplen, struct ip_tuple *inverse, 
		u8_t *iphdr_new_changed_buf, 
		u8_t *iphdr_old_changed_buf, 
		u32_t iphdr_changed_buflen)
{
	struct udp_hdr       *udphdr  = NULL;
	u16_t                 old_value;

	udphdr = (struct udp_hdr *) (iphdr+iplen);
	if (udphdr->chksum != 0) {

		// adjust udp checksum
		if (inverse->ipv == 4)
			nat_chksum_adjust((u8_t *) & udphdr->chksum, 
				(u8_t *) iphdr_old_changed_buf, iphdr_changed_buflen, 
				(u8_t *) iphdr_new_changed_buf, iphdr_changed_buflen);

		// Set port
		if (type == NAT_DNAT) {
			old_value    = udphdr->dest;
			udphdr->dest = inverse->src.proto.udp.port;

			nat_chksum_adjust((u8_t *) & udphdr->chksum, (u8_t *) & old_value, 2, (u8_t *) & udphdr->dest, 2);
		}
		else if (type == NAT_SNAT) {
			old_value    = udphdr->src;
			udphdr->src  = inverse->dst.proto.udp.port;

			nat_chksum_adjust((u8_t *) & udphdr->chksum, (u8_t *) & old_value, 2, (u8_t *) & udphdr->src, 2);
		}
		LWIP_DEBUGF(NAT_DEBUG, ("\t\tdest port: %d\n", ntohs(udphdr->dest))    ); 
	}


	return -1;
}

int nat_udp_tuple_inverse (struct ip_tuple *reply, struct ip_tuple *tuple, nat_type_t type, struct manip_range *nat_manip )
{
	if (type == NAT_SNAT) {
		reply->dst.proto.udp.port = htons(nat_ports_getnew()); 
	} else if (type == NAT_DNAT) {
		/* Change destination port only if specified */	
		if (nat_manip->flag & MANIP_RANGE_PROTO) {
			reply->src.proto.udp.port = nat_manip->protomin.value;
		}
	}
	return 1;
}

int nat_udp_free(struct nat_pcb *pcb)
{
	if (pcb->nat_type == NAT_SNAT) {
		nat_ports_free(ntohs(pcb->tuple[CONN_DIR_REPLY].dst.proto.udp.port));	
	} 
	return 1;
}

struct track_protocol  udp_track = {
	.new     = track_udp_new,
	.tuple   = track_udp_tuple,
	.inverse = track_udp_inverse,
	.handle  = track_udp_handle,

	.manip   = nat_udp_manip,
	.nat_tuple_inverse = nat_udp_tuple_inverse,
	.nat_free = nat_udp_free
};

#endif

