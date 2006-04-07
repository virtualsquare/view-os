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


#define NAT_IDLE_ICMP_TIMEOUT       (30  * SECOND)



int track_icmp4_tuple(struct ip_tuple *tuple, void *hdr)
{ 
	struct icmp_echo_hdr *icmphdr = NULL;
	icmphdr = (struct icmp_echo_hdr *) hdr;

	tuple->src.proto.icmp4.id   = icmphdr->id;
	tuple->src.proto.icmp4.type = icmphdr->type;
	tuple->src.proto.icmp4.code = icmphdr->icode;

	return 1;
}

int track_icmp4_inverse(struct ip_tuple *reply, struct ip_tuple *tuple)  
{ 
	static u_int8_t invmap[]
		= { [ICMP4_ECHO] = ICMP4_ER + 1,
		    [ICMP4_ER] = ICMP4_ECHO + 1 };

	if ( (tuple->src.proto.icmp4.type >= sizeof(invmap)) || 
	     !(invmap[tuple->src.proto.icmp4.type])) {
		return -1;
	}

	reply->src.proto.icmp4.id   = tuple->src.proto.icmp4.id;
	reply->src.proto.icmp4.type = invmap[tuple->src.proto.icmp4.type] -  1;
	reply->src.proto.icmp4.code = tuple->src.proto.icmp4.code;

	return 1;
}

int track_icmp6_tuple(struct ip_tuple *tuple, void *hdr)
{ 
	struct icmp_echo_hdr *icmphdr = NULL;
	icmphdr = (struct icmp_echo_hdr *) hdr;

	tuple->src.proto.icmp6.id   = icmphdr->id;
	tuple->src.proto.icmp6.type = icmphdr->type;
	tuple->src.proto.icmp6.code = icmphdr->icode;

	return 1;
}

int track_icmp6_inverse(struct ip_tuple *reply, struct ip_tuple *tuple)  
{ 
	static u_int8_t invmap6[]
		= { [ICMP6_ECHO] = ICMP6_ER   + 1,
		    [ICMP6_ER]   = ICMP6_ECHO + 1 };

	if ( (tuple->src.proto.icmp4.type >= sizeof(invmap6)) || 
	     !(invmap6[tuple->src.proto.icmp4.type])) {
		return -1;
	}

	reply->src.proto.icmp6.id   = tuple->src.proto.icmp6.id;
	reply->src.proto.icmp6.type = invmap6[tuple->src.proto.icmp6.type] -  1;
	reply->src.proto.icmp6.code = tuple->src.proto.icmp6.code;

	return 1;
}


int track_icmp4_new(struct nat_pcb *pcb, struct pbuf *p, void *iphdr, int iplen) 
{ 
	//struct icmp_echo_hdr *icmphdr = NULL;
	//icmphdr = (struct icmp_echo_hdr *) (iphdr+iplen);

	pcb->proto.icmp4.count = 0;
	pcb->timeout           = NAT_IDLE_ICMP_TIMEOUT;

	return 1;
}
int track_icmp6_new(struct nat_pcb *pcb, struct pbuf *p, void *iphdr, int iplen) 
{ 
	//struct icmp_echo_hdr *icmphdr = NULL;
	//icmphdr = (struct icmp_echo_hdr *) (iphdr+iplen);

	pcb->proto.icmp6.count = 0;
	pcb->timeout           = NAT_IDLE_ICMP_TIMEOUT;

	return 1;
}


int track_icmp4_handle(uf_verdict_t *verdict, struct nat_pcb *pcb, struct pbuf *p, conn_dir_t direction)
{ 
	struct icmp_echo_hdr *icmphdr = NULL;

	struct ip_hdr *iphdr;
	struct ip4_hdr *ip4hdr;
	//u16_t iphdrlen;

	ip4hdr = p->payload;
	iphdr  = p->payload;
	if (IPH_V(iphdr) == 6)      icmphdr = p->payload + IP_HLEN;
	else if (IPH_V(iphdr) == 4) icmphdr = p->payload + IPH4_HL(ip4hdr) * 4;

	if (direction == CONN_DIR_ORIGINAL) {
		LWIP_DEBUGF(NAT_DEBUG, ("%s: icmp4 ORIGINAL.\n", __func__));
		pcb->proto.icmp4.count++;
	} else {
		LWIP_DEBUGF(NAT_DEBUG, ("%s: icmp4 REPLY.\n", __func__));
		pcb->proto.icmp4.count--;

		/* Last packet in this direction, remove timer */
		if (pcb->proto.icmp4.count == 0) {
			///sys_untimeout((sys_timeout_handler) close_timeout, pcb);
			if (conn_remove_timer(pcb))
				conn_force_timeout(pcb);

			LWIP_DEBUGF(NAT_DEBUG, ("%s: REPLY RECEIVED.\n", __func__));
		}
	}

	conn_refresh_timer(pcb->timeout, pcb);

	*verdict = UF_ACCEPT;

	return 1;
}

int track_icmp6_handle(uf_verdict_t *verdict, struct nat_pcb *pcb, struct pbuf *p, conn_dir_t direction)
{ 
	struct icmp_echo_hdr *icmphdr = NULL;

	struct ip_hdr *iphdr;
	struct ip4_hdr *ip4hdr;
	//u16_t iphdrlen;

	ip4hdr = p->payload;
	iphdr  = p->payload;
	if (IPH_V(iphdr) == 6)      icmphdr = p->payload + IP_HLEN;
	else if (IPH_V(iphdr) == 4) icmphdr = p->payload + IPH4_HL(ip4hdr) * 4;

	if (direction == CONN_DIR_ORIGINAL) {
		LWIP_DEBUGF(NAT_DEBUG, ("%s: icmp4 ORIGINAL.\n", __func__));
		pcb->proto.icmp6.count++;
	} else {
		LWIP_DEBUGF(NAT_DEBUG, ("%s: icmp4 REPLY.\n", __func__));
		pcb->proto.icmp6.count--;

		/* Last packet in this direction, remove timer */
		if (pcb->proto.icmp6.count == 0) {
			///sys_untimeout((sys_timeout_handler) close_timeout, pcb);
			//conn_remove_timer(pcb);
			//pcb->refcount--;
			if (conn_remove_timer(pcb))
				conn_force_timeout(pcb);
			LWIP_DEBUGF(NAT_DEBUG, ("%s: REPLY RECEIVED.\n", __func__));
		}
	}

	conn_refresh_timer(pcb->timeout, pcb);

	* verdict = UF_ACCEPT;

	return 1;
}


int nat_icmp4_manip (nat_type_t type, void *iphdr, int iplen, struct ip_tuple *inverse, 
		u8_t *iphdr_new_changed_buf, 
		u8_t *iphdr_old_changed_buf, 
		u32_t iphdr_changed_buflen)
{
	struct icmp_echo_hdr *icmphdr = NULL;
	u16_t                 old_value;

	icmphdr = (struct icmp_echo_hdr *) (iphdr+iplen);

	if (ICMPH_CODE(icmphdr) == ICMP4_ECHO || ICMPH_CODE(icmphdr) == ICMP4_ER) {
		// Set icmp id
		old_value = icmphdr->id;
		if (type == NAT_DNAT)      
			icmphdr->id = inverse->src.proto.icmp4.id;
		else if (type == NAT_SNAT) 
			icmphdr->id = inverse->src.proto.icmp4.id;

		nat_chksum_adjust((u8_t *) & ICMPH_CHKSUM(icmphdr), (u8_t *) & old_value, 2, (u8_t *) & icmphdr->id, 2);

		LWIP_DEBUGF(NAT_DEBUG, ("\t\ticmp id: %d\n", ntohs(icmphdr->id))    ); 
	}

	return -1;
}

int nat_icmp6_manip (nat_type_t type, void *iphdr, int iplen, struct ip_tuple *inverse, 
		u8_t *iphdr_new_changed_buf, 
		u8_t *iphdr_old_changed_buf, 
		u32_t iphdr_changed_buflen)
{
	struct icmp_echo_hdr *icmphdr = NULL;
	u16_t                 old_value;

	icmphdr = (struct icmp_echo_hdr *) (iphdr+iplen);
	if ((ICMPH_CODE(icmphdr) == ICMP4_ECHO || ICMPH_CODE(icmphdr) == ICMP4_ER) ||
	    (ICMPH_CODE(icmphdr) == ICMP6_ECHO || ICMPH_CODE(icmphdr) == ICMP6_ER) ){
		// Set icmp id
		old_value = icmphdr->id;
		if (type == NAT_DNAT)      
			icmphdr->id = inverse->src.proto.icmp4.id;
		else if (type == NAT_SNAT) 
			icmphdr->id = inverse->src.proto.icmp4.id;

		nat_chksum_adjust((u8_t *) & ICMPH_CHKSUM(icmphdr), (u8_t *) & old_value, 2, (u8_t *) & icmphdr->id, 2);

		LWIP_DEBUGF(NAT_DEBUG, ("\t\ticmp id: %d\n", ntohs(icmphdr->id))    ); 
	}

	return -1;
}


int nat_icmp4_tuple_inverse (struct ip_tuple *reply, struct ip_tuple *tuple, nat_type_t type, struct manip_range *nat_manip )
{
	/// XXX get new ID
	if (type == NAT_SNAT) {
		reply->src.proto.icmp4.id = tuple->src.proto.icmp4.id;
	} else if (type == NAT_DNAT) {
		reply->src.proto.icmp4.id = tuple->src.proto.icmp4.id;
	}
	return 1;
}

int nat_icmp6_tuple_inverse (struct ip_tuple *reply, struct ip_tuple *tuple, nat_type_t type, struct manip_range *nat_manip )
{
	/// XXX get new ID
	if (type == NAT_SNAT) {
		reply->src.proto.icmp4.id = tuple->src.proto.icmp4.id;
	} else if (type == NAT_DNAT) {
		reply->src.proto.icmp4.id = tuple->src.proto.icmp4.id;
	}

	return 1;
}

int nat_icmp4_free(struct nat_pcb *pcb)
{
	return 1;
}
int nat_icmp6_free(struct nat_pcb *pcb)
{
	return 1;
}


struct track_protocol  icmp4_track = {
	.new     = track_icmp4_new,
	.tuple   = track_icmp4_tuple,
	.inverse = track_icmp4_inverse,
	.handle  = track_icmp4_handle,

	.manip   = nat_icmp4_manip,
	.nat_tuple_inverse = nat_icmp4_tuple_inverse,
	.nat_free = nat_icmp4_free

};

struct track_protocol  icmp6_track = {
	.new     = track_icmp6_new,
	.tuple   = track_icmp6_tuple,
	.inverse = track_icmp6_inverse,
	.handle  = track_icmp6_handle,

	.manip   = nat_icmp6_manip,
	.nat_tuple_inverse = nat_icmp6_tuple_inverse,
	.nat_free = nat_icmp6_free
};

#endif 

