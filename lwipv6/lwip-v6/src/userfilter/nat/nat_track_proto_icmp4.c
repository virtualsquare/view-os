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
#include "lwip/sys.h"
#include "lwip/memp.h" /* MEMP_NAT_RULE */

#include "lwip/inet.h"
#include "lwip/ip.h"
#include "lwip/icmp.h"

#include "lwip/nat/nat.h"
#include "lwip/nat/nat_tables.h"


#ifndef NAT_DEBUG
#define NAT_DEBUG   DBG_OFF
#endif


#define SECOND   1000  
#define NAT_IDLE_ICMP_TIMEOUT       (30  * SECOND)

/*--------------------------------------------------------------------------*/

int track_icmp4_tuple(struct ip_tuple *tuple, void *hdr)
{ 
	struct icmp_echo_hdr *icmphdr = NULL;
	icmphdr = (struct icmp_echo_hdr *) hdr;

	tuple->src.proto.upi.icmp4.id   = icmphdr->id;
	tuple->src.proto.upi.icmp4.type = icmphdr->type;
	tuple->src.proto.upi.icmp4.code = icmphdr->icode;

	return 1;
}

int track_icmp4_inverse(struct ip_tuple *reply, struct ip_tuple *tuple)  
{ 
	static u_int8_t invmap[]
		= { [ICMP4_ECHO] = ICMP4_ER + 1,
		    [ICMP4_ER] = ICMP4_ECHO + 1 };

	if ( (tuple->src.proto.upi.icmp4.type >= sizeof(invmap)) || 
	     !(invmap[tuple->src.proto.upi.icmp4.type])) {
		return -1;
	}

	reply->src.proto.upi.icmp4.id   = tuple->src.proto.upi.icmp4.id;
	reply->src.proto.upi.icmp4.type = invmap[tuple->src.proto.upi.icmp4.type] -  1;
	reply->src.proto.upi.icmp4.code = tuple->src.proto.upi.icmp4.code;

	return 1;
}

int track_icmp6_tuple(struct ip_tuple *tuple, void *hdr)
{ 
	struct icmp_echo_hdr *icmphdr = NULL;
	icmphdr = (struct icmp_echo_hdr *) hdr;

	tuple->src.proto.upi.icmp6.id   = icmphdr->id;
	tuple->src.proto.upi.icmp6.type = icmphdr->type;
	tuple->src.proto.upi.icmp6.code = icmphdr->icode;

	return 1;
}

int track_icmp6_inverse(struct ip_tuple *reply, struct ip_tuple *tuple)  
{ 
	static u_int8_t invmap6[]
		= { [ICMP6_ECHO] = ICMP6_ER   + 1,
		    [ICMP6_ER]   = ICMP6_ECHO + 1 };

	if ( (tuple->src.proto.upi.icmp6.type >= sizeof(invmap6)) || 
	     !(invmap6[tuple->src.proto.upi.icmp6.type])) {
		return -1;
	}

	reply->src.proto.upi.icmp6.id   = tuple->src.proto.upi.icmp6.id;
	reply->src.proto.upi.icmp6.type = invmap6[tuple->src.proto.upi.icmp6.type] -  1;
	reply->src.proto.upi.icmp6.code = tuple->src.proto.upi.icmp6.code;

	return 1;
}

/*--------------------------------------------------------------------------*/
#if 0
int error_message(uf_verdict_t *verdict, struct pbuf *p)
{
	struct ip4_hdr       *ip4hdr;
	struct icmp_echo_hdr *icmphdr;
	struct ip4_hdr       *inside_ip4hdr;
	char                 *inside_hdr;

	struct track_protocol *innerproto;
	struct ip_tuple        original;  
	struct ip_tuple        inverse;  

	struct nat_pcb * pcb;
	conn_dir_t *  direction;

	/* Get IP and ICMP header */
	ip4hdr  = (struct ip4_hdr *) p->payload;
	icmphdr = p->payload + IPH4_HL(ip4hdr) * 4;

	/* Get the original IPv4 packet and pointer to the inner protocol hdr */
	inside_ip4hdr = (struct ip4_hdr *) icphdr + 1;
	inside_hdr =  ((char *)inside_ip4hdr) + IPH4_LEN(inside_ip4hdr) * 4;

	innerproto = track_proto_find( IPH4_PROTO(inside_ip4hdr ) );

	/* Get the tuple of the packet */
	if (tuple_create(&original, inside_ip4hdr, innerproto) < 0) {
		LWIP_DEBUGF(NAT_DEBUG, ("%s: unable to create tuple!\n", __func__ ));
		* verdict = UF_ACCEPT;
		return -1;
	}

	if (tuple_inverse(&inverse, &original) < 0) {

	}

	pcb = conn_find_track( & direction, &inverse );
	if (pcb == NULL) {

	}
	else {

	}

	p->nat.track = pcb;
	p->nat.dir = direction;


	* verdict = UF_ACCEPT;
	return 1;
}
#endif

int track_icmp4_error (uf_verdict_t *verdict, struct pbuf *p)
{
	struct ip4_hdr *ip4hdr;
	struct icmp_echo_hdr *icmphdr = NULL;

	ip4hdr = (struct ip4_hdr *) p->payload;
	if (IPH4_V(ip4hdr) == 4) 
		icmphdr = p->payload + IPH4_HL(ip4hdr) * 4;
	else {
        	*verdict = UF_DROP;
		return -1;
	}

	/* FIX: checksum? */

	/* Drop unsupported types */
	if (icmphdr->type > ICMP4_IR) {
		LWIP_DEBUGF(NAT_DEBUG, ("%s: wrong ICMPv4 type %d.\n", __func__, icmphdr->type));
        	*verdict = UF_DROP;
		return -1;
	}

	// Check only error messages
	if (icmphdr->type != ICMP4_DUR  &&    /* destination unreachable */
	    icmphdr->type != ICMP4_SQ   &&    /* source quench */
	    icmphdr->type != ICMP4_TE   &&    /* time exceeded */
	    icmphdr->type != ICMP4_PP   &&    /* parameter problem */
	    icmphdr->type != ICMP4_RD) {       /* redirect */
		return 1;
	}

	LWIP_DEBUGF(NAT_DEBUG, ("%s: ICMPv4 error message %d.\n", __func__, icmphdr->type));

	/* FIX: HANDLE error messages here  */

       	*verdict = UF_DROP;
	return -1;
}

int track_icmp6_error (uf_verdict_t *verdict, struct pbuf *p)
{
	struct ip_hdr *iphdr;
	struct icmp_echo_hdr *icmph = NULL;

	iphdr  = (struct ip_hdr *) p->payload;
	if (IPH_V(iphdr) == 6)      
		icmph = p->payload + IP_HLEN;
	else {
        	*verdict = UF_DROP;
		return -1;
	}

	/* FIX: checksum? */

	/* Don't track Neighbour Solicitation and Router Solicitation protocols */

	if (icmph->type == ICMP6_RS ||    /* router solicitation */
	    icmph->type == ICMP6_RA ||    /* router advertisement */
	    icmph->type == ICMP6_NS ||    /* neighbor solicitation */
	    icmph->type == ICMP6_NA) {   /* neighbor advertisement */

		LWIP_DEBUGF(NAT_DEBUG, ("%s: not track NS or RA.\n", __func__));
		*verdict = UF_ACCEPT;
		return -1;
	}

	// Check only error messages
	if (icmph->type != ICMP6_DUR  &&    /* destination unreachable */
	    icmph->type != ICMP6_PTB   &&   /* Packet Too Big */
	    icmph->type != ICMP6_TE   &&    /* time exceeded */
	    icmph->type != ICMP4_PP   &&    /* parameter problem */
	    icmph->type != ICMP4_RD) {      /* redirect */
		return 1;
	}

	/* FIX: HANDLE error messages here  */

	LWIP_DEBUGF(NAT_DEBUG, ("%s: ICMPv6 error message %d.\n", __func__, icmph->type));

       	*verdict = UF_DROP;
	return -1;
}

/*--------------------------------------------------------------------------*/

int track_icmp4_new(struct nat_pcb *pcb, struct pbuf *p, void *iphdr, int iplen) 
{ 
	pcb->proto.icmp4.count = 0;
	pcb->timeout           = NAT_IDLE_ICMP_TIMEOUT;

	return 1;
}
int track_icmp6_new(struct nat_pcb *pcb, struct pbuf *p, void *iphdr, int iplen) 
{ 
	pcb->proto.icmp6.count = 0;
	pcb->timeout           = NAT_IDLE_ICMP_TIMEOUT;

	return 1;
}

int track_icmp4_handle(uf_verdict_t *verdict, struct pbuf *p, conn_dir_t direction)
{ 
	struct icmp_echo_hdr *icmphdr = NULL;

	struct ip_hdr *iphdr;
	struct ip4_hdr *ip4hdr;
	//u16_t iphdrlen;

	struct nat_pcb *pcb = p->nat.track;


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
			if (conn_remove_timer(pcb))
				conn_force_timeout(pcb);

			LWIP_DEBUGF(NAT_DEBUG, ("%s: REPLY RECEIVED.\n", __func__));
		}
	}

	conn_refresh_timer(pcb->timeout, pcb);

	*verdict = UF_ACCEPT;

	return 1;
}

int track_icmp6_handle(uf_verdict_t *verdict, struct pbuf *p, conn_dir_t direction)
{ 
	struct icmp_echo_hdr *icmphdr = NULL;

	struct ip_hdr *iphdr;
	struct ip4_hdr *ip4hdr;
	//u16_t iphdrlen;

	struct nat_pcb *pcb = p->nat.track;

	//ip4hdr = p->payload;
	iphdr  = p->payload;
	if (IPH_V(iphdr) == 6)      icmphdr = p->payload + IP_HLEN;
	else if (IPH_V(iphdr) == 4) icmphdr = p->payload + IPH4_HL(ip4hdr) * 4;

	if (direction == CONN_DIR_ORIGINAL) {
		LWIP_DEBUGF(NAT_DEBUG, ("%s: icmp6 ORIGINAL.\n", __func__));
		pcb->proto.icmp6.count++;
	} else {
		LWIP_DEBUGF(NAT_DEBUG, ("%s: icmp6 REPLY.\n", __func__));
		pcb->proto.icmp6.count--;

		/* Last packet in this direction, remove timer */
		if (pcb->proto.icmp6.count == 0) {

			if (conn_remove_timer(pcb))
				conn_force_timeout(pcb);

			LWIP_DEBUGF(NAT_DEBUG, ("%s: REPLY RECEIVED.\n", __func__));
		}
	}

	conn_refresh_timer(pcb->timeout, pcb);

	* verdict = UF_ACCEPT;

	return 1;
}

/*--------------------------------------------------------------------------*/

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
			icmphdr->id = inverse->src.proto.upi.icmp4.id;
		else if (type == NAT_SNAT) 
			icmphdr->id = inverse->src.proto.upi.icmp4.id;

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

	if ((ICMPH_CODE(icmphdr) == ICMP6_ECHO || ICMPH_CODE(icmphdr) == ICMP6_ER)) {

		// Adjust checksum because IP header (and pseudo header) is changed
		nat_chksum_adjust((u8_t *) & ICMPH_CHKSUM(icmphdr), 
				iphdr_old_changed_buf, iphdr_changed_buflen, 
				iphdr_new_changed_buf, iphdr_changed_buflen);

		// Set icmp id
		old_value = icmphdr->id;
		if (type == NAT_DNAT)      
			icmphdr->id = inverse->src.proto.upi.icmp6.id;
		else if (type == NAT_SNAT) 
			icmphdr->id = inverse->src.proto.upi.icmp6.id;

		nat_chksum_adjust((u8_t *) & ICMPH_CHKSUM(icmphdr), (u8_t *) & old_value, 2, (u8_t *) & icmphdr->id, 2);

		LWIP_DEBUGF(NAT_DEBUG, ("\t\ticmp id: %d\n", ntohs(icmphdr->id))    ); 
	}

	return -1;
}


int nat_icmp4_tuple_inverse (struct ip_tuple *reply, struct ip_tuple *tuple, nat_type_t type, struct manip_range *nat_manip )
{
	u32_t id;
	u32_t min, max;

	if (type == NAT_SNAT) {

		if (nat_manip->flag & MANIP_RANGE_PROTO) {
			min = nat_manip->protomin.value;
			max = nat_manip->protomax.value;
		}
		else {
			min = 0;
			max = 0xFFFF;
		}

		if (nat_ports_getnew(IP_PROTO_ICMP4, &id, min, max) > 0) {
			reply->dst.proto.upi.icmp4.id = htons(id); 
		}
		else 
			return -1;
	} 
	else if (type == NAT_DNAT) {
		reply->src.proto.upi.icmp4.id = tuple->src.proto.upi.icmp4.id;
	}

	return -1;
}

int nat_icmp6_tuple_inverse (struct ip_tuple *reply, struct ip_tuple *tuple, nat_type_t type, struct manip_range *nat_manip )
{
	u32_t id;
	u32_t min, max;

	if (type == NAT_SNAT) {

		if (nat_manip->flag & MANIP_RANGE_PROTO) {
			min = nat_manip->protomin.value;
			max = nat_manip->protomax.value;
		}
		else {
			min = 0;
			max = 0xFFFF;
		}

		if (nat_ports_getnew(IP_PROTO_ICMP, &id, min, max) > 0) {
			reply->dst.proto.upi.icmp6.id = htons(id); 
		}
		else 
			return -1;
	} 
	else if (type == NAT_DNAT) {
		reply->src.proto.upi.icmp6.id = tuple->src.proto.upi.icmp6.id;
	}

	return 1;
}

int nat_icmp4_free(struct nat_pcb *pcb)
{
	if (pcb->nat_type == NAT_SNAT) {
		nat_ports_free(IP_PROTO_ICMP4, ntohs( pcb->tuple[CONN_DIR_REPLY].src.proto.upi.icmp4.id ));
	}

	return 1;
}

int nat_icmp6_free(struct nat_pcb *pcb)
{
	if (pcb->nat_type == NAT_SNAT) {
		nat_ports_free(IP_PROTO_ICMP, ntohs( pcb->tuple[CONN_DIR_REPLY].src.proto.upi.icmp6.id ));
		//nat_ports_free(IP_PROTO_ICMP, ntohs(reply->src.proto.upi.icmp6.id));
	}

	return 1;
}

/*--------------------------------------------------------------------------*/

struct track_protocol  icmp4_track = {
	.tuple   = track_icmp4_tuple,
	.inverse = track_icmp4_inverse,

	.error   = track_icmp4_error,
	.new     = track_icmp4_new,
	.handle  = track_icmp4_handle,

	.manip             = nat_icmp4_manip,
	.nat_tuple_inverse = nat_icmp4_tuple_inverse,
	.nat_free          = nat_icmp4_free
};

struct track_protocol  icmp6_track = {
	.tuple   = track_icmp6_tuple,
	.inverse = track_icmp6_inverse,

	.error   = track_icmp6_error,
	.new     = track_icmp6_new,
	.handle  = track_icmp6_handle,

	.manip             = nat_icmp6_manip,
	.nat_tuple_inverse = nat_icmp6_tuple_inverse,
	.nat_free          = nat_icmp6_free
};

#endif 


#if 0
	//struct icmp_echo_hdr *icmphdr = NULL;
	//icmphdr = (struct icmp_echo_hdr *) (iphdr+iplen);

	//struct icmp_echo_hdr *icmphdr = NULL;
	//icmphdr = (struct icmp_echo_hdr *) (iphdr+iplen);


	u16_t val;
	struct ip_tuple trytuple;
	conn_dir_t dir;


	if (type == NAT_SNAT) {
		//reply->src.proto.upi.icmp4.id = tuple->src.proto.upi.icmp4.id;

		/* Copy tuple */
		memcpy(&trytuple, tuple, sizeof(struct ip_tuple));
	
		for(val=0; val < 0xFFFF; val++) {

			trytuple->src.proto.upi.icmp4.id = htons(val);
	
			if (conn_find_track(&dir, &trytuple) == NULL) {
	
				memcpy(reply, &trytuple, sizeof(struct ip_tuple));
	
				return 1;
			}
		}


	} else if (type == NAT_DNAT) {
		reply->src.proto.upi.icmp4.id = tuple->src.proto.upi.icmp4.id;
		return 1;
	}

	//if (type == NAT_SNAT) {
	//reply->src.proto.upi.icmp6.id = tuple->src.proto.upi.icmp6.id;
	//	u32_t id;
	//	nat_ports_getnew(IP_PROTO_ICMP, &id);
	//	reply->src.proto.upi.icmp6.id  = htons(id);
	//} 

#endif


