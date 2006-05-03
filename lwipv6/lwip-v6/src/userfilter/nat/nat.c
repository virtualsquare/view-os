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
#include "lwip/udp.h"
#include "lwip/tcp.h"
#include "lwip/icmp.h"

#include "lwip/sockets.h"
#include "lwip/if.h"

#include "lwip/nat/nat.h"
#include "lwip/nat/nat_tables.h"

#ifndef NAT_DEBUG
#define NAT_DEBUG   DBG_OFF
#endif

/*--------------------------------------------------------------------------*/

uf_verdict_t  nat_track   (uf_hook_t hooknum, struct pbuf **q, struct netif *inif, struct netif *outif);
uf_verdict_t  nat_perform (uf_hook_t hooknum, struct pbuf **q, struct netif *inif, struct netif *outif);
uf_verdict_t  nat_confirm (uf_hook_t hooknum, struct pbuf **q, struct netif *inif, struct netif *outif);

struct uf_hook_handler   nat_prerouting_track =
{
	.next     = NULL,
	.hooknum  = UF_IP_PRE_ROUTING,
	.hook     = nat_track,
	.priority = UF_PRI_NAT_PREROUTING_TRACK
};

struct uf_hook_handler   nat_prerouting_dnat =
{
	.next     = NULL,
	.hooknum  = UF_IP_PRE_ROUTING,
	.hook     = nat_perform,
	.priority = UF_PRI_NAT_PREROUTING_DNAT
};

struct uf_hook_handler   nat_input_confirm =
{
	.next     = NULL,
	.hooknum  = UF_IP_LOCAL_IN,
	.hook     = nat_confirm,
	.priority = UF_PRI_NAT_INPUT_CONFIRM
};

struct uf_hook_handler   nat_output_track =
{
	.next     = NULL,
	.hooknum  = UF_IP_LOCAL_OUT,
	.hook     = nat_track,
	.priority = UF_PRI_NAT_OUTPUT_TRACK
};

struct uf_hook_handler   nat_postrouting_snat =
{
	.next     = NULL,
	.hooknum  = UF_IP_POST_ROUTING,
	.hook     = nat_perform,
	.priority = UF_PRI_NAT_POSTROUTING_SNAT
};

struct uf_hook_handler   nat_postrouting_confirm =
{
	.next     = NULL,
	.hooknum  = UF_IP_POST_ROUTING,
	.hook     = nat_confirm,
	.priority = UF_PRI_NAT_POSTROUTING_CONFIRM
};

/*--------------------------------------------------------------------------*/
/* Nat PCBS */
/*--------------------------------------------------------------------------*/

sys_sem_t unique_mutex;

sys_sem_t nat_mutex; /* Semaphore for critical section */

#define LOCK(sem)         sys_sem_wait_timeout((sem), 0)
#define UNLOCK(sem)       sys_sem_signal((sem))

//#define NAT_LOCK()     sys_sem_wait_timeout(nat_mutex, 0)
//#define NAT_UNLOCK()   sys_sem_signal(nat_mutex)

#define NAT_LOCK()     LOCK(nat_mutex)
#define NAT_UNLOCK()   UNLOCK(nat_mutex)

struct nat_pcb *nat_tentative_pcbs;
struct nat_pcb *nat_active_pcbs; 

#define NAT_PCB_REG(pcbs_list, npcb) \
	do { \
		NAT_LOCK(); \
		npcb->next = *pcbs_list; \
		*(pcbs_list) = npcb; \
		NAT_UNLOCK(); \
	} while(0)

#define NAT_PCB_RMV(pcbs_list, npcb) \
	do { \
		struct nat_pcb *___tmp; \
		NAT_LOCK(); \
		if(*(pcbs_list) == npcb) { \
			(*(pcbs_list)) = (*pcbs_list)->next; \
		} else \
			for(___tmp = *pcbs_list; ___tmp != NULL; ___tmp = ___tmp->next) { \
				if((___tmp->next != NULL) && (___tmp->next == npcb)) { \
					___tmp->next = npcb->next; \
					break; \
				} \
			} \
		npcb->next = NULL; \
		NAT_UNLOCK(); \
	} while(0)

/*--------------------------------------------------------------------------*/

struct track_protocol *ip_ct_protos[MAX_TRACK_PROTO];

struct track_protocol * track_proto_find(u_int8_t protocol)
{
	return ip_ct_protos[protocol];
}

/*--------------------------------------------------------------------------*/

int nat_init(void)
{
	int i;

	nat_mutex    = sys_sem_new(1);
	unique_mutex = sys_sem_new(1);

	// FIX: remove this and bind ip/port in the stack
	nat_ports_init();

	// Init rules lists
	nat_in_rules  = NULL;
	nat_out_rules = NULL;

	// Init pcbs lists
	nat_active_pcbs    = NULL; 
	nat_tentative_pcbs = NULL;

	/* Set protocol handlers */

	ip_conntrack_protocol_tcp_lockinit();

	for (i = 0; i < MAX_TRACK_PROTO; i++)
		ip_ct_protos[i] = &default_track;
	ip_ct_protos[IP_PROTO_TCP]   = &tcp_track;
	ip_ct_protos[IP_PROTO_UDP]   = &udp_track;
	ip_ct_protos[IP_PROTO_ICMP4] = &icmp4_track;
	ip_ct_protos[IP_PROTO_ICMP]  = &icmp6_track;

	/* Register hooks */
	uf_register_hook(& nat_prerouting_track );
	uf_register_hook(& nat_prerouting_dnat );
	uf_register_hook(& nat_input_confirm );
	uf_register_hook(& nat_output_track );
	uf_register_hook(& nat_postrouting_snat );
	uf_register_hook(& nat_postrouting_confirm );

	LWIP_DEBUGF(NAT_DEBUG, ("%s: registered NAT hooks!\n", __func__));
	
	return ERR_OK;
}

/*--------------------------------------------------------------------------*/

// assuming: unsigned char is 8 bits, long is 32 bits.
//	- chksum points to the chksum in the packet 
//	- optr points to the old data in the packet
//	- nptr points to the new data in the packet
void nat_chksum_adjust(u8_t * chksum, u8_t * optr, s16_t olen, u8_t * nptr, s16_t nlen)
{
	s32_t x, old, new;

	x = chksum[0] * 256 + chksum[1];
	x = ~x & 0xFFFF;
	while (olen) {
		old = optr[0] * 256 + optr[1];
		optr += 2;
		x -= old & 0xffff;
		if (x <= 0) {
			x--;
			x &= 0xffff;
		}
		olen -= 2;
	}
	while (nlen) {
		new = nptr[0] * 256 + nptr[1];
		nptr += 2;
		x += new & 0xffff;
		if (x & 0x10000) {
			x++;
			x &= 0xffff;
		}
		nlen -= 2;
	}
	x = ~x & 0xFFFF;
	chksum[0] = x / 256;
	chksum[1] = x & 0xff;
}

/*--------------------------------------------------------------------------*/
// NAT session descriptors 
/*--------------------------------------------------------------------------*/

static unsigned int pcb_id = 0;

/* Return a new session descriptor. Returns NULL on error */
struct nat_pcb *nat_new_pcb(void)
{
	struct nat_pcb *pcb;

	pcb = memp_malloc(MEMP_NAT_PCB);
	if (pcb != NULL) {
		LWIP_DEBUGF(NAT_DEBUG, ("%s: get new! %p\n", __func__, pcb));
		bzero(pcb, sizeof(struct nat_pcb));
		pcb->nat_type = NAT_NONE;
		pcb->id       = pcb_id++;
	}
	return pcb;
}

void nat_free_pcb(struct nat_pcb *pcb)
{
	LWIP_DEBUGF(NAT_DEBUG, ("%s: free %p (id=%d)\n", __func__, pcb, pcb->id));
	memp_free(MEMP_NAT_PCB, pcb);
}

/*--------------------------------------------------------------------------*/

void nat_session_put(struct nat_pcb *pcb);

void nat_pbuf_init(struct pbuf *p)
{
	p->nat.track = NULL;
	p->nat.dir   = 0;
}

void nat_pbuf_get(struct pbuf *p)
{
}

void nat_pbuf_put(struct pbuf *p)
{
	if (p->nat.track == NULL)
		return;

	nat_session_put(p->nat.track);

	p->nat.track = NULL;
	p->nat.dir   = 0;
}

void nat_pbuf_reset(struct pbuf *p)
{
	nat_pbuf_put(p);
}

/*--------------------------------------------------------------------------*/
// Tuples
/*--------------------------------------------------------------------------*/

#ifdef LWIP_DEBUG
/* Print a tuple on output for debug messages */
void dump_tuple (struct ip_tuple *tuple)
{
	LWIP_DEBUGF(NAT_DEBUG, ("TUPLE: ")); 
	ip_addr_debug_print(NAT_DEBUG, &tuple->src.ip); LWIP_DEBUGF(NAT_DEBUG, ("  ")); 
	ip_addr_debug_print(NAT_DEBUG, &tuple->dst.ip); LWIP_DEBUGF(NAT_DEBUG, ("  ")); 

	switch (tuple->src.proto.protonum)
	{
		case IP_PROTO_TCP:
			LWIP_DEBUGF(NAT_DEBUG, ("TCP [%d,%d]", ntohs(tuple->src.proto.upi.tcp.port), 
				ntohs(tuple->dst.proto.upi.tcp.port))); 
			break;
		case IP_PROTO_UDP:
			LWIP_DEBUGF(NAT_DEBUG, ("UDP [%d,%d]", ntohs(tuple->src.proto.upi.udp.port), 
				ntohs(tuple->dst.proto.upi.udp.port))); 
			break;
		case IP_PROTO_ICMP4:
			LWIP_DEBUGF(NAT_DEBUG, ("Icmp4 id=%d type=%d code=%d", 
				ntohs(tuple->src.proto.upi.icmp4.id), 
				tuple->src.proto.upi.icmp4.type, tuple->src.proto.upi.icmp4.code)); 
			break;
		case IP_PROTO_ICMP:
			LWIP_DEBUGF(NAT_DEBUG, ("Icmp6 id=%d (%x) type=%d code=%d", 
				ntohs(tuple->src.proto.upi.icmp6.id), 
				ntohs(tuple->src.proto.upi.icmp6.id), 
				tuple->src.proto.upi.icmp6.type, 
				tuple->src.proto.upi.icmp6.code)); 
			break;
		default:
			LWIP_DEBUGF(NAT_DEBUG, ("%s: strange protocol", __func__ ));
			break;
	}
	LWIP_DEBUGF(NAT_DEBUG, ("\n"));
}
#else
#define dump_tuple(p) {}
#endif

/*--------------------------------------------------------------------------*/

int get_masquerade_ip(struct ip_addr *ip, u8_t ipv, struct netif *netif)
{
	struct ip_addr_list *addr;

	addr = ip_addr_list_masquarade_addr(netif->addrs, ipv);
	if (addr != NULL) {
		ip_addr_set(ip, &addr->ipaddr);
		return 1;
	}

	return -1;
}

/* Create a unique tuple for NAT */
int tuple_create_nat_inverse(struct ip_tuple *reply, struct ip_tuple *tuple, 
	struct netif *iface, nat_type_t type, struct manip_range *nat_manip) 
{
	int r;
	struct track_protocol *proto;

	//LOCK(unique_mutex)

	/* Set IP */

	reply->ipv = tuple->ipv;

	if (type == NAT_MASQUERADE) {
		if (get_masquerade_ip(&reply->dst.ip, reply->ipv, iface) < 0)
			return -1;
	}
	else
	if (type == NAT_SNAT) {
		ip_addr_set (&reply->dst.ip, &nat_manip->ipmin);
	}
	else
	if (type == NAT_DNAT) {
		ip_addr_set (&reply->src.ip, &nat_manip->ipmin);
	}
	else {
		LWIP_DEBUGF(NAT_DEBUG, ("%s: BUG\n", __func__ ));
		return -1;
	}

	/* Set PROTO */

	reply->src.proto.protonum = tuple->src.proto.protonum;

	proto = track_proto_find( tuple->src.proto.protonum );
	if (proto == NULL) {
		LWIP_DEBUGF(NAT_DEBUG, ("%s: BUG 2 \n", __func__ ));
		return -1;
	}
	
	r = proto->nat_tuple_inverse(reply, tuple, type, nat_manip);

	//UNLOCK(unique_mutex);

	return r;
}

/*--------------------------------------------------------------------------*/

/* Returns 1 if t2 and t1 are equal. */
int nat_tuple_cmp(struct ip_tuple *t1, struct ip_tuple *t2)
{
	int r;

	/* FIX: too simple */
	r = memcmp(t1, t2, sizeof(struct ip_tuple));

	if ( r == 0) return 1;
	else         return 0;
}

int tuple_inverse(struct ip_tuple *reply, struct ip_tuple *tuple) 
{
	struct track_protocol *proto;

	bzero(reply, sizeof(struct ip_tuple));

	reply->ipv = tuple->ipv;
	ip_addr_set (&reply->src.ip, &tuple->dst.ip);
	ip_addr_set (&reply->dst.ip, &tuple->src.ip);

	reply->src.proto.protonum = tuple->src.proto.protonum;
	proto = track_proto_find( tuple->src.proto.protonum );

	return proto->inverse(reply, tuple);
}

int tuple_create(struct ip_tuple *tuple, struct pbuf *p, struct track_protocol *proto) 
{
	struct ip_hdr *ip6hdr;
	struct ip4_hdr *ip4hdr;
	u32_t  iphdrlen;

	bzero(tuple, sizeof(struct ip_tuple));

	ip6hdr = (struct ip_hdr *) p->payload;
	ip4hdr = (struct ip4_hdr *) p->payload;
	tuple->ipv = IPH_V(ip6hdr);
	if (tuple->ipv == 6) {
		ip_addr_set (&tuple->src.ip , &(ip6hdr->src)  );
		ip_addr_set (&tuple->dst.ip , &(ip6hdr->dest) );

		tuple->src.proto.protonum = IPH_NEXTHDR(ip6hdr); 

		iphdrlen = IP_HLEN;
	}
	else if (tuple->ipv == 4) {
		IP64_CONV (&tuple->src.ip , &(ip4hdr->src)  );
		IP64_CONV (&tuple->dst.ip , &(ip4hdr->dest) );

		tuple->src.proto.protonum = IPH4_PROTO(ip4hdr);

		iphdrlen = IPH4_HL(ip4hdr) * 4;
	} else {
		LWIP_DEBUGF(NAT_DEBUG, ("%s: IP version wrong \n", __func__ ));
		return -1; /* error */
	}

	return proto->tuple(tuple, ((char*)p->payload) + iphdrlen);
}

/*--------------------------------------------------------------------------*/
// NAT timer functions */
/*--------------------------------------------------------------------------*/

struct nat_pcb * nat_create_session(nat_type_t nat_type, 
	struct nat_pcb *pcb, struct netif *iface, struct manip_range *manip)
{
	LWIP_DEBUGF(NAT_DEBUG, ("\tnat=%s iface=%d \n",STR_NATNAME(nat_type), iface->id ));

	pcb->nat_type = nat_type;

	if (pcb->nat_type == NAT_MASQUERADE) {
		pcb->status   |= TS_MASQUERADE;
		pcb->nat_type  = NAT_SNAT;
		pcb->iface    = iface;
	}

	/* Setup inverse natted tuple 
	   NOTE: pcb->tuple[CONN_DIR_ORIGINAL ]is already set
	*/
	if (tuple_create_nat_inverse(&pcb->tuple[CONN_DIR_REPLY], 
		&pcb->tuple[CONN_DIR_ORIGINAL], iface, nat_type, manip ) < 0)
		return NULL;

	LWIP_DEBUGF(NAT_DEBUG, ("\tinverse="));	dump_tuple (&pcb->tuple[CONN_DIR_REPLY]);
	LWIP_DEBUGF(NAT_DEBUG, ("\n"));

	return pcb;
}

void nat_session_put(struct nat_pcb *pcb)
{
	struct track_protocol *proto;

	LWIP_DEBUGF(NAT_DEBUG, ("%s: pcb id=%d ref=%d\n", __func__, pcb->id, (int)pcb->refcount));
	pcb->refcount--;
	if (pcb->refcount == 0)  {
		LWIP_DEBUGF(NAT_DEBUG, ("\tid=%d ref now = 0 -> FREE\n", pcb->id));

		/* The tracking not confirmed this connection, remove it */
		if (!(pcb->status & TS_CONFIRMED)) {
			NAT_PCB_RMV(&nat_tentative_pcbs, pcb);
		} 

		// Need to unbind() used ports for SNAT
		if (pcb->nat_type != NAT_NONE) {

			proto = track_proto_find( pcb->tuple[CONN_DIR_ORIGINAL].src.proto.protonum );
			if (proto != NULL) {
				proto->nat_free(pcb);
			}
			else
				LWIP_DEBUGF(NAT_DEBUG, ("%s: BUG 2 \n", __func__ ));
		}

		nat_free_pcb(pcb);
	}
}

/*--------------------------------------------------------------------------*/
// Tracking
/*--------------------------------------------------------------------------*/

void close_timeout(void *arg)
{
	struct nat_pcb *pcb = (struct nat_pcb *) arg;

	LWIP_DEBUGF(NAT_DEBUG, ("%s: session p=%p id=%d expired\n", __func__, pcb, pcb->id));
	LWIP_DEBUGF(NAT_DEBUG, ("\t")); dump_tuple(&pcb->tuple[CONN_DIR_ORIGINAL]); 

	NAT_PCB_RMV(&nat_active_pcbs, pcb);

	nat_session_put(pcb);
}

void conn_refresh_timer(u32_t timeout, struct nat_pcb *pcb)
{
	pcb->timeout = timeout;

	LWIP_DEBUGF(NAT_DEBUG, ("%s: refresh on pcb id=%d\n", __func__, pcb->id));
	if (!conn_remove_timer(pcb)) {
		LWIP_DEBUGF(NAT_DEBUG, ("%s: No timer\n", __func__));
		return ;
	}
	
	sys_timeout(timeout, (sys_timeout_handler) close_timeout, pcb);
}

int conn_remove_timer(struct nat_pcb *pcb)
{
	return sys_untimeout_and_check((sys_timeout_handler)close_timeout, pcb);
}

void conn_force_timeout(struct nat_pcb *pcb)
{
	close_timeout(pcb);
}

int new_track(struct nat_pcb **newpcb, uf_hook_t hook, struct pbuf **q, 
	struct ip_tuple * tuple, conn_dir_t *direction, struct track_protocol *proto)
{
	struct ip_hdr *ip6hdr;
	struct ip4_hdr *ip4hdr;
	u16_t iphdrlen;
	struct nat_pcb *pcb;
	struct pbuf *p=*q;

	LWIP_DEBUGF(NAT_DEBUG, ("%s: start\n", __func__));

	pcb = nat_new_pcb();
	if (pcb == NULL) {
		LWIP_DEBUGF(NAT_DEBUG, ("%s: NAT PCB memory full.\n", __func__));
		return -1;
	}

	/* 
	 * Save ORIGINAL and REPLY connection tuple. 
	 */
	memcpy(&pcb->tuple[CONN_DIR_ORIGINAL], tuple, sizeof (struct ip_tuple));

	if (tuple_inverse(&pcb->tuple[CONN_DIR_REPLY], 
		&pcb->tuple[CONN_DIR_ORIGINAL]) < 0) {
		LWIP_DEBUGF(NAT_DEBUG, ("%s: Unable to get inverse tuple\n", __func__));
        	return -1;
	}

	LWIP_DEBUGF(NAT_DEBUG, ("%s: New track. id=%d\n", __func__, pcb->id));
	LWIP_DEBUGF(NAT_DEBUG, ("\tORIGINAL: ")); dump_tuple ( &pcb->tuple[CONN_DIR_ORIGINAL] ); 
	LWIP_DEBUGF(NAT_DEBUG, ("\tREPLY   : ")); dump_tuple ( &pcb->tuple[CONN_DIR_REPLY] ); 

	/* Init per-protocol informations */
	ip4hdr = (struct ip4_hdr *) p->payload;
	ip6hdr = (struct ip_hdr *) p->payload;
	if (tuple->ipv == 6)      
		iphdrlen = IP_HLEN;
	else if (tuple->ipv == 4) 
		iphdrlen = IPH4_HL(ip4hdr) * 4;

	if (proto->new(pcb, p, p->payload, iphdrlen) < 0) {
		LWIP_DEBUGF(NAT_DEBUG, ("%s: Unable to create new valid tracking.\n", __func__));

		nat_free_pcb(pcb);
		return -1;
	}

	*direction = CONN_DIR_ORIGINAL;
	*newpcb    = pcb;

	pcb->refcount = 1;

	pcb->next = NULL;
	/* Register this connection as a Tentative */
	NAT_PCB_REG(&nat_tentative_pcbs, pcb);

	return 1;
}

struct nat_pcb * conn_find_track(conn_dir_t *direction, struct ip_tuple * tuple )
{
	struct nat_pcb *pcb = NULL;

	/* Search in the table */
	NAT_LOCK();
	for(pcb = nat_active_pcbs; pcb != NULL; pcb = pcb->next)  {

		LWIP_DEBUGF(NAT_DEBUG, ("\tpcb=%p\tORIGINAL: ", pcb)); 
		dump_tuple(&pcb->tuple[CONN_DIR_ORIGINAL]);
		LWIP_DEBUGF(NAT_DEBUG, ("\t\t\tREPLY   : ")); 
		dump_tuple(&pcb->tuple[CONN_DIR_REPLY]);
		LWIP_DEBUGF(NAT_DEBUG, ("\n"));

		if (nat_tuple_cmp(&pcb->tuple[CONN_DIR_ORIGINAL], tuple)) {
			*direction = CONN_DIR_ORIGINAL;
			break;
		}
		if (nat_tuple_cmp(&pcb->tuple[CONN_DIR_REPLY]   , tuple)) {
			*direction = CONN_DIR_REPLY;
			break;
		}
	}

	if (pcb != NULL) {
		LWIP_DEBUGF(NAT_DEBUG, ("\tFOUND pcb id=%d\n", pcb->id)); 
		pcb->refcount++;
	}

	NAT_UNLOCK();

	return pcb;
}

/*
 * Try to track the packet. If this packet doesn't belong to any existing connection
 * a new one will be created. On errors return -1.
 */
int conn_track(conn_dir_t *direction, uf_hook_t hook, 
	struct pbuf **q, struct netif *inif, struct netif *outif, struct track_protocol *proto)
{
	struct pbuf *p = * q;
	struct nat_pcb *tmppcb = NULL;
	struct ip_tuple tuple;  

	LWIP_DEBUGF(NAT_DEBUG, ("%s: start\n", __func__ ));

	/* Get the tuple of the packet */
	if (tuple_create(&tuple, p, proto) < 0) {
		LWIP_DEBUGF(NAT_DEBUG, ("%s: unable to create tuple!\n", __func__ ));
		return -1;
	}

	dump_tuple (&tuple); 

	/* Find tracking informations */	
	tmppcb = conn_find_track(direction, &tuple);
	if (tmppcb == NULL) {
		if (new_track(&tmppcb, hook, q, &tuple, direction, proto) < 0) {
			LWIP_DEBUGF(NAT_DEBUG, ("%s: unable to create new track \n", __func__ ));
			return -1;
		}
		LWIP_DEBUGF(NAT_DEBUG, ("%s: NEW track %p id=%d!!\n", __func__, tmppcb, tmppcb->id));
	}

	if ((*direction) == CONN_DIR_REPLY)
		tmppcb->status |= TS_SEEN_REPLY;

	p->nat.track = tmppcb;
	p->nat.dir   = *direction;

	return 1;
}


/* Returns 1 if 'p' is a valid packet for tracking and NAT.
   Some ICMP6 packet (NS,ND, RA,RD) don't need tracking or NAT */
int conn_need_track(struct pbuf *p)
{
	struct ip_hdr *ip6hdr;
	struct ip4_hdr *ip4hdr;
	u32_t  iphdrlen;
	struct ip_addr src,dst;

	ip6hdr = (struct ip_hdr *) p->payload;
	ip4hdr = (struct ip4_hdr *) p->payload;
	if (IPH_V(ip6hdr) == 6) {
		iphdrlen = IP_HLEN;
		if (ip_addr_ismulticast(&ip6hdr->dest)) 
			return 0;
		if (ip_addr_ismulticast(&ip6hdr->src)) 
			return 0;
	}
	else if (IPH_V(ip6hdr) == 4) {
		iphdrlen = IPH4_HL(ip4hdr) * 4;

		IP64_CONV (&src , &(ip4hdr->src)  );
		IP64_CONV (&dst , &(ip4hdr->dest) );

		if (ip_addr_is_v4multicast(&dst)) 
			return 0;
	}

	return 1;
}
/*--------------------------------------------------------------------------*/
// HOOKS
/*--------------------------------------------------------------------------*/

uf_verdict_t nat_track (uf_hook_t hooknum, struct pbuf **q, struct netif *inif, struct netif *outif)
{
	struct pbuf *p = *q;
	struct ip4_hdr *ip4hdr;
	struct ip_hdr  *ip6hdr;

	struct track_protocol *proto;

	///struct nat_pcb *pcb;
	conn_dir_t direction;
	uf_verdict_t verdict;

	/* ASSERT! This is the first hook, no tracking info yet! */
	if (p->nat.track != NULL) {
		LWIP_DEBUGF(NAT_DEBUG, ("%s:  pcb not NULL!!!!!\n", __func__));
	}

	nat_pbuf_reset(p);

	/* Find transport protocol handler */
	ip6hdr = (struct ip_hdr *) p->payload;
	ip4hdr = (struct ip4_hdr *) p->payload;
	if (IPH_V(ip6hdr) == 6) 
		// FIX: handle IPv6 extension headers 
		proto = track_proto_find( IPH_NEXTHDR(ip6hdr) );
	else if (IPH_V(ip6hdr) == 4) 
		proto = track_proto_find(  IPH4_PROTO(ip4hdr) );
	else
		return UF_DROP;

	if (proto->error != NULL) {
		if (proto->error(&verdict, p) < 0) {
			LWIP_DEBUGF(NAT_DEBUG, ("%s: proto error() -> %s\n", __func__, STR_VERDICT(verdict) ));
			return verdict;				
		}
	}

	if (!conn_need_track(p)) {
		LWIP_DEBUGF(NAT_DEBUG, ("%s: doesn't need track\n", __func__ ));
		return UF_ACCEPT;				
	}

	/* Find connection, if none is found a new will be created */	
	if (conn_track(&direction, hooknum, q, inif, outif, proto ) < 0) {
		LWIP_DEBUGF(NAT_DEBUG, ("%s: tracking failed (not new valid connection)! DROP\n", __func__ ));
		return UF_DROP;
	}

	/* Update tracking informations */
	if (proto->handle(&verdict, p, direction) < 0) {
		LWIP_DEBUGF(NAT_DEBUG, ("%s: drop this packet!!\n", __func__));
		/* Invalid: inverse of the return code tells
		 * the netfilter core what to do*/
		nat_session_put(p->nat.track);
		p->nat.track = NULL;
		//return -verdict;
		return verdict;
	}

	LWIP_DEBUGF(NAT_DEBUG, ("%s: pcb %p, dir=%s -> %s!!\n", __func__, 
		p->nat.track, STR_DIRECTIONNAME(direction), STR_VERDICT(verdict)));

	return verdict;
}

uf_verdict_t  nat_confirm (uf_hook_t hooknum, struct pbuf **q, struct netif *inif, struct netif *outif)
{
	struct nat_pcb *pcb = NULL;
	struct pbuf *p = *q;

	pcb = p->nat.track;
	if (pcb == NULL) {
		LWIP_DEBUGF(NAT_DEBUG, ("%s: no track for this packet!!\n", __func__));
		return UF_ACCEPT;
	}

	if (! (pcb->status & TS_CONFIRMED)) {

		/// FIX: controllare che non ci sia gia' un'altra connessione valida
		/// con le stesse tuple. Se e' presente vuol dire che:
		///  a) Il NAT ha modificato una connessione usando una tupla gia' occupata
		///     Una connessione proveniente dal LOCALOUT e' uguale ad una modificata in
		///     SNAT.

		pcb->status |= TS_CONFIRMED;

		pcb->refcount++;
		sys_timeout(pcb->timeout, (sys_timeout_handler) close_timeout, pcb);

		NAT_PCB_RMV(&nat_tentative_pcbs, pcb);
		NAT_PCB_REG(&nat_active_pcbs, pcb);

		LWIP_DEBUGF(NAT_DEBUG, ("%s: confirming track %p id=%d!!\n", __func__, pcb, pcb->id));
	}

	return UF_ACCEPT;
}

/* Return -1 on error */
int  nat_check_rule(struct nat_pcb *pcb, uf_hook_t hooknum, struct netif *inif,struct netif *outif)
{
	struct nat_rule * list, *rule;
	struct netif    * netif = NULL;
	struct manip_range *nat_manip;
        nat_type_t      type;

	if (hooknum == UF_IP_PRE_ROUTING) {
		list  = nat_in_rules;
		netif = inif;
	} 
	else if (hooknum == UF_IP_POST_ROUTING) {
		list  = nat_out_rules;
		netif = outif;
	}

	/* Search for rules */
	for(rule = list; rule != NULL; rule = rule->next) {
		if (nat_match_rule(&rule->matches, netif, &pcb->tuple[CONN_DIR_ORIGINAL])) 
			break; 
	}

	if (rule == NULL) {
		LWIP_DEBUGF(NAT_DEBUG, ("%s: no rule found\n",__func__));
		return 1;
	}
	else {
		type = rule->type;
		nat_manip = &rule->manip;
	}

	/* We try only SNAT or DNAT, not both */
	pcb->status |= TS_NAT_TRY_MASK;


	if (nat_create_session(type, pcb, netif, nat_manip) == NULL) {
		LWIP_DEBUGF(NAT_DEBUG, ("%s: unable to create session with rule\n",__func__));
		return -1;
	}

	return 1;
}

void nat_modify_ip(nat_type_t nat, struct pbuf *p, struct ip_tuple *inverse)
{
	struct ip_hdr  *iphdr;
	struct ip4_hdr *ip4hdr;
	u16_t iphdrlen;
	struct track_protocol *proto;

	struct ip4_addr tmp_ip4;

	u32_t          old_ip4_addr;
	struct ip_addr old_ip6_addr;

	u8_t  *iphdr_old_changed_buf;
	u8_t  *iphdr_new_changed_buf;
	u32_t  iphdr_changed_buflen;

	/* Modify IP header */

	iphdr = (struct ip_hdr *) p->payload;
	ip4hdr = (struct ip4_hdr *) p->payload;

	if (inverse->ipv == 4) {
		/* Need to convert tuple's IP used for manipulations 
		   from 128 bit to 32 bit */
		if (nat == NAT_DNAT) {
			// copy old address
			old_ip4_addr = ip4hdr->dest.addr;
			ip64_addr_set( &tmp_ip4, &inverse->src.ip);
			ip4_addr_set((struct ip4_addr *) &(ip4hdr->dest), &tmp_ip4);
			
			// Adjust IP checksum. Only IPv4 has checksum
			nat_chksum_adjust((u8_t *) & IPH4_CHKSUM(ip4hdr), 
				(u8_t *) & old_ip4_addr, 4, (u8_t *) & ip4hdr->dest.addr, 4);
	
			// remember IP header changes
			iphdr_new_changed_buf = (u8_t *) &ip4hdr->dest.addr;
			iphdr_old_changed_buf = (u8_t *) &old_ip4_addr;
			iphdr_changed_buflen  = 4;
		}
		if (nat == NAT_SNAT) {
			old_ip4_addr = ip4hdr->src.addr;
			ip64_addr_set( &tmp_ip4, &inverse->dst.ip);
			ip4_addr_set((struct ip4_addr *) &(ip4hdr->src), &tmp_ip4);
	
			// Adjust IP checksum. Only IPv4 has checksum
			nat_chksum_adjust((u8_t *) & IPH4_CHKSUM(ip4hdr), 
				(u8_t *) & old_ip4_addr, 4, (u8_t *) & ip4hdr->src.addr, 4);
		
			// remember IP header changes
			iphdr_new_changed_buf = (u8_t *) &ip4hdr->src.addr;
			iphdr_old_changed_buf = (u8_t *) &old_ip4_addr;
			iphdr_changed_buflen = 4;
		}
	} else 
	if (inverse->ipv == 6) {
		if (nat == NAT_DNAT) {
			ip_addr_set( &old_ip6_addr, &iphdr->dest);
			ip_addr_set( &iphdr->dest, &inverse->src.ip);

			iphdr_new_changed_buf = (u8_t *) &iphdr->dest;
		}
		if (nat == NAT_SNAT) {
			ip_addr_set( &old_ip6_addr, &iphdr->src);
			ip_addr_set( &iphdr->src, &inverse->dst.ip);

			iphdr_new_changed_buf = (u8_t *) &iphdr->src;
		}

		iphdr_old_changed_buf = (u8_t *) &old_ip6_addr;
		iphdr_changed_buflen = 16;
	}

	/* Modify transport header */

	proto = track_proto_find(inverse->src.proto.protonum);

	if (inverse->ipv == 6)      iphdrlen = IP_HLEN;
	else if (inverse->ipv == 4) iphdrlen = IPH4_HL(ip4hdr) * 4;

	proto->manip(nat, p->payload, iphdrlen, inverse, 
		iphdr_new_changed_buf, iphdr_old_changed_buf, iphdr_changed_buflen);
}


uf_verdict_t  nat_perform   (uf_hook_t hooknum, struct pbuf **q, struct netif *inif, struct netif *outif)
{
	struct pbuf *p = * q;
	struct nat_pcb *pcb;
	conn_dir_t direction;
	struct ip_tuple *tuple_inverse;
	nat_type_t      nat_original = NAT_NONE;
	nat_type_t      nat_manip = NAT_NONE;

	LWIP_DEBUGF(NAT_DEBUG, ("%s: start %s!\n", __func__, STR_HOOKNAME(hooknum)));

	if (p->nat.track == NULL) {
		LWIP_DEBUGF(NAT_DEBUG, ("%s: no track for this packet!!\n", __func__));
		return UF_ACCEPT;
	}

	pcb = p->nat.track;
	direction = p->nat.dir;

	/* If no NAT has been done on this connection and one of SNAT or DNAT
	   rules haven't been checked yet, try them */

	if (pcb->nat_type == NAT_NONE)
	if ((pcb->status & TS_NAT_TRY_MASK) != TS_NAT_TRY_MASK) {

		LWIP_DEBUGF(NAT_DEBUG, ("%s: Check for rules...\n", __func__ ));

		if (nat_check_rule(pcb, hooknum, inif, outif ) < 0) {
			LWIP_DEBUGF(NAT_DEBUG, ("%s: error, DROP\n", __func__ ));
			return UF_DROP;
		}
	}

	/* No NAT? No party */
	if (pcb->nat_type == NAT_NONE)
		return UF_ACCEPT;

	/* How tuples will be manipulated by Hooks
         *
	 * NAT  | DIRECTION | PREROUTING    ----->   POSTROUTING
	 *------|-----------|------------------------------------------
	 *      | ORIGINAL  | [x,y] -> x,N (D)            - 
	 * DNAT |           |
	 *      | REPLY     |       -                [N,x] -> y,x (S)
	 *------|-----------|------------------------------------------
	 *      | ORIGINAL  |       -                [x,y] -> N,y (S)
	 * SNAT |           |
	 *      | REPLY     | [y,N] -> y,x (D)            -
	 *------|-----------|------------------------------------------
	 *
	 *    x,y  tuple (IP.src,IP.dst,proto.src,proto.dst)
	 *   [x,y] connection's tuple saved in tracking data
	 *    (D)  new destination = source      in the inverse tuple
	 *    (S)  new source      = destination in the inverse tuple
	 */

        /* We use the tuple in the other direction for NAT. See above */
	if (direction == CONN_DIR_ORIGINAL) 
		tuple_inverse = &pcb->tuple[CONN_DIR_REPLY];
	else
		tuple_inverse = &pcb->tuple[CONN_DIR_ORIGINAL];

	nat_original = pcb->nat_type;

	/* Manipulation's type depends on packet direction and
	   original manipulation */

	if (hooknum == UF_IP_PRE_ROUTING) {
		if (direction == CONN_DIR_ORIGINAL) {
			if (nat_original == NAT_DNAT)  
				nat_manip = NAT_DNAT;
		}
		else
		if (direction == CONN_DIR_REPLY)
			if (nat_original == NAT_SNAT)  
				nat_manip = NAT_DNAT;
	}
	else if (hooknum == UF_IP_POST_ROUTING) {
		if (direction == CONN_DIR_ORIGINAL) {
			if (nat_original == NAT_SNAT)  
				nat_manip = NAT_SNAT;
		}
		else 
		if (direction == CONN_DIR_REPLY)
			if (nat_original == NAT_DNAT)  
				nat_manip = NAT_SNAT;
	}

	/* Manipulation on this packet is needed in this hook? */
	if (nat_manip != NAT_NONE) {

		nat_modify_ip(nat_manip, p, tuple_inverse);

		LWIP_DEBUGF(NAT_DEBUG, ("%s: NATed packet !\n", __func__));
		ip_debug_print(NAT_DEBUG, p);
		LWIP_DEBUGF(NAT_DEBUG, ("%s: end.\n", __func__));
	}

	return UF_ACCEPT;
}

#endif /* LWIP_NAT */





#if 0
/* Returns 1 if 'p' is a valid packet for tracking and NAT.
   Some ICMP6 packet (NS,ND, RA,RD) don't need tracking or NAT */
int conn_need_track(struct pbuf *p)
{
	struct ip_hdr *ip6hdr;
	struct ip4_hdr *ip4hdr;
	u32_t  iphdrlen;
	struct ip_addr src,dst;

	ip6hdr = (struct ip_hdr *) p->payload;
	ip4hdr = (struct ip4_hdr *) p->payload;
	if (IPH_V(ip6hdr) == 6) {
		iphdrlen = IP_HLEN;

		if (ip_addr_islinkscope(&ip6hdr->dest)) 
			return 0;
		if (ip_addr_islinkscope(&ip6hdr->src)) 
			return 0;

		if (ip_addr_ismulticast(&ip6hdr->dest)) 
			return 0;
		if (ip_addr_ismulticast(&ip6hdr->src)) 
			return 0;

	}
	else if (IPH_V(ip6hdr) == 4) {
		iphdrlen = IPH4_HL(ip4hdr) * 4;

		IP64_CONV (&src , &(ip4hdr->src)  );
		IP64_CONV (&dst , &(ip4hdr->dest) );

		if (ip_addr_is_v4multicast(&dst)) 
			return 0;
	}

	return 1;
}
#endif




