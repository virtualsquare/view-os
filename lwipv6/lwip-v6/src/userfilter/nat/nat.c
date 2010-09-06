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
 *   51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 */ 
#include "lwip/opt.h"

#if LWIP_USERFILTER && LWIP_NAT

#include "lwip/debug.h"
#include "lwip/sys.h"
#include "lwip/stats.h"
#include "lwip/memp.h" /* MEMP_NAT_RULE */

#include "lwip/inet.h"
#include "lwip/ip.h"
#include "lwip/ip_frag.h"
#include "lwip/udp.h"
#include "lwip/tcp.h"
#include "lwip/icmp.h"

#include "lwip/sockets.h"
#include "lwip/if.h"

#include "lwip/netif.h"
#include "lwip/userfilter.h"

#include "lwip/nat/nat.h"
#include "lwip/nat/nat_tables.h"


#ifndef NAT_DEBUG
#define NAT_DEBUG   DBG_OFF
#endif

/*--------------------------------------------------------------------------*/

uf_verdict_t  nat_defrag  (struct stack *stack, uf_hook_t hooknum, struct pbuf **q, struct netif *inif, struct netif *outif);

uf_verdict_t  nat_track   (struct stack *stack, uf_hook_t hooknum, struct pbuf **q, struct netif *inif, struct netif *outif);
uf_verdict_t  nat_perform (struct stack *stack, uf_hook_t hooknum, struct pbuf **q, struct netif *inif, struct netif *outif);
uf_verdict_t  nat_confirm (struct stack *stack, uf_hook_t hooknum, struct pbuf **q, struct netif *inif, struct netif *outif);

#if 0
struct uf_hook_handler   nat_prerouting_defrag =
{
	.hooknum  = UF_IP_PRE_ROUTING,
	.hook     = nat_defrag,
	.priority = UF_PRI_NAT_PREROUTING_DEFRAG
};
#endif

struct uf_hook_handler   nat_prerouting_track =
{
	.hooknum  = UF_IP_PRE_ROUTING,
	.hook     = nat_track,
	.priority = UF_PRI_NAT_PREROUTING_TRACK
};

struct uf_hook_handler   nat_prerouting_dnat =
{
	.hooknum  = UF_IP_PRE_ROUTING,
	.hook     = nat_perform,
	.priority = UF_PRI_NAT_PREROUTING_DNAT
};

struct uf_hook_handler   nat_input_confirm =
{
	.hooknum  = UF_IP_LOCAL_IN,
	.hook     = nat_confirm,
	.priority = UF_PRI_NAT_INPUT_CONFIRM
};

struct uf_hook_handler   nat_output_track =
{
	.hooknum  = UF_IP_LOCAL_OUT,
	.hook     = nat_track,
	.priority = UF_PRI_NAT_OUTPUT_TRACK
};

struct uf_hook_handler   nat_postrouting_snat =
{
	.hooknum  = UF_IP_POST_ROUTING,
	.hook     = nat_perform,
	.priority = UF_PRI_NAT_POSTROUTING_SNAT
};

struct uf_hook_handler   nat_postrouting_confirm =
{
	.hooknum  = UF_IP_POST_ROUTING,
	.hook     = nat_confirm,
	.priority = UF_PRI_NAT_POSTROUTING_CONFIRM
};

/*--------------------------------------------------------------------------*/
/* Nat PCBS */
/*--------------------------------------------------------------------------*/

/* it seems useless: rd20100730 */
/*sys_sem_t unique_mutex;*/


#define LOCK(sem)         sys_sem_wait_timeout((sem), 0)
#define UNLOCK(sem)       sys_sem_signal((sem))

#define NAT_LOCK(stack)        LOCK(stack->stack_nat->nat_mutex)
#define NAT_UNLOCK(stack)      UNLOCK(stack->stack_nat->nat_mutex)

#define NAT_PCB_REG(stack, pcbs_list, npcb) \
	do { \
		NAT_LOCK(stack); \
		npcb->next = *pcbs_list; \
		*(pcbs_list) = npcb; \
		NAT_UNLOCK(stack); \
	} while(0)

#define NAT_PCB_RMV(stack, pcbs_list, npcb) \
	do { \
		struct nat_pcb *___tmp; \
		NAT_LOCK(stack); \
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
		NAT_UNLOCK(stack); \
	} while(0)

/*--------------------------------------------------------------------------*/

#define MAX_TRACK_PROTO 256

static struct track_protocol *ip_ct_protos[MAX_TRACK_PROTO];

struct track_protocol * track_proto_find(u8_t protocol)
{
	return ip_ct_protos[protocol];
}

/*--------------------------------------------------------------------------*/

int nat_init(struct stack *stack)
{
	int i;

	/* global mapping, initialized once */
	if (ip_ct_protos[0] == NULL) {
		for (i = 0; i < MAX_TRACK_PROTO; i++)
			ip_ct_protos[i] = &default_track;
		ip_ct_protos[IP_PROTO_TCP]   = &tcp_track;
		ip_ct_protos[IP_PROTO_UDP]   = &udp_track;
		ip_ct_protos[IP_PROTO_ICMP4] = &icmp4_track;
		ip_ct_protos[IP_PROTO_ICMP]  = &icmp6_track;
	}

	/* Register hooks */

	stack->stack_nat = mem_malloc(sizeof(struct stack_nat));
	if (stack->stack_nat == NULL)
		return -ENOMEM;

	stack->stack_nat->nat_mutex    = sys_sem_new(1);
	/*unique_mutex = sys_sem_new(1);*/

	// FIX: remove this and bind ip/port in the stack
	nat_ports_init(stack);

	// Init rules lists
	stack->stack_nat->nat_in_rules  = NULL;
	stack->stack_nat->nat_out_rules = NULL;

	// Init pcbs lists
	stack->stack_nat->nat_active_pcbs    = NULL; 
	stack->stack_nat->nat_tentative_pcbs = NULL;

	/* Set protocol handlers */

	ip_conntrack_protocol_tcp_lockinit(stack);

	//uf_register_hook( & nat_prerouting_defrag);
	uf_register_hook(stack, & nat_prerouting_track);
	uf_register_hook(stack, & nat_prerouting_dnat);
	uf_register_hook(stack, & nat_input_confirm);
	uf_register_hook(stack, & nat_output_track);
	uf_register_hook(stack, & nat_postrouting_snat);
	uf_register_hook(stack, & nat_postrouting_confirm);

	LWIP_DEBUGF(NAT_DEBUG, ("%s: registered NAT hooks!\n", __func__));
	
	return ERR_OK;
}

void nat_free_pcb(struct nat_pcb *pcb);
int nat_shutdown(struct stack *stack)
{
	struct nat_pcb *nat_pcb_tmp; 
	if (stack->stack_nat == NULL)
		return -EINVAL;

	nat_rules_shutdown(stack);
	while (stack->stack_nat->nat_tentative_pcbs != NULL) {
		nat_pcb_tmp = stack->stack_nat->nat_tentative_pcbs;
		NAT_PCB_RMV(stack, &stack->stack_nat->nat_tentative_pcbs, nat_pcb_tmp);
		nat_free_pcb(nat_pcb_tmp);
	}
	while (stack->stack_nat->nat_active_pcbs != NULL) {
		nat_pcb_tmp = stack->stack_nat->nat_active_pcbs;
		NAT_PCB_RMV(stack, &stack->stack_nat->nat_active_pcbs, nat_pcb_tmp);
		nat_free_pcb(nat_pcb_tmp);
	}
	mem_free(stack->stack_nat);
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

void nat_session_get(struct nat_pcb *pcb);
void nat_session_put(struct nat_pcb *pcb);

void nat_pbuf_init(struct pbuf *p)
{
	p->nat.track = NULL;
	p->nat.dir   = 0;
	p->nat.info  = 0;
}

void nat_pbuf_get(struct pbuf *p)
{
}

void nat_pbuf_clone(struct pbuf *r, struct pbuf *p)
{
	if (p->nat.track == NULL) 
		return;

	nat_session_get(p->nat.track);

	r->nat.track = p->nat.track;
	r->nat.dir   = p->nat.dir;
	r->nat.info  = p->nat.info;
}

void nat_pbuf_put(struct pbuf *p)
{
	if (p->nat.track == NULL)
		return;

	nat_session_put(p->nat.track);

	p->nat.track = NULL;
	p->nat.dir   = 0;
	p->nat.info  = 0;
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
				tuple->src.proto.upi.icmp4.type, 
				tuple->src.proto.upi.icmp4.code)); 
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
	
	r = proto->nat_tuple_inverse(iface->stack, reply, tuple, type, nat_manip);

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

int tuple_create(struct ip_tuple *tuple, char  *iphdr, struct track_protocol *proto) 
{
	struct ip_hdr *ip6hdr;
	struct ip4_hdr *ip4hdr;
	u32_t  iphdrlen;

	bzero(tuple, sizeof(struct ip_tuple));

	ip6hdr = (struct ip_hdr *) iphdr;
	ip4hdr = (struct ip4_hdr *) iphdr;
	tuple->ipv = IPH_V(ip6hdr);
	if (tuple->ipv == 6) {
		LWIP_DEBUGF(NAT_DEBUG, ("%s: ipv6 \n", __func__ ));
		ip_addr_set (&tuple->src.ip , &(ip6hdr->src)  );
		ip_addr_set (&tuple->dst.ip , &(ip6hdr->dest) );

		tuple->src.proto.protonum = IPH_NEXTHDR(ip6hdr); 

		iphdrlen = IP_HLEN;
	}
	else if (tuple->ipv == 4) {
		LWIP_DEBUGF(NAT_DEBUG, ("%s: ipv4 \n", __func__ ));
		IP64_CONV (&tuple->src.ip , &(ip4hdr->src)  );
		IP64_CONV (&tuple->dst.ip , &(ip4hdr->dest) );

		tuple->src.proto.protonum = IPH4_PROTO(ip4hdr);

		iphdrlen = IPH4_HL(ip4hdr) * 4;
	} else {
		LWIP_DEBUGF(NAT_DEBUG, ("%s: IP version wrong \n", __func__ ));
		return -1; /* error */
	}

	return proto->tuple(tuple, iphdr + iphdrlen);
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

void nat_session_get(struct nat_pcb *pcb)
{
	pcb->refcount++;
}

void nat_session_put(struct nat_pcb *pcb)
{
	struct track_protocol *proto;
	struct stack *stack = pcb->stack;

	LWIP_DEBUGF(NAT_DEBUG, ("%s: pcb id=%d ref=%d\n", __func__, pcb->id, (int)pcb->refcount));
	pcb->refcount--;
	if (pcb->refcount == 0)  {
		LWIP_DEBUGF(NAT_DEBUG, ("\tid=%d ref now = 0 -> FREE\n", pcb->id));

		/* The tracking not confirmed this connection, remove it */
		if (!(pcb->status & TS_CONFIRMED)) {
			NAT_PCB_RMV(stack, &stack->stack_nat->nat_tentative_pcbs, pcb);
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
	struct stack *stack = pcb->stack;

	LWIP_DEBUGF(NAT_DEBUG, ("%s: session p=%p id=%d expired\n", __func__, pcb, pcb->id));
	LWIP_DEBUGF(NAT_DEBUG, ("\t")); dump_tuple(&pcb->tuple[CONN_DIR_ORIGINAL]); 

	NAT_PCB_RMV(stack, &stack->stack_nat->nat_active_pcbs, pcb);

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

int new_track(struct stack *stack, struct nat_pcb **newpcb, uf_hook_t hook, 
	struct pbuf **q, 
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
	else
		return -1;

	if (proto->new(stack, pcb, p, p->payload, iphdrlen) < 0) {
		LWIP_DEBUGF(NAT_DEBUG, ("%s: Unable to create new valid tracking.\n", __func__));

		nat_free_pcb(pcb);
		return -1;
	}

	*direction = CONN_DIR_ORIGINAL;
	*newpcb    = pcb;

	pcb->stack = stack;
	pcb->refcount = 1;

	pcb->next = NULL;
	/* Register this connection as a Tentative */
	NAT_PCB_REG(stack, &stack->stack_nat->nat_tentative_pcbs, pcb);

	return 1;
}

struct nat_pcb * conn_find_track(struct stack *stack, conn_dir_t *direction, struct ip_tuple * tuple )
{
	struct nat_pcb *pcb = NULL;

	/* Search in the table */
	NAT_LOCK(stack);
	for(pcb = stack->stack_nat->nat_active_pcbs; pcb != NULL; pcb = pcb->next)  {

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

	NAT_UNLOCK(stack);

	return pcb;
}

/*
 * Try to track the packet. If this packet doesn't belong to any existing connection
 * a new one will be created. On errors return -1.
 */
int conn_track(struct stack *stack, conn_dir_t *direction, uf_hook_t hook, 
	struct pbuf **q, struct netif *inif, struct netif *outif, struct track_protocol *proto)
{
	struct pbuf *p = * q;
	struct nat_pcb *tmppcb = NULL;
	struct ip_tuple tuple;  

	LWIP_DEBUGF(NAT_DEBUG, ("%s: start\n", __func__ ));

	/* Get the tuple of the packet */
///	if (tuple_create(&tuple, p, proto) < 0) {
	if (tuple_create(&tuple, p->payload, proto) < 0) {
		LWIP_DEBUGF(NAT_DEBUG, ("%s: unable to create tuple!\n", __func__ ));
		return -1;
	}

	dump_tuple (&tuple); 

	/* Find tracking informations */	
	tmppcb = conn_find_track(stack, direction, &tuple);
	if (tmppcb == NULL) {
		if (new_track(stack, &tmppcb, hook, q, &tuple, direction, proto) < 0) {
			LWIP_DEBUGF(NAT_DEBUG, ("%s: unable to create new track \n", __func__ ));
			return -1;
		}
		LWIP_DEBUGF(NAT_DEBUG, ("%s: NEW track %p id=%d!!\n", __func__, tmppcb, tmppcb->id));
	}

	p->nat.track = tmppcb;
	p->nat.dir   = *direction;

	/* It exists; we have (non-exclusive) reference. */
	if (*direction == CONN_DIR_REPLY) {
		p->nat.info = CT_ESTABLISHED + CT_IS_REPLY;
		LWIP_DEBUGF(NAT_DEBUG, ("%s: CT_ESTABLISHED + CT_IS_REPLY\n", __func__));
	} else {
		/* Once we've had two way comms, always ESTABLISHED. */
		if (p->nat.track->status & TS_SEEN_REPLY) {
			LWIP_DEBUGF(NAT_DEBUG, ("%s: CT_ESTABLISHED\n", __func__));
			p->nat.info = CT_ESTABLISHED;
		} else {
			LWIP_DEBUGF(NAT_DEBUG, ("%s: CT_NEW\n", __func__));
			p->nat.info = CT_NEW;
		}
	}

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

		if (ip_addr_islinkscope(&ip6hdr->dest))
			return 0;
		if (ip_addr_islinkscope(&ip6hdr->src))
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
/* HOOKS */
/*--------------------------------------------------------------------------*/

#if 0
uf_verdict_t  nat_defrag  (struct stack *stack, uf_hook_t hooknum, struct pbuf **q, struct netif *inif, struct netif *outif)
{
	struct pbuf *p = *q;
	struct ip4_hdr *ip4hdr;
	struct ip_hdr  *ip6hdr;
	u8_t proto;
	uf_verdict_t ret = UF_ACCEPT;

	LWIP_DEBUGF(NAT_DEBUG, ("%s: start\n", __func__));

	/* ASSERT! This is the first hook, no tracking info yet! */
	if (p->nat.track != NULL) {
		LWIP_DEBUGF(NAT_DEBUG, ("%s:  pcb not NULL!!!!!\n", __func__));
	}

	nat_pbuf_reset(p);


	/* Find transport protocol handler */
	ip6hdr = (struct ip_hdr *) p->payload;
	ip4hdr = (struct ip4_hdr *) p->payload;

	if (IPH_V(ip6hdr) == 4) {
	
		if ((IPH4_OFFSET(ip4hdr) & htons(IP_OFFMASK | IP_MF)) != 0) 
		{
#ifdef IPv4_FRAGMENTATION 
			LWIP_DEBUGF(NAT_DEBUG, ("%s: Packet is a fragment (id=0x%04x tot_len=%u len=%u MF=%u offset=%u)\n", __func__, 
				ntohs(IPH4_ID(ip4hdr)), p->tot_len, ntohs(IPH4_LEN(ip4hdr)), !!(IPH4_OFFSET(ip4hdr) & htons(IP_MF)), (ntohs(IPH4_OFFSET(ip4hdr)) & IP_OFFMASK)*8));

			p = ip4_reass(p);
#else
			ret = UF_DROP;
#endif
		} 
	}
	else 
	if (IPH_V(ip6hdr) == 6) {

		proto = IPH_NEXTHDR(ip6hdr);

		if (proto == IP6_NEXTHDR_FRAGMENT) {
#ifdef IPv6_FRAGMENTATION 
		        LWIP_DEBUGF(NAT_DEBUG, ("%s: Fragment Header\n", __func__));

		        struct ip6_fraghdr *fhdr = (struct ip6_fraghdr *) (p->payload + IP_HLEN);

		        p = ip6_reass(p, fhdr, NULL); 
#else
			ret = UF_DROP;
#endif
		}
	}
	else
		return UF_DROP;

	if (ret == UF_DROP) {
		LWIP_DEBUGF(NAT_DEBUG | 2, ("%s: IP packet dropped since it was fragmented\n",  __func__));
		IP_STATS_INC(ip.opterr);
		IP_STATS_INC(ip.drop);
		return UF_DROP;
	}

	if (p == NULL) {
		LWIP_DEBUGF(NAT_DEBUG,("%s: packet cached\n", __func__));
		return UF_STOLEN;
	}

	*q = p;

	return UF_ACCEPT;
}
#endif


uf_verdict_t nat_track (struct stack *stack, uf_hook_t hooknum, struct pbuf **q, struct netif *inif, struct netif *outif)
{
	struct pbuf *p = *q;
	struct pbuf *new_p;
	struct ip4_hdr *ip4hdr;
	struct ip_hdr  *ip6hdr;

	struct track_protocol *proto;

	conn_dir_t direction;
	uf_verdict_t verdict;

	LWIP_DEBUGF(NAT_DEBUG, ("%s: pbuf %d/%d\n", __func__, p->len, p->tot_len));

	/* ASSERT! This is the first hook, no tracking info yet! */
	if (p->nat.track != NULL) {
		LWIP_DEBUGF(NAT_DEBUG, ("%s:  pcb not NULL!!!!!\n", __func__));
	}

	nat_pbuf_reset(p);

	/*
	 *  We need a not-memory-fragmented packet for NAT manipulation.
	 */
	new_p = pbuf_make_writable(p);
	if (new_p == NULL) {
		LWIP_DEBUGF(NAT_DEBUG, ("%s:  unable to realloc pbuf!!!!!\n", __func__));
		return UF_ACCEPT;
	}

	LWIP_DEBUGF(NAT_DEBUG, ("%s: p now writable (old=%p new=%p)\n", __func__, p, new_p));

	*q = p = new_p;

	/* Find transport protocol handler */
	ip6hdr = (struct ip_hdr *) p->payload;
	ip4hdr = (struct ip4_hdr *) p->payload;
	if (IPH_V(ip6hdr) == 6) 
		// FIX: handle IPv6 extension headers ?
		proto = track_proto_find( IPH_NEXTHDR(ip6hdr) );
	else if (IPH_V(ip6hdr) == 4) 
		proto = track_proto_find(  IPH4_PROTO(ip4hdr) );
	else
		return UF_DROP;

	LWIP_DEBUGF(NAT_DEBUG, ("%s: proto = %d\n", __func__, IPH4_PROTO(ip4hdr) ));

	if (proto->error != NULL) {
		if (proto->error(stack, &verdict, p) < 0) {
			LWIP_DEBUGF(NAT_DEBUG, ("%s: proto error() -> %s\n", __func__, STR_VERDICT(verdict) ));
			return verdict;				
		}
	}

	if (!conn_need_track(p)) {
		LWIP_DEBUGF(NAT_DEBUG, ("%s: doesn't need track\n", __func__ ));
		return UF_ACCEPT;				
	}

	/* Find connection, if none is found a new will be created */	
	if (conn_track(stack, &direction, hooknum, q, inif, outif, proto ) < 0) {
		LWIP_DEBUGF(NAT_DEBUG, ("%s: tracking failed (not new valid connection)! DROP\n", __func__ ));
		return UF_DROP;
	}

	/* Update tracking informations */
	if (proto->handle(stack, &verdict, p, direction) < 0) {
		LWIP_DEBUGF(NAT_DEBUG, ("%s: drop this packet!!\n", __func__));
		/* Invalid: inverse of the return code tells
		 * the netfilter core what to do*/
		nat_session_put(p->nat.track);
		p->nat.track = NULL;
		return verdict;
	}

	if (direction == CONN_DIR_REPLY)
		p->nat.track->status |= TS_SEEN_REPLY;


	LWIP_DEBUGF(NAT_DEBUG, ("%s: pcb %p, dir=%s -> %s!!\n", __func__, 
		p->nat.track, STR_DIRECTIONNAME(direction), STR_VERDICT(verdict)));

	return verdict;
}

uf_verdict_t  nat_confirm (struct stack *stack, uf_hook_t hooknum, struct pbuf **q, struct netif *inif, struct netif *outif)
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

		NAT_PCB_RMV(stack, &stack->stack_nat->nat_tentative_pcbs, pcb);
		NAT_PCB_REG(stack, &stack->stack_nat->nat_active_pcbs, pcb);

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
	struct stack *stack = pcb->stack;

	if (hooknum == UF_IP_PRE_ROUTING) {
		list  = stack->stack_nat->nat_in_rules;
		netif = inif;
	} 
	else if (hooknum == UF_IP_POST_ROUTING) {
		list  = stack->stack_nat->nat_out_rules;
		netif = outif;
	}
	else {
		LWIP_DEBUGF(NAT_DEBUG, ("%s: wrong hooknum!\n",__func__));
		return -1;
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

void nat_modify_ip(nat_manip_t nat, char *p, struct ip_tuple *inverse, u8_t manip_innerproto)
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

	iphdr = (struct ip_hdr *) p;
	ip4hdr = (struct ip4_hdr *) p;

	if (inverse->ipv == 4) {
		/* Need to convert tuple's IP used for manipulations 
		   from 128 bit to 32 bit */
		if (nat == MANIP_DST) {
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
		if (nat == MANIP_SRC) {
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
		if (nat == MANIP_DST) {
			ip_addr_set( &old_ip6_addr, &iphdr->dest);
			ip_addr_set( &iphdr->dest, &inverse->src.ip);

			iphdr_new_changed_buf = (u8_t *) &iphdr->dest;
		}
		if (nat == MANIP_SRC) {
			ip_addr_set( &old_ip6_addr, &iphdr->src);
			ip_addr_set( &iphdr->src, &inverse->dst.ip);

			iphdr_new_changed_buf = (u8_t *) &iphdr->src;
		}

		iphdr_old_changed_buf = (u8_t *) &old_ip6_addr;
		iphdr_changed_buflen = 16;
	}

	/* Modify transport header */

	if (manip_innerproto) {

		proto = track_proto_find(inverse->src.proto.protonum);
	
		if (inverse->ipv == 6)      iphdrlen = IP_HLEN;
		else if (inverse->ipv == 4) iphdrlen = IPH4_HL(ip4hdr) * 4;
	
		proto->manip(nat, p, iphdrlen, inverse, 
			iphdr_new_changed_buf, 
			iphdr_old_changed_buf, 
			iphdr_changed_buflen);
	}
}

int icmp_reply_translation(struct pbuf *p, nat_manip_t nat_here);

uf_verdict_t  nat_perform   (struct stack *stack, uf_hook_t hooknum, struct pbuf **q, struct netif *inif, struct netif *outif)
{
	struct pbuf    *p = * q;
	struct ip_hdr  *ip6hdr;
	struct ip4_hdr *ip4hdr;
	u16_t proto;

	struct nat_pcb   *pcb;
	conn_dir_t       direction;
	struct ip_tuple  *tuple_inverse;

	nat_manip_t      nat_here; /* NAT to do in this hook */
	nat_manip_t      nat_todo; /* NAT to do on the connection */


	LWIP_DEBUGF(NAT_DEBUG, ("%s: start %s!\n", __func__, STR_HOOKNAME(hooknum)));

	if (p->nat.track == NULL) {
		LWIP_DEBUGF(NAT_DEBUG, ("%s: no track for this packet!!\n", __func__));
		return UF_ACCEPT;
	}


	pcb = p->nat.track;
	direction = p->nat.dir;

        /* 
	 * Check what to do...
	 */

	nat_here = HOOK2MANIP(hooknum);
	
	ip6hdr = (struct ip_hdr *) p->payload;
	ip4hdr = (struct ip4_hdr *) p->payload;
	if (IPH_V(ip6hdr) == 6)       proto = IPH_NEXTHDR(ip6hdr) ;
	else if (IPH_V(ip6hdr) == 4)  proto = IPH4_PROTO(ip4hdr) ;
	else
		return UF_DROP;

	switch (p->nat.info) {
		case CT_RELATED:
		case CT_RELATED + CT_IS_REPLY:
			LWIP_DEBUGF(NAT_DEBUG, ("%s: is RELATED || RELATED+REPLY \n", __func__ ));
			if (proto == IP_PROTO_ICMP || proto == IP_PROTO_ICMP4) {
				if (icmp_reply_translation(p, nat_here) <= 0) 
					return UF_DROP;
				else
					return UF_ACCEPT;
			}
			/* Fall thru... (Only ICMPs can be IP_CT_IS_REPLY) */
		case CT_NEW:

			LWIP_DEBUGF(NAT_DEBUG, ("%s: is NEW \n", __func__ ));

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

			break;
	
		default:
			LWIP_DEBUGF(NAT_DEBUG, ("%s: is ESTABLISHED or other... \n", __func__ ));
			/* ESTABLISHED: do NAT */
			break;

	}

#if 0
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
#endif

	/* No NAT? No party */
	if (pcb->nat_type == NAT_NONE) {
		LWIP_DEBUGF(NAT_DEBUG, ("%s: no NAT to do.\n", __func__ ));
		return UF_ACCEPT;
	}

	/* How tuples will be manipulated by Hooks
         *
	 * NAT  | DIRECTION | --> PREROUTING    ----->   POSTROUTING -->
	 *------|-----------|------------------------------------------
	 *      | ORIGINAL  |   [x,y] -> x,N (D)            - 
	 * DNAT |           |
	 *      | REPLY     |         -                [N,x] -> y,x (S)
	 *------|-----------|------------------------------------------
	 *      | ORIGINAL  |         -                [x,y] -> N,y (S)
	 * SNAT |           |
	 *      | REPLY     |   [y,N] -> y,x (D)            -
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


	/* Manipulation's type depends on hook and packet direction */

	nat_todo = NAT2MANIP(pcb->nat_type);

	if (direction == CONN_DIR_REPLY) {
        	nat_todo = ! nat_todo;
	}

	/* Manipulation on this packet is needed in this hook? */
	if (nat_todo == nat_here) {

		nat_modify_ip(nat_todo, p->payload, tuple_inverse, 1);

		LWIP_DEBUGF(NAT_DEBUG, ("%s: NATed packet !\n", __func__));
		ip_debug_print(NAT_DEBUG, p);
		LWIP_DEBUGF(NAT_DEBUG, ("%s: END.\n", __func__));
	}
	else {
		LWIP_DEBUGF(NAT_DEBUG, ("%s: no NAT to do in this hook\n", __func__ ));

	}

	return UF_ACCEPT;
}


int icmp_reply_translation(struct pbuf *p, nat_manip_t nat_here)
{
	struct {
		struct icmp_echo_hdr icmp;
		union {
			struct ip4_hdr ip4hdr;
			struct ip_hdr  ip6hdr;
		} uip;
	} *inside;


	conn_dir_t       direction;
	struct ip4_hdr *ip4hdr;
	struct ip_hdr *ip6hdr;
	int hdrlen;

	nat_manip_t      nat_todo; /* NAT to do on the connection */

	struct ip_tuple *inverse;
	struct ip_tuple  inner_inverse;

	struct nat_pcb *pcb = p->nat.track;

	direction = p->nat.dir;

	ip6hdr = (struct ip_hdr *)  p->payload;
	ip4hdr = (struct ip4_hdr *) p->payload;
	if (IPH4_V(ip4hdr) == 4)  hdrlen = IPH4_HL(ip4hdr) * 4;
	else                      hdrlen = IP_HLEN;

	inside = (void *)(p->payload + hdrlen);


	if (p->nat.info == CT_RELATED || p->nat.info == CT_RELATED + CT_IS_REPLY) {
		LWIP_DEBUGF(NAT_DEBUG, ("%s: Strange, not RELATED or RELATED+REPLY\n", __func__));
		return -1;
	}

	/* 
	 *  Get tuples for translations 
	 */	
        /* We use the tuple in the other direction for NAT. See above */
	if (direction == CONN_DIR_ORIGINAL) 
		inverse = &pcb->tuple[CONN_DIR_REPLY];
	else
		inverse = &pcb->tuple[CONN_DIR_ORIGINAL];

	if (tuple_inverse( &inner_inverse, inverse ) < 0) {
		LWIP_DEBUGF(NAT_DEBUG, ("%s: Strange, can't get tuple inverse!\n", __func__));
		return -1;
	}


	/*
	 *
	 */
	nat_todo = NAT2MANIP(pcb->nat_type);

	if (direction == CONN_DIR_REPLY) {
        	nat_todo = ! nat_todo;
	}

	if (nat_todo != nat_here)
		return 1;

	/*
	 * Change Inner packet
	 */
	nat_modify_ip(!nat_todo, (char *) &inside->uip.ip4hdr, &inner_inverse, 1);


	LWIP_DEBUGF(NAT_DEBUG, ("%s: NATed INNER PACKET !\n", __func__));
	ip_debug_print(NAT_DEBUG, p);

	/// CHECKSUM?

	/*
	 * Change Packet hearde
	 */
	nat_modify_ip(nat_todo, p->payload, inverse, 0);

	LWIP_DEBUGF(NAT_DEBUG, ("%s: NATed PACKET !\n", __func__));
	ip_debug_print(NAT_DEBUG, p);


	LWIP_DEBUGF(NAT_DEBUG, ("%s: END !\n", __func__));

	return 1;
}

#endif /* LWIP_NAT */


