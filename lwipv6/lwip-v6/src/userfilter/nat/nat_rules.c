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

#include <stdlib.h>

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

#include "lwip/netif.h"
#include "lwip/userfilter.h"

#include "lwip/nat/nat.h"
#include "lwip/nat/nat_rules.h"


#ifndef NATRULE_DEBUG
#define NATRULE_DEBUG DBG_OFF
#endif


/*--------------------------------------------------------------------------*/
/* Rules functions */
/*--------------------------------------------------------------------------*/

#define NAT_RULE_REG(rules_list, nrule) \
	do { \
		(nrule)->next = *(rules_list); \
		*(rules_list) = (nrule); \
	} while(0)

#define NAT_RULE_APPEND(rules_list, nrule) \
	do { \
		struct nat_rule *nat_tmp_rule; \
		if (*(rules_list) != NULL) { \
			nat_tmp_rule = *(rules_list); \
			while (nat_tmp_rule->next != NULL) \
				nat_tmp_rule = nat_tmp_rule->next; \
			nat_tmp_rule->next = (nrule); \
		} \
		else { \
			(nrule)->next = NULL; \
			*(rules_list) = (nrule); \
		} \
	} while(0)

#define NAT_RULE_RMV(pcbs_list, npcb) \
	do { \
		if(*pcbs_list == npcb) { \
			*pcbs_list = (*pcbs_list)->next; \
		} else \
			struct nat_rule *nat_tmp_rule; \
			for(nat_tmp_rule = *pcbs_list; nat_tmp_rule != NULL; nat_tmp_rule = nat_tmp_rule->next) { \
				if (nat_tmp_rule->next != NULL && nat_tmp_rule->next == npcb) { \
				    nat_tmp_rule->next = npcb->next; \
					break; \
				} \
			} \
		npcb->next = NULL; \
	} while(0)

#define NAT_RULE_FIND(rules_list, netif, result) do {\
		struct nat_rule *nat_tmp_rule; \
		for(nat_tmp_rule = *(rules_list); nat_tmp_rule != NULL; nat_tmp_rule = nat_tmp_rule->next) { \
			if(nat_tmp_rule->iface == (netif)) { \
				* (result) = nat_tmp_pcb; \
				break; \
			} \
		} \
	} while(0)

//
// Returns a new nat_rule structure.
// Returns NULL if no more nat_rule can be created.
//
struct nat_rule * nat_new_rule(void)
{
	struct nat_rule *r;

	r = memp_malloc(MEMP_NAT_RULE);
	if (r == NULL)
		return NULL;

	bzero(r, sizeof(struct nat_rule)); // clean all

	return r;
}

void nat_free_rule(struct nat_rule *rule)
{
	memp_free(MEMP_NAT_RULE, rule);
}

int  nat_add_rule(struct stack *stack, int ipv, nat_table_t where, struct nat_rule *new_rule)
{
	if (stack->stack_nat == NULL)
		return -1;
	// MASQUARADE e SNAT can be used only on POSTROUTING
	if ((where == NAT_POSTROUTING) &&
		((new_rule->type == NAT_MASQUERADE) || (new_rule->type == NAT_SNAT)) )
	{
		NAT_RULE_APPEND(&stack->stack_nat->nat_out_rules, new_rule);
		return 1;
	}
	else
	// DNAT can be used only on PREROUTING
	if ((where == NAT_PREROUTING) && (new_rule->type == NAT_DNAT)) 
	{
		NAT_RULE_APPEND(&stack->stack_nat->nat_in_rules, new_rule);
		return 1;
	}

	return 0;
}

// Remove from 'list' the rule at position 'pos'.
// Returns the pointer to the removed rule.
struct nat_rule * nat_del_rule_raw(struct nat_rule **list, int pos)
{
	int i=0;
	struct nat_rule *removed = NULL;
	struct nat_rule *p;

	// list empty, skip
	if (*list != NULL) {

		if (pos == 0) {
			removed = *list;
			*list = (*list)->next; 
		} else 
			for(p = *list; p != NULL; p = p->next, i++) { 
				if ((p->next != NULL) && ((i+1) == pos)) { 
					removed = p->next;
					p->next = removed->next; 
					break; 
				} 
			} 

		if (removed != NULL) {
			removed->next = NULL; 
			return removed;
		}
	}

	return NULL;     
}

struct nat_rule * nat_del_rule(struct stack *stack, nat_table_t where, int pos)
{
	if (stack->stack_nat == NULL)
		return NULL;
	if (where == NAT_POSTROUTING)
		return nat_del_rule_raw(&stack->stack_nat->nat_out_rules, pos);
	else 
	if (where == NAT_PREROUTING)
		return nat_del_rule_raw(&stack->stack_nat->nat_in_rules, pos);
	else
		return NULL;
}

void nat_rules_shutdown(struct stack *stack)
{
	while (stack->stack_nat->nat_out_rules != NULL) 
		nat_free_rule(nat_del_rule_raw(&stack->stack_nat->nat_out_rules, 0));
	while (stack->stack_nat->nat_in_rules != NULL) 
		nat_free_rule(nat_del_rule_raw(&stack->stack_nat->nat_in_rules, 0));
}

int nat_match_rule(struct rule_matches *matches, struct netif *iface, struct ip_tuple *tuple)
{
	if (matches->iface != NULL) {
		if (matches->iface != iface) {
			LWIP_DEBUGF(NATRULE_DEBUG, ("%s: wrong interface.\n", __func__));
			return 0;
		}
	}

	if (matches->ipv != tuple->ipv) {
		LWIP_DEBUGF(NATRULE_DEBUG, ("%s: wrong IP version (%d, %d)\n", __func__,matches->ipv, tuple->ipv));
		return 0;
	}

	if (! IS_IGNORE_IP(&matches->src_ip)) 
		if (ip_addr_cmp(&matches->src_ip, &tuple->src.ip) != 0) {
			LWIP_DEBUGF(NATRULE_DEBUG, ("%s: wrong src IP\n", __func__));
			return 0;
		}

	if (! IS_IGNORE_IP(&matches->dst_ip)) 
		if (ip_addr_cmp(&matches->dst_ip, &tuple->dst.ip) != 0) {
			LWIP_DEBUGF(NATRULE_DEBUG, ("%s: wrong dst IP\n", __func__));
			return 0;
		}

	if (! IS_IGNORE_PROTO(matches->protocol)) 
		if (matches->protocol != tuple->src.proto.protonum) {
			LWIP_DEBUGF(NATRULE_DEBUG, ("%s: wrong proto\n", __func__));
			return 0;
		}

	if (tuple->src.proto.protonum == IP_PROTO_TCP) {
		
		if (! IS_IGNORE_PORT(matches->src_port))
			if (matches->src_port != tuple->src.proto.upi.tcp.port) {
				LWIP_DEBUGF(NATRULE_DEBUG, ("%s: wrong src port\n", __func__));
				return 0;
			}
			
		if (! IS_IGNORE_PORT(matches->dst_port))
			if (matches->dst_port != tuple->dst.proto.upi.tcp.port) {
				LWIP_DEBUGF(NATRULE_DEBUG, ("%s: wrong dst port\n", __func__));
				return 0;
			}
	}

	if (tuple->src.proto.protonum == IP_PROTO_UDP) {

		if (! IS_IGNORE_PORT(matches->src_port))
			if (matches->src_port != tuple->src.proto.upi.udp.port) {
				LWIP_DEBUGF(NATRULE_DEBUG, ("%s: wrong src port\n", __func__));
				return 0;
			}
			
		if (! IS_IGNORE_PORT(matches->dst_port))
			if (matches->dst_port != tuple->dst.proto.upi.udp.port) {
				LWIP_DEBUGF(NATRULE_DEBUG, ("%s: wrong dst port\n", __func__));
				return 0;
			}
	}
	
	return 1;
}

#endif


