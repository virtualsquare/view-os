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

//#ifdef LWIP_NAT
#if LWIP_USERFILTER && LWIP_NAT

#ifndef __NAT_RULES_H__
#define __NAT_RULES_H__

// Max number of rule the stack can handle
#ifndef MEMP_NUM_NAT_RULE
#define MEMP_NUM_NAT_RULE   100
#endif

/*
 * Manipulation range. FIX: up to now, only ipmin and protomin are used!
 */
struct manip_range {

	u8_t flag;  /* values to use */
#define MANIP_RANGE_IP    0x01
#define MANIP_RANGE_PROTO 0x02

	/* IP range */
	struct ip_addr ipmin, ipmax;

	/* TCP/UDP port range */
	struct proto_range {
		u16_t value;
	} protomin, protomax;
	
};

//
// Matching options
//
struct rule_matches {
	struct netif *iface;    // Interface 

	// Match IP
	u8_t ipv;
	struct ip_addr src_ip; 
	struct ip_addr dst_ip; 
#define SET_IGNORE_IP(ipaddr)     IP6_ADDR((ipaddr), 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000)
#define IS_IGNORE_IP(ipaddr)      ((ipaddr)->addr[3] == 0x0000 && (ipaddr)->addr[2] == 0x0000 && (ipaddr)->addr[0] == 0x0000 && (ipaddr)->addr[1] == 0x0000)

	// Transport protocol (TCP/UDP)
	u16_t protocol; 
#define IGNORE_PROTO  0xFFFF
#define IS_IGNORE_PROTO(proto) ((proto) == IGNORE_PROTO)
	
	// Match port TCP/UDP
	u16_t src_port;
	u16_t dst_port;
#define IGNORE_PORT 0x0000
#define IS_IGNORE_PORT(p) ((p) == IGNORE_PORT)
};

struct nat_rule 
{
	struct nat_rule  *next; // For the linked list

	struct rule_matches  matches;		

	nat_type_t  type;       
	struct manip_range manip;
};

/*--------------------------------------------------------------------------*/
/* Functions */
/*--------------------------------------------------------------------------*/

// Malloc a new nat_rule structure
struct nat_rule * nat_new_rule(void);

void nat_free_rule(struct nat_rule *rule);

int nat_add_rule(struct stack *stack, int ipv, nat_table_t where, struct nat_rule *new_rule);	
struct nat_rule * nat_del_rule(struct stack *stack, nat_table_t where, int pos);
	
/* Returns 1 if "rule" matches with the tuple "tuple" */
int nat_match_rule(struct rule_matches *matches, struct netif *iface, struct ip_tuple *tuple);

void nat_rules_shutdown(struct stack *stack);

#endif 

#endif


