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

#ifndef __NAT_RULES_H__
#define __NAT_RULES_H__

// Max number of rule the stack can handle
#ifndef MEMP_NUM_NAT_RULE
#define MEMP_NUM_NAT_RULE   10
#endif

/*
 * Manipulation range. FIX: up to now, only ipmin and protomin are used!
 */
struct manip_range {

	u8_t flag;  /* values to use */
#define MANIP_RANGE_IP    0x01
#define MANIP_RANGE_PROTO 0x02

	struct ip_addr ipmin, ipmax;

	struct proto_range {
		u16_t value;
	} protomin, protomax;
	
};

struct nat_rule 
{
	struct nat_rule  *next; // For the linked list
		
	//
	// Matching options
	//
	struct netif *iface;    // Interface 

	//
	// Match protocol
	//
	u16_t protocol; 

#define IGNORE_PROTO  0xFFFF
#define IS_IGNORE_PROTO(proto) ((proto) == IGNORE_PROTO)
	
	//
	// Match IP
	//
	u8_t ipv;
	struct ip_addr src_ip; 
	struct ip_addr dst_ip; 
		
#define SET_IGNORE_IP(ipaddr)     IP6_ADDR((ipaddr), 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000)
#define IS_IGNORE_IP(ipaddr)      ((ipaddr)->addr[3] == 0x0000 && (ipaddr)->addr[2] == 0x0000 && (ipaddr)->addr[0] == 0x0000 && (ipaddr)->addr[1] == 0x0000)
	
	//
	// Match TCP/UDP
	//
	u16_t src_port;
	u16_t dst_port;
	
#define IGNORE_PORT 0x0000
#define IS_IGNORE_PORT(p) ((p) == IGNORE_PORT)
	
	// 
	// NAT targets
	//
	nat_type_t  type;       
	struct manip_range manip;
};


// PREROUTING rules
extern struct nat_rule *nat_in_rules;
// POSTROUTING rules
extern struct nat_rule *nat_out_rules;


// Malloc a new nat_rule structure
struct nat_rule * nat_new_rule(void);

void nat_free_rule(struct nat_rule *rule);

int nat_add_rule(int ipv, nat_table_t where, struct nat_rule *new_rule);	
struct nat_rule * nat_del_rule(struct nat_rule **list, int pos);
	
INLINE int nat_match_rule(struct nat_rule *rule, struct netif *iface, struct ip_tuple *tuple);

#endif 


///extern struct nat_rule *nat6_in_rules;
///extern struct nat_rule *nat6_out_rules;

#endif

