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

#ifndef __LWIP_ROUTE_H__
#define __LWIP_ROUTE_H__

#include "lwip/ip_addr.h"
#include "lwip/err.h"

#if 0
#ifdef IPv6_PMTU_DISCOVERY
struct pmtu_info;
#endif
#endif

struct netif;
struct ip_route_list {
	struct ip_route_list *next;
	struct ip_addr addr;
	struct ip_addr netmask;
	struct ip_addr nexthop;
	struct netif *netif;
	char flags;

#if 0
#ifdef IPv6_PMTU_DISCOVERY
    /* List of Per-host Path MTU for each destination throw this route */
	struct pmtu_info *pmtu_list;
#endif
#endif

};

/* routing table. Please use it read-only! */
extern struct ip_route_list *ip_route_head;

void ip_route_list_init();

err_t ip_route_list_add(struct ip_addr *addr, struct ip_addr *netmask, struct ip_addr *nexthop, struct netif *netif, int flags);

err_t ip_route_list_del(struct ip_addr *addr, struct ip_addr *netmask, struct ip_addr *nexthop, struct netif *netif, int flags);

err_t ip_route_findpath(struct ip_addr *addr, struct ip_addr **pnexthop, struct netif **pnetif, int *flags);

err_t ip_route_list_delnetif(struct netif *netif);


/* Select the source address for the given destination IP "dst" and the outgoing interface "outif"  */
struct ip_addr_list * ip_route_ipv6_select_source(struct netif *outif, struct ip_addr *dst);




/* added by Diego Billi */
#if 0
#ifdef IPv6_PMTU_DISCOVERY

/* PMTU's timer timeout interval in msec (1 second) */
#define PMTU_TMR_INTERVAL   1000 /*(10 * 1000)*/


/* Path MTU Destination information */
struct pmtu_info {
	struct pmtu_info *next;

	struct ip_addr dest;
    struct ip_addr src;
	u8_t   tos; /* not used yet, use 0 */
	u16_t  pmtu;

	/* time counter (in seconds) for garbage collection */
	u32_t   expire_time; 

	u32_t  op_timeout;     /* timeout to the next operation */
	u8_t   flags;
};

#define PMTU_EXPIRE_TIMEOUT   10       
#define PMTU_NEVER_EXPIRE     0xffff   

#define PMTU_FLAG_INCREASE    0x01
#define PMTU_FLAG_DECREASE    0x02

#define PMTU_TOS_NONE         0

/* Timeout in seconds before MTU decrease should be done. 
 * From RFC: once this timer expires and a larger MTU is 
 * attempted, the timeout can be set to a much smaller 
 * value (say, 2 minutes).
 */
#define PMTU_DECREASE_TIMEOUT   5  /*(2 * 60)*/

/* Timeout in seconds before MTU increase should be done
 * from RFC: after the PTMU estimate is decreased, the 
 * timeout should be set to 10 minutes; 
 */
#define PMTU_INCREASE_TIMEOUT  10  /* (10 * 60) */


/* Add new Path MTU informations for the given destinatioin. Used by ICMP system */
err_t ip_pmtu_add(struct ip_addr *src, struct ip_addr *dest, u8_t tos, u16_t mtu);

/* Find the extimated Path MTU for the given destination and stores it in 'mtu' */
err_t ip_pmtu_getmtu(struct ip_addr *dest, struct ip_addr *src, u8_t tos,u16_t *mtu);

/* Decrease Path MTU for the given destiantion. Used by ICMP system.
 * NOTE: Increase of Path MTU is done internaly by PMTU Discovery algorithm. 
 */
err_t ip_pmtu_decrease(struct ip_addr *dest, struct ip_addr *src, u8_t tos, u16_t new_mtu);

#endif /* IPv6_PMTU_DISCOVERY */
#endif


#endif /* LWIP_ROUTE_H */
