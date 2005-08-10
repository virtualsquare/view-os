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

struct netif;
struct ip_route_list {
	struct ip_route_list *next;
	struct ip_addr addr;
	struct ip_addr netmask;
	struct ip_addr nexthop;
	struct netif *netif;
	char flags;
};

void ip_route_list_init();

err_t ip_route_list_add(struct ip_addr *addr, struct ip_addr *netmask, struct ip_addr *nexthop, struct netif *netif, int flags);

err_t ip_route_list_del(struct ip_addr *addr, struct ip_addr *netmask, struct ip_addr *nexthop, struct netif *netif, int flags);

err_t ip_route_findpath(struct ip_addr *addr, struct ip_addr **pnexthop, struct netif **pnetif, int *flags);

err_t ip_route_list_delnetif(struct netif *netif);


#endif
