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

#include "lwip/opt.h"

#if LWIP_USERFILTER && LWIP_NAT

#include <string.h>

#include "lwip/debug.h"
#include "lwip/sys.h"
#include "lwip/ip.h"

#include "lwip/netif.h"
#include "lwip/userfilter.h"

#include "lwip/nat/nat_tables.h"

#ifndef NATPORTS_DEBUG
#define NATPOSTS_DEBUG DBG_OFF
#endif

/*--------------------------------------------------------------------------*/

#define TCP_MIN_PORT          0
#define TCP_MAX_PORT          65535
#define TCP_MAX_PORTS         (TCP_MAX_PORT - TCP_MIN_PORT)     
#define TCP_PORTS_TABLE_SIZE  (TCP_MAX_PORTS / 8)

unsigned char nat_tcp_table[TCP_PORTS_TABLE_SIZE];

/*--------------------------------------------------------------------------*/

#define UDP_MIN_PORT          0
#define UDP_MAX_PORT          65535
#define UDP_MAX_PORTS         (UDP_MAX_PORT - UDP_MIN_PORT)     
#define UDP_PORTS_TABLE_SIZE  (UDP_MAX_PORTS / 8)

unsigned char nat_udp_table[UDP_PORTS_TABLE_SIZE];

/*--------------------------------------------------------------------------*/

#define ICMP_MIN_PORT          0
#define ICMP_MAX_PORT          65535
#define ICMP_MAX_PORTS         (ICMP_MAX_PORT - ICMP_MIN_PORT)     
#define ICMP_PORTS_TABLE_SIZE  (ICMP_MAX_PORTS / 8)

unsigned char nat_icmp_table[ICMP_PORTS_TABLE_SIZE];

/*--------------------------------------------------------------------------*/

void nat_ports_init(void)
{
	memset(nat_tcp_table , 0xff, TCP_PORTS_TABLE_SIZE);
	memset(nat_udp_table , 0xff, UDP_PORTS_TABLE_SIZE);
	memset(nat_icmp_table, 0xff, ICMP_PORTS_TABLE_SIZE);
}

/*--------------------------------------------------------------------------*/

int  getnew_range(u16_t *val, unsigned char *table, u32_t start, u32_t range_min, u32_t range_max)
{
	int i;

	range_min -= start;
	range_max -= start;
	

	for (i=range_min; i < range_max; i++)
		if (table[ i/8 ]  &  (0x01 << (i % 8)))
			break;

	if (i < range_max) {
	
		table[i/8] &= ~(0x01 << (i%8));
		*val = i + start;
		
//		printf("NEW PORT ID=%d (%d)\n", *val, htons(*val));
		
		return 1;
	}

	return 0;
}

int  nat_ports_getnew(int protocol, u16_t *port, u32_t min, u32_t max)
{
	u32_t r;

	switch (protocol) {
        	case IP_PROTO_ICMP4:
		case IP_PROTO_ICMP:
			//r = getnew( &nat_icmp_table[0], ICMP_PORTS_TABLE_SIZE) + ICMP_MIN_PORT;
			r = getnew_range(port,  &nat_icmp_table[0], ICMP_MIN_PORT, min, max);
			break;
		case IP_PROTO_TCP:
			//r = getnew( &nat_tcp_table[0], TCP_PORTS_TABLE_SIZE) +	TCP_MIN_PORT;
			r = getnew_range(port,  &nat_tcp_table[0], TCP_MIN_PORT, min, max);
			break;
		case IP_PROTO_UDP:
			//r = getnew(  &nat_udp_table[0], UDP_PORTS_TABLE_SIZE) +	UDP_MIN_PORT;
			r = getnew_range(port,  &nat_udp_table[0], UDP_MIN_PORT, min, max);
			break;
		default:
			//FIX:
			break;
	}
	return r;
}

/*--------------------------------------------------------------------------*/

#define nat_ports_unset(table, min, n)    ( (table)[((n)-(min))/8] |=  (1<<(((n)-(min))%8))    )


u16_t nat_ports_free(int protocol, u16_t port)
{
	switch (protocol) {
        	case IP_PROTO_ICMP4:
		case IP_PROTO_ICMP:
			nat_ports_unset(nat_icmp_table, ICMP_MIN_PORT, port);
			break;
		case IP_PROTO_TCP:
			nat_ports_unset(nat_tcp_table, TCP_MIN_PORT, port);
			break;
		case IP_PROTO_UDP:
			nat_ports_unset(nat_udp_table, UDP_MIN_PORT, port);
			break;
		default:
			//FIX:
			break;
	}
	return 1;
}


#endif /* LWIP_NAT */


