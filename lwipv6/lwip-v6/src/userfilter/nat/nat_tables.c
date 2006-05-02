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

#include <string.h>

#include "lwip/debug.h"
#include "lwip/sys.h"
#include "lwip/ip.h"

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

int  getnew_range(u32_t *val, unsigned char *table, u32_t start, u32_t range_min, u32_t range_max)
{
	int i;
	unsigned int r = 0;

	range_min -= start;
	range_max -= start;

	for (i=range_min; i < range_max; i++)
		if (table[ i/8 ]  &  (0x01 << (i % 8)))
			break;

	if (i < range_max) {
		*val = r + start;
		return 1;
	}

	return 0;
}

int  nat_ports_getnew(int protocol, u32_t *port, u32_t min, u32_t max)
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


u16_t nat_ports_free(int protocol, u32_t port)
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


/*
u16_t  nat_ports_getnew(void)
{
	int i=1;
	unsigned int r = 0;

	for (; i < NAT_PORTS_TABLE_SIZE; i++)
	{
		// if all ports in this "block" are used (0x00) go to next
		if (! nat_ports_table[i])
			continue;

		if (nat_ports_table[i] & 0x01) { nat_ports_table[i] &= ~0x01  ; r = ((8*i)+0); break; }
		if (nat_ports_table[i] & 0x02) { nat_ports_table[i] &= ~0x02  ; r = ((8*i)+1); break; }
		if (nat_ports_table[i] & 0x04) { nat_ports_table[i] &= ~0x04  ; r = ((8*i)+2); break; }
		if (nat_ports_table[i] & 0x08) { nat_ports_table[i] &= ~0x08  ; r = ((8*i)+3); break; }
		if (nat_ports_table[i] & 0x10) { nat_ports_table[i] &= ~0x10  ; r = ((8*i)+4); break; }
		if (nat_ports_table[i] & 0x20) { nat_ports_table[i] &= ~0x20  ; r = ((8*i)+5); break; }
		if (nat_ports_table[i] & 0x40) { nat_ports_table[i] &= ~0x40  ; r = ((8*i)+6); break; }
		if (nat_ports_table[i] & 0x80) { nat_ports_table[i] &= ~0x80  ; r = ((8*i)+7); break; }
	}

	return (r + NAT_MIN_PORT);
}

u16_t nat_ports_free(u16_t port)
{
	nat_ports_unset(port);
	return 1;
}

*/

//#define NAT_MIN_PORT          49152
//#define NAT_MAX_PORT          65535
//#define NAT_MAX_PORTS         (NAT_MAX_PORT - NAT_MIN_PORT)     
//#define NAT_PORTS_TABLE_SIZE  (NAT_MAX_PORTS / 8)

//#define nat_ports_isset(n)   !((nat_ports_table[((n)-NAT_MIN_PORT)/8] >> (((n)-NAT_MIN_PORT)%8)) & 0x01)
//#define nat_ports_set(n)      ( nat_ports_table[((n)-NAT_MIN_PORT)/8] &= ~(1<<(((n)-NAT_MIN_PORT)%8))    )
//#define nat_ports_unset(n)    ( nat_ports_table[((n)-NAT_MIN_PORT)/8] |=  (1<<(((n)-NAT_MIN_PORT)%8))    )

//
// ATTENTION: all these function works with host byte alignment
//
//extern unsigned char nat_ports_table[NAT_PORTS_TABLE_SIZE];


//unsigned char nat_ports_table[NAT_PORTS_TABLE_SIZE];



#if 0


u16_t  getnew(unsigned char *table, u32_t size)
{
	int i;
	unsigned int r = 0;

	for (i=1; i < size; i++)
	{
		// if all ports in this "block" are used (0x00) go to next
		if (! table[i])
			continue;

		if (table[i] & 0x01) { table[i] &= ~0x01; r = ((8*i)+0); break; }
		if (table[i] & 0x02) { table[i] &= ~0x02; r = ((8*i)+1); break; }
		if (table[i] & 0x04) { table[i] &= ~0x04; r = ((8*i)+2); break; }
		if (table[i] & 0x08) { table[i] &= ~0x08; r = ((8*i)+3); break; }
		if (table[i] & 0x10) { table[i] &= ~0x10; r = ((8*i)+4); break; }
		if (table[i] & 0x20) { table[i] &= ~0x20; r = ((8*i)+5); break; }
		if (table[i] & 0x40) { table[i] &= ~0x40; r = ((8*i)+6); break; }
		if (table[i] & 0x80) { table[i] &= ~0x80; r = ((8*i)+7); break; }
	}

	return r;
}


int  nat_ports_getnew(int protocol, u32_t *port)
{
	u32_t r;

	switch (protocol) {
        	case IP_PROTO_ICMP4:
		case IP_PROTO_ICMP:
			r = getnew( &nat_icmp_table[0], ICMP_PORTS_TABLE_SIZE) + ICMP_MIN_PORT;
			break;
		case IP_PROTO_TCP:
			r = getnew( &nat_tcp_table[0], TCP_PORTS_TABLE_SIZE) +	TCP_MIN_PORT;
			break;
		case IP_PROTO_UDP:
		case IP_PROTO_UDPLITE:
			r = getnew(  &nat_udp_table[0], UDP_PORTS_TABLE_SIZE) +	UDP_MIN_PORT;
			break;
		default:
			//FIX:
			break;
	}
	return r;
}


#endif
