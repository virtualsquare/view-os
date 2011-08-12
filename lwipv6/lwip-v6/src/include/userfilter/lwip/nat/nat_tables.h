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

#ifndef __NAT_PORTS_H__
#define __NAT_PORTS_H__

/*--------------------------------------------------------------------------*/

#define TCP_MIN_PORT          0
#define TCP_MAX_PORT          65535
#define TCP_MAX_PORTS         (TCP_MAX_PORT - TCP_MIN_PORT)     
#define TCP_PORTS_TABLE_SIZE  (TCP_MAX_PORTS / 8)

#define UDP_MIN_PORT          0
#define UDP_MAX_PORT          65535
#define UDP_MAX_PORTS         (UDP_MAX_PORT - UDP_MIN_PORT)     
#define UDP_PORTS_TABLE_SIZE  (UDP_MAX_PORTS / 8)

#define ICMP_MIN_PORT          0
#define ICMP_MAX_PORT          65535
#define ICMP_MAX_PORTS         (ICMP_MAX_PORT - ICMP_MIN_PORT)     
#define ICMP_PORTS_TABLE_SIZE  (ICMP_MAX_PORTS / 8)

/*--------------------------------------------------------------------------*/

void nat_ports_init(struct stack *stack);

int  nat_ports_getnew(struct stack *stack, int protocol, u16_t *port, u32_t min, u32_t max);

u16_t nat_ports_free(struct stack *stack, int protocol, u16_t val);

#endif /* NAT_PORTS */

#endif

