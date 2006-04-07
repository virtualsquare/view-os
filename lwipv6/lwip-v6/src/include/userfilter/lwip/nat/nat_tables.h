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
#ifndef __NAT_PORTS_H__
#define __NAT_PORTS_H__

#include "lwip/ip.h"
#include "lwip/udp.h"
#include "lwip/tcp.h"

#include "lwip/tcpip.h"
#include "netif/etharp.h"

#include "netif/vdeif.h"
#include "netif/tunif.h"
#include "netif/tapif.h"

#include "lwip/sockets.h"
#include "lwip/if.h"

#include "lwip/nat/nat.h"

//****************************************************************************

//
// ATTENTION: all these function works with host byte alignment
//
#define NAT_MIN_PORT          49152
#define NAT_MAX_PORT          65535

#define NAT_MAX_PORTS         (NAT_MAX_PORT - NAT_MIN_PORT)     
#define NAT_PORTS_TABLE_SIZE  (NAT_MAX_PORTS / 8)

extern unsigned char nat_ports_table[NAT_PORTS_TABLE_SIZE];

void nat_ports_init(void);

/*
 * Return the first free port. Returns 0 if no one was found.
 */
INLINE u16_t nat_ports_getnew(void);

INLINE u16_t nat_ports_free(u16_t port);

#define nat_ports_isset(n)   !((nat_ports_table[((n)-NAT_MIN_PORT)/8] >> (((n)-NAT_MIN_PORT)%8)) & 0x01)
#define nat_ports_set(n)      ( nat_ports_table[((n)-NAT_MIN_PORT)/8] &= ~(1<<(((n)-NAT_MIN_PORT)%8))    )
#define nat_ports_unset(n)    ( nat_ports_table[((n)-NAT_MIN_PORT)/8] |=  (1<<(((n)-NAT_MIN_PORT)%8))    )

#endif
