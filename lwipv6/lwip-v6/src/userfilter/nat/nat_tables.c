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

#include "lwip/nat/nat_tables.h"

#ifndef NATPORTS_DEBUG
#define NATPOSTS_DEBUG DBG_OFF
#endif

/*--------------------------------------------------------------------------*/


unsigned char nat_ports_table[NAT_PORTS_TABLE_SIZE];

void nat_ports_init(void)
{
	// Set all ports unused
	memset(nat_ports_table, 0xff, NAT_PORTS_TABLE_SIZE);

#if IP_DEBUG
	LWIP_DEBUGF(NATPOSTS_DEBUG, ("unat: allocated %d ports \n", NAT_MAX_PORTS));
#endif
}

INLINE u16_t  nat_ports_getnew(void)
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

	//unat_ports_set(r+ UNAT_MIN_PORT);
	
	return (r + NAT_MIN_PORT);
}

INLINE u16_t nat_ports_free(u16_t port)
{
	nat_ports_unset(port);
	return 1;
}

#endif /* LWIP_NAT */
