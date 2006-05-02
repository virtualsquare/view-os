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

#ifndef __NAT_PORTS_H__
#define __NAT_PORTS_H__


void nat_ports_init(void);

int  nat_ports_getnew(int protocol, u32_t *port, u32_t min, u32_t max);

u16_t nat_ports_free(int protocol, u32_t val);

#endif /* NAT_PORTS */

#endif




/*
 * Return the first free port. Returns 0 if no one was found.
 */
//u16_t nat_ports_getnew(void);
//u16_t nat_ports_free(u16_t port);
//int  nat_ports_getnew(int protocol, u32_t *port);
