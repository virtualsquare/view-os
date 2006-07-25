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
#if LWIP_USERFILTER && LWIP_NAT

#ifndef _NAT_TRACK_PROTOCOL_H
#define _NAT_TRACK_PROTOCOL_H


struct track_protocol
{
	u_int8_t proto;

	/* Tuple functions */

	int (*tuple)(struct ip_tuple *tuple, void *hdr);
	int (*inverse) (struct ip_tuple *reply, struct ip_tuple *tuple);

	/* Tracking functions */

	int (*error) (uf_verdict_t *verdict, struct pbuf *q);
	int (*new)  (struct nat_pcb *pcb,  struct pbuf *p, void *iphdr, int iplen);
	int (*handle) (uf_verdict_t *verdict, struct pbuf *p, conn_dir_t direction);

	/* NAT functions */

	int (*nat_tuple_inverse) (struct ip_tuple *reply, struct ip_tuple *tuple, 
		nat_type_t type, struct manip_range *nat_manip);

	int (*nat_free) (struct nat_pcb *pcb);

	int (*manip) (nat_manip_t type, void *iphdr, int iplen, struct ip_tuple *inverse, 
		u8_t *iphdr_new_changed_buf, 
		u8_t *iphdr_old_changed_buf, 
		u32_t iphdr_changed_buflen);

};


#endif /*_INAT_TRACK_PROTOCOL */

#endif

