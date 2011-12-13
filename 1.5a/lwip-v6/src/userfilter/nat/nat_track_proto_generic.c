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
#include "lwip/opt.h"

#if LWIP_USERFILTER && LWIP_NAT

#include "lwip/debug.h"
#include "lwip/sys.h"
#include "lwip/memp.h" /* MEMP_NAT_RULE */

#include "lwip/inet.h"
#include "lwip/ip.h"

#include "lwip/netif.h"
#include "lwip/userfilter.h"

#include "lwip/nat/nat.h"
#include "lwip/nat/nat_tables.h"


/*--------------------------------------------------------------------------*/

/* Abort, skip or drop everything we don't understand */

int track_default_tuple(struct ip_tuple *tuple, void *hdr)
{ 
	return -1;
}

int track_default_inverse(struct ip_tuple *reply, struct ip_tuple *tuple)  
{ 
	return -1;
}

/*--------------------------------------------------------------------------*/

int track_default_error (struct stack *stack, uf_verdict_t *verdict, struct pbuf *q)
{
	* verdict = UF_DROP;
	return -1;
}

int track_default_new(struct stack *stack, struct nat_pcb *pcb,  struct pbuf *p, void *iphdr, int iplen)
{ 
	return 1;
}

int track_default_handle(struct stack *stack, uf_verdict_t *verdict, struct pbuf *p, conn_dir_t direction)
{ 
	*verdict = UF_DROP;
	return -1;
}

/*--------------------------------------------------------------------------*/

int nat_default_tuple_inverse (struct stack *stack, struct ip_tuple *reply, struct ip_tuple *tuple, nat_type_t type, struct manip_range *nat_manip )
{
	return -1;
}

int nat_default_manip (nat_manip_t type, void *iphdr, int iplen, struct ip_tuple *inverse, 
		u8_t *iphdr_new_changed_buf, 
		u8_t *iphdr_old_changed_buf, 
		u32_t iphdr_changed_buflen)
{
	return 1;
}

int nat_default_free(struct nat_pcb *pcb)
{
	return 1;
}

/*--------------------------------------------------------------------------*/

struct track_protocol  default_track = {
	.tuple   = track_default_tuple,
	.inverse = track_default_inverse,

	.error   = track_default_error,
	.new     = track_default_new,
	.handle  = track_default_handle,

	.manip   = nat_default_manip,
	.nat_tuple_inverse = nat_default_tuple_inverse,
	.nat_free = nat_default_free
};

#endif 


