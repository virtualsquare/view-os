/*   This is part of LWIPv6
 *   Developed for the Ale4NET project
 *   Application Level Environment for Networking
 *   
 *   Copyright 2005 Diego Billi University of Bologna - Italy
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
/*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
 * All rights reserved. 
 * 
 * Redistribution and use in source and binary forms, with or without modification, 
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED 
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT 
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, 
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT 
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING 
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY 
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 * 
 * Author: Jani Monoses <jani@iv.ro>
 *
 */

#if Pv4_FRAGMENTATION || IPv6_FRAGMENTATION

#ifndef __LWIP_IP_FRAG_H__
#define __LWIP_IP_FRAG_H__

/* Module init */
void ip_frag_reass_init(void);


#if IPv4_FRAGMENTATION

/* 
 * IPv4 Frag/Defrag functions 
 */
struct pbuf *ip4_reass(struct pbuf *p);

err_t ip4_frag(struct pbuf *, struct netif *, struct ip_addr *);

#endif /* IPv4_FRAGMENTATION */



#if IPv6_FRAGMENTATION

/*
 * IPv6 Frag/Defrag functions
 */

/* Fragmentation extension header */
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/bpstruct.h"
#endif
PACK_STRUCT_BEGIN
struct ip6_fraghdr {
	PACK_STRUCT_FIELD(u8_t  nexthdr); 
	PACK_STRUCT_FIELD(u8_t  reserved); 
	PACK_STRUCT_FIELD(u16_t offset_res_m);
#define IP6_OFFMASK       0xfff8
#define IP6_MF            0x0001
	PACK_STRUCT_FIELD(u32_t id);
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/epstruct.h"
#endif

#define IP6_NEXTHDR(fhdr) (fhdr)->nexthdr
#define IP6_OFFSET(fhdr)  (ntohs((fhdr)->offset_res_m) & IP6_OFFMASK)
#define IP6_M(fhdr)       (ntohs((fhdr)->offset_res_m) & IP6_MF)
#define IP6_ID(fhdr)      (ntohl((fhdr)->id) )

/* Lenght in bytes of the fragmentation header.  */
#define IP_EXTFRAG_LEN    8

struct pbuf *ip6_reass(struct pbuf *p, struct ip6_fraghdr *fragext, struct ip_exthdr *lastext);

err_t ip6_frag(struct pbuf *p, struct netif *netif, struct ip_addr *dest);

#endif /* IPv6_FRAGMENTATION */



#endif /* __LWIP_IP_FRAG_H__ */

#endif /* IPv4_FRAGMENTATION || IPv6_FRAGMENTATION */
