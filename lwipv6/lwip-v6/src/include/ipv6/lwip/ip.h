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
 * Author: Adam Dunkels <adam@sics.se>
 *
 */
#ifndef __LWIP_IP_H__
#define __LWIP_IP_H__

#include "lwip/opt.h"
#include "lwip/def.h"
#include "lwip/pbuf.h"
#include "lwip/ip_addr.h"

#include "lwip/err.h"

/* This is the common part of all PCB types. It needs to be at the
 * beginning of a PCB type definition. It is located here so that
 * changes to this common part are made in one location instead of
 * having to change all PCB structs. */
#define IP_PCB \
    struct ip_addr local_ip;  \
    struct ip_addr remote_ip; \
	/* Socket options */      \
	u16_t so_options;         \
	/* Type Of Service */     \
	u8_t tos;                 \
	/* Time To Live */        \
	u8_t ttl


/* This is passed as the destination address to ip_output_if (not
 * to ip_output), meaning that an IP header already is constructed
 * in the pbuf. This is used when TCP retransmits. */
#ifdef IP_HDRINCL
#undef IP_HDRINCL
#endif /* IP_HDRINCL */
#define IP_HDRINCL  NULL


/*
 * Protocols numbers
 */
#define IP_PROTO_ICMP4           1
#define IP_PROTO_TCP             6      /* TCP segment. */
#define IP_PROTO_UDP            17      /* UDP message. */
#define IP_FRAG_TAG             44
#define IP_PROTO_ICMP           58      /* ICMP for IPv6. */
#define IP_PROTO_UDPLITE       170


/*****************************************************************************/
/* IPv6 structures and macroes */
/*****************************************************************************/

/* Extensions headers */
#define IP6_NEXTHDR_HOP          0      /* Hop-by-hop option header. */
#define IP6_NEXTHDR_DEST        60      /* Destination options header. */
#define IP6_NEXTHDR_ROUTING     43      /* Routing header. */
#define IP6_NEXTHDR_FRAGMENT    44      /* Fragmentation/reassembly header. */
#define IP6_NEXTHDR_ESP         50      /* Encapsulating security payload. */
#define IP6_NEXTHDR_AUTH        51      /* Authentication header. */
#define IP6_NEXTHDR_NONE        59      /* No next header */
#define IP6_NEXTHDR_IPV6        41      /* IPv6 in IPv6 */
#define IP6_NEXTHDR_MAX        255      /* Max value */

/* The IPv6 header. */
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/bpstruct.h"
#endif
PACK_STRUCT_BEGIN
struct ip_hdr {
	  /* version / class1 */
	  PACK_STRUCT_FIELD(u16_t _v_cl_fl);
	  /* class2 / flow */
	  PACK_STRUCT_FIELD(u16_t flow2);
	  /* length */
	  PACK_STRUCT_FIELD(u16_t len);
	  /* next_hdr / hoplim*/
	  PACK_STRUCT_FIELD(u16_t _next_hop);
	  /* source and destination IP addresses */
	  PACK_STRUCT_FIELD(struct ip_addr src);
	  PACK_STRUCT_FIELD(struct ip_addr dest);
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/epstruct.h"
#endif

#define IP_HLEN 40

#define IPH_V(hdr)         (ntohs((hdr)->_v_cl_fl) >> 12)
#define IPH_CL(hdr)        ((ntohs((hdr)->_v_cl_fl) >> 4) & 0xff)
#define IPH_FLOW(hdr)      ((ntohs((hdr)->_v_cl_fl) & 0xf) + ((hdr)->flow2))
#define IPH_NEXTHDR(hdr)   (ntohs((hdr)->_next_hop) >> 8)
#define IPH_HOPLIMIT(hdr)  (ntohs((hdr)->_next_hop) & 0xff)

#define IPH_V_SET(hdr,vv)                   ((hdr)->_v_cl_fl)  = htons((ntohs((hdr)->_v_cl_fl) & 0xffffff) | ((vv) << 12))
#define IPH_NEXTHDR_SET(hdr, nexthdr)       ((hdr)->_next_hop) = htons((nexthdr) << 8 | IPH_HOPLIMIT(hdr))
#define IPH_HOPLIMIT_SET(hdr, hop)          ((hdr)->_next_hop) = htons(IPH_NEXTHDR(hdr) << 8 | (hop))
#define IPH_NEXT_HOP_SET(hdr, nexthdr, hop) ((hdr)->_next_hop) = htons((nexthdr) << 8 | (hop))

#define IPH_PAYLOADLEN(hdr)             ((hdr)->len)
#define IPH_PAYLOADLEN_SET(hdr, newlen) ((hdr)->len = htons((newlen)))


/* Generic IPv6 Extension Header  */
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/bpstruct.h"
#endif
PACK_STRUCT_BEGIN
struct ip_exthdr {
	  /* Next Header */
	  PACK_STRUCT_FIELD(u8_t nexthdr);
	  /* Hdr Ext Len */
	  PACK_STRUCT_FIELD(u8_t len);
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/epstruct.h"
#endif
                                
#define IPEXTH_NEXTHDR(hdr)               ((hdr)->nexthdr)
#define IPEXTH_NEXTHDR_SET(hdr, nexthdr)  ((hdr)->nexthdr = (nexthdr))

#define is_ipv6_exthdr(nexthdr) \
	(((nexthdr)==IP6_NEXTHDR_HOP)      || \
     ((nexthdr)==IP6_NEXTHDR_ROUTING)  || \
	 ((nexthdr)==IP6_NEXTHDR_FRAGMENT) || \
	 ((nexthdr)==IP6_NEXTHDR_AUTH)     || \
	 ((nexthdr)==IP6_NEXTHDR_NONE)     || \
	 ((nexthdr)==IP6_NEXTHDR_DEST))


/* Generic IPv6 Option  */
struct ip6_option {       
  u8_t type;
  u8_t len;        /* in units of 8 octets (including the type and length fields). */
  u8_t data[0];    /* 0 is not allowed with some compilers */
};

/* Option Type field encoding :

    00?? ???? - skip over and continue processing.
    01?? ???? - discard.
    10?? ???? - discard and send an ICMP Parameter Problem, Code 2.
    11?? ???? - discard and, if Destination Address was not multicast address, send ICMP Parameter Problem.

    ??0? ???? - Option Data does not change en-route.
    ??1? ???? - Option Data may change en-route.
*/
#define IP6_OPT_SKIP(opt)             (((opt)->type & 0xC0) == 0) 
#define IP6_OPT_DISCARD(opt)          ((opt)->type & 0x40) 
#define IP6_OPT_INVALID(opt)          ((opt)->type & 0x80) 
#define IP6_OPT_INVALID_NOTMULTI(opt) ((opt)->type & 0xC0) 
#define IP6_OPT_DONTCHANGE(opt)       (((opt)->type & 0x20) == 0)
#define IP6_OPT_CHANGE(opt)           ((opt)->type & 0x20) 

#define IP6_OPT_LEN(opt)              ((opt)->len * 8)

/*****************************************************************************/
/* IPv4 structures and macroes */
/*****************************************************************************/

/* The IPv4 header. */
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/bpstruct.h"
#endif
PACK_STRUCT_BEGIN
struct ip4_hdr {
  /* version / header length / type of service */
  PACK_STRUCT_FIELD(u16_t _v_hl_tos);
  /* total length */
  PACK_STRUCT_FIELD(u16_t _len);
  /* identification */
  PACK_STRUCT_FIELD(u16_t _id);
  /* fragment offset field */
  PACK_STRUCT_FIELD(u16_t _offset);
#define IP_RF 0x8000        /* reserved fragment flag */
#define IP_DF 0x4000        /* dont fragment flag */
#define IP_MF 0x2000        /* more fragments flag */
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
  /* time to live / protocol*/
  PACK_STRUCT_FIELD(u16_t _ttl_proto);
  /* checksum */
  PACK_STRUCT_FIELD(u16_t _chksum);
  /* source and destination IP addresses */
  PACK_STRUCT_FIELD(struct ip4_addr src);
  PACK_STRUCT_FIELD(struct ip4_addr dest); 
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/epstruct.h"
#endif

#define IP4_HLEN 20

#define IPH4_V(hdr)      (ntohs((hdr)->_v_hl_tos) >> 12)
#define IPH4_HL(hdr)     ((ntohs((hdr)->_v_hl_tos) >> 8) & 0x0f)
#define IPH4_TOS(hdr)    (htons((ntohs((hdr)->_v_hl_tos) & 0xff)))
#define IPH4_LEN(hdr)    ((hdr)->_len)
#define IPH4_ID(hdr)     ((hdr)->_id)
#define IPH4_OFFSET(hdr) ((hdr)->_offset)
#define IPH4_TTL(hdr)    (ntohs((hdr)->_ttl_proto) >> 8)
#define IPH4_PROTO(hdr)  (ntohs((hdr)->_ttl_proto) & 0xff)
#define IPH4_CHKSUM(hdr) ((hdr)->_chksum)

#define IPH4_VHLTOS_SET(hdr, v, hl, tos) (hdr)->_v_hl_tos = (htons(((v) << 12) | ((hl) << 8) | (tos)))
#define IPH4_LEN_SET(hdr, len)           (hdr)->_len = (len)
#define IPH4_ID_SET(hdr, id)             (hdr)->_id = (id)
#define IPH4_OFFSET_SET(hdr, off)        (hdr)->_offset = (off)
#define IPH4_TTL_SET(hdr, ttl)           (hdr)->_ttl_proto = (htons(IPH4_PROTO(hdr) | ((ttl) << 8)))
#define IPH4_PROTO_SET(hdr, proto)       (hdr)->_ttl_proto = (htons((proto) | (IPH4_TTL(hdr) << 8)))
#define IPH4_CHKSUM_SET(hdr, chksum)     (hdr)->_chksum = (chksum)

/* no variable part */
#define IPH_HL(x)      (IP_HLEN >> 2) /*IPv4 compatibility*/
#define IPH_PROTO(x)   ((x)->nexthdr)

#include "lwip/netif.h"


/*
 * Option flags per-socket. These are the same like SO_XXX.
 */
#define	SOF_DEBUG	    (u16_t)0x0001U		/* turn on debugging info recording */
#define	SOF_ACCEPTCONN	(u16_t)0x0002U		/* socket has had listen() */
#define	SOF_REUSEADDR	(u16_t)0x0004U		/* allow local address reuse */
#define	SOF_KEEPALIVE	(u16_t)0x0008U		/* keep connections alive */
#define	SOF_DONTROUTE	(u16_t)0x0010U		/* just use interface addresses */
#define	SOF_BROADCAST	(u16_t)0x0020U		/* permit sending of broadcast msgs */
#define	SOF_USELOOPBACK	(u16_t)0x0040U		/* bypass hardware when possible */
#define	SOF_LINGER	    (u16_t)0x0080U		/* linger on close if data present */
#define	SOF_OOBINLINE	(u16_t)0x0100U		/* leave received OOB data in line */
#define	SOF_REUSEPORT	(u16_t)0x0200U		/* allow local address & port reuse */
#define	SOF_IPV6_CHECKSUM (u16_t)0x8000U	/* RAW socket IPv6 checksum */



/*****************************************************************************/
/* IP Layer functions  */
/*****************************************************************************/

/* Fragmentation IDs */
/* FIX: race condition between ipv4 and ipv6 fragmentation code */
extern u16_t ip_id;


void ip_init(void);

/* Input functions for netif interfaces */
void ip_input(struct pbuf *p, struct netif *inp);

/* source and destination addresses in network byte order, please */
err_t ip_output(struct pbuf *p, struct ip_addr *src, struct ip_addr *dest,
		unsigned char ttl, unsigned char tos, unsigned char proto);

err_t ip_output_if(struct pbuf *p, struct ip_addr *src, struct ip_addr *dest,
		unsigned char ttl, unsigned char tos, unsigned char proto,
		struct netif *netif, struct ip_addr *nexthop, int flags);


err_t ip_output_raw(struct pbuf *p, struct netif *out, struct ip_addr *nexthop);


#if IP_DEBUG
void ip_debug_print(int how, struct pbuf *p);
#else
#define ip_debug_print(how,p) 
#endif /* IP_DEBUG */

/* Used in ip6.c to handle ingoing packets from both IPv4 and IPv6 */
struct pseudo_iphdr {
	u8_t  version;         /* ip version */
	u16_t iphdrlen;        /* header len (IPv4+options, IPv6 main header only) */
	u16_t proto;           /* Next protocol (also IPv6 extension headers) */
	struct ip_addr *src;
	struct ip_addr *dest;
};

int ip_build_piphdr(struct pseudo_iphdr *piphdr, struct pbuf *p, 
		struct ip_addr *src4, struct ip_addr *dest4);


#endif /* __LWIP_IP_H__ */

