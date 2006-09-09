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
#ifndef __LWIP_ICMP_H__
#define __LWIP_ICMP_H__

#include "lwip/opt.h"
#include "lwip/arch.h"
#include "lwip/def.h"
#include "lwip/pbuf.h"

#include "lwip/netif.h"

#define ICMP4_ER      0    /* echo reply */
#define ICMP4_DUR     3    /* destination unreachable */
#define ICMP4_SQ      4    /* source quench */
#define ICMP4_RD      5    /* redirect */
#define ICMP4_ECHO    8    /* echo */
#define ICMP4_TE     11    /* time exceeded */
#define ICMP4_PP     12    /* parameter problem */
#define ICMP4_TS     13    /* timestamp */
#define ICMP4_TSR    14    /* timestamp reply */
#define ICMP4_IRQ    15    /* information request */
#define ICMP4_IR     16    /* information reply */

#define ICMP6_DUR     1
#define ICMP6_PTB     2    /* Packet Too Big */
#define ICMP6_TE      3
#define ICMP6_ECHO  128    /* echo */
#define ICMP6_ER    129    /* echo reply */
#define ICMP6_RS    133    /* router solicitation */
#define ICMP6_RA    134    /* router advertisement */
#define ICMP6_NS    135    /* neighbor solicitation */
#define ICMP6_NA    136    /* neighbor advertisement */

enum icmp_dur_type {
  ICMP_DUR_NET   = 0,  /* net unreachable */
  ICMP_DUR_HOST  = 1,  /* host unreachable */
  ICMP_DUR_PROTO = 2,  /* protocol unreachable */
  ICMP_DUR_PORT  = 3,  /* port unreachable */
  ICMP_DUR_FRAG  = 4,  /* fragmentation needed and DF set */
  ICMP_DUR_SR    = 5   /* source route failed */
};

enum icmp_te_type {
  ICMP_TE_TTL  = 0,    /* time to live exceeded in transit */
  ICMP_TE_FRAG = 1     /* fragment reassembly time exceeded */
};

void icmp_input(struct pbuf *p, struct ip_addr_list *inad, struct pseudo_iphdr *piphdr);

void icmp_send_dad(struct ip_addr_list *targetip, struct netif *srcnetif);


void icmp_neighbor_solicitation(struct ip_addr *ipaddr, struct ip_addr_list *inad);
void icmp_router_solicitation(struct ip_addr *ipaddr, struct ip_addr_list *inad);

void icmp_dest_unreach(struct pbuf *p, enum icmp_dur_type t);
void icmp_time_exceeded(struct pbuf *p, enum icmp_te_type t);

void icmp_packet_too_big(struct pbuf *p, u16_t mtu);

void icmp4_dest_unreach(struct pbuf *p, enum icmp_dur_type t, u16_t nextmtu );
void icmp4_time_exceeded(struct pbuf *p, enum icmp_te_type t);

/*
 * ICMP Headers used for IPv4 and IPv6
 */

#define ICMPH_TYPE_SET(hdr,typ) (hdr)->type=(typ)

#define ICMPH_TYPE(hdr)   ((hdr)->type)
#define ICMPH_CODE(hdr)   ((hdr)->icode)
#define ICMPH_CHKSUM(hdr) ((hdr)->chksum)

/* Echo Request, Echo Reply */
/* The IPv6 header. */
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/bpstruct.h"
#endif
PACK_STRUCT_BEGIN
struct icmp_echo_hdr {	
  PACK_STRUCT_FIELD(u8_t type);
  PACK_STRUCT_FIELD(u8_t icode);
  PACK_STRUCT_FIELD(u16_t chksum);
  PACK_STRUCT_FIELD(u16_t id);
  PACK_STRUCT_FIELD(u16_t seqno);
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/epstruct.h"
#endif


/* Destination Unreachable */
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/bpstruct.h"
#endif
PACK_STRUCT_BEGIN
struct icmp_dur_hdr { 	
  PACK_STRUCT_FIELD(u8_t type);
  PACK_STRUCT_FIELD(u8_t icode);
  PACK_STRUCT_FIELD(u16_t chksum);
  PACK_STRUCT_FIELD(u16_t unused);
  PACK_STRUCT_FIELD(u16_t nextmtu);    /* this is used only in ICMPv4 packets */
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/epstruct.h"
#endif


/* Time Exceeded */
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/bpstruct.h"
#endif
PACK_STRUCT_BEGIN
struct icmp_te_hdr {	
  PACK_STRUCT_FIELD(u8_t type);
  PACK_STRUCT_FIELD(u8_t icode);
  PACK_STRUCT_FIELD(u16_t chksum);
  PACK_STRUCT_FIELD(u32_t unused);
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/epstruct.h"
#endif



/*
 * ICMPv6 Headers
 */

/* Packet Too Big */
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/bpstruct.h"
#endif
PACK_STRUCT_BEGIN
struct icmp_ptb_hdr { 	
  PACK_STRUCT_FIELD(u8_t type);
  PACK_STRUCT_FIELD(u8_t icode);
  PACK_STRUCT_FIELD(u16_t chksum);
  PACK_STRUCT_FIELD(u32_t mtu);
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/epstruct.h"
#endif


/* NS - Neighbor Solicitation */
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/bpstruct.h"
#endif
PACK_STRUCT_BEGIN
struct icmp_ns_hdr {    
  PACK_STRUCT_FIELD(u8_t type); 
  PACK_STRUCT_FIELD(u8_t icode); 
  PACK_STRUCT_FIELD(u16_t chksum);
  PACK_STRUCT_FIELD(u32_t reserved);
  PACK_STRUCT_FIELD(u32_t targetip[4]);
  //struct icmp_opt option;  /* for Source link-layer address */
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/epstruct.h"
#endif


/* NA - Neighbor advertisement */
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/bpstruct.h"
#endif
PACK_STRUCT_BEGIN
struct icmp_na_hdr {    
  PACK_STRUCT_FIELD(u8_t type); 
  PACK_STRUCT_FIELD(u8_t icode); 
  PACK_STRUCT_FIELD(u16_t chksum);
  PACK_STRUCT_FIELD(u8_t rso_flags);
#define ICMP6_NA_R  0x01
#define ICMP6_NA_S  0x02
#define ICMP6_NA_O  0x04
  PACK_STRUCT_FIELD(u8_t reserved[3]);
  PACK_STRUCT_FIELD(u32_t targetip[4]);
  //struct icmp_opt option;  /* for Target link-layer address */
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/epstruct.h"
#endif


/* RS - Router Solicitation */
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/bpstruct.h"
#endif
PACK_STRUCT_BEGIN
struct icmp_rs_hdr {    
  PACK_STRUCT_FIELD(u8_t type); 
  PACK_STRUCT_FIELD(u8_t icode); 
  PACK_STRUCT_FIELD(u16_t chksum);
  PACK_STRUCT_FIELD(u32_t reserved);
  //struct icmp_opt option;  /* for Source link-layer addres */
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/epstruct.h"
#endif


/* RA - Router Advertisement */
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/bpstruct.h"
#endif
PACK_STRUCT_BEGIN
struct icmp_ra_hdr {    
  PACK_STRUCT_FIELD(u8_t type); 
  PACK_STRUCT_FIELD(u8_t icode); 
  PACK_STRUCT_FIELD(u16_t chksum);
  PACK_STRUCT_FIELD(u8_t hoplimit); 
  PACK_STRUCT_FIELD(u8_t m_o_flag);
#define ICMP6_RA_M  0x80
#define ICMP6_RA_O  0x40
  PACK_STRUCT_FIELD(u16_t life);     /* (seconds) The lifetime associated with the default router */
  PACK_STRUCT_FIELD(u32_t reach);    /* (milliseconds) */
  PACK_STRUCT_FIELD(u32_t retran);   /* (milliseconds) between retransmitted Neighbor Solicitation messages. */
  //struct icmp_opt option;  /* for Source link-layer addres */
  //struct icmp_opt option;  /* MTU */
  //struct icmp_opt option;  /* Prefix Information */
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/epstruct.h"
#endif



/*
 * ICMP6 Options
 */

#define ICMP6_OPT_SRCADDR     1
#define ICMP6_OPT_DESTADDR    2
#define ICMP6_OPT_PREFIX      3
#define ICMP6_OPT_REDIRECT    4
#define ICMP6_OPT_MTU         5

/* Generic ICMP option */
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/bpstruct.h"
#endif
PACK_STRUCT_BEGIN
struct icmp_opt {       
  PACK_STRUCT_FIELD(u8_t type);
  PACK_STRUCT_FIELD(u8_t len);        /* in units of 8 octets (including the type and length fields). */
  PACK_STRUCT_FIELD(u8_t data[0]);    
}PACK_STRUCT_STRUCT;
PACK_STRUCT_END
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/epstruct.h"
#endif

/* ICMPv6 Address Options field */
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/bpstruct.h"
#endif
PACK_STRUCT_BEGIN
struct icmp_opt_addr {       
  PACK_STRUCT_FIELD(u8_t type);
  PACK_STRUCT_FIELD(u8_t len);        /* in units of 8 octets (including the type and length fields). */
  PACK_STRUCT_FIELD(u8_t addr[0]);    /* 0 is not allowed with some compilers */
}PACK_STRUCT_STRUCT;
PACK_STRUCT_END
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/epstruct.h"
#endif

/* Length of ethernet address in 8-octects  */
#define ICMP6_OPT_LEN_ETHER   1


#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/bpstruct.h"
#endif
PACK_STRUCT_BEGIN
struct icmp_opt_prefix {       
  PACK_STRUCT_FIELD(u8_t type);       
  PACK_STRUCT_FIELD(u8_t len);        /* 4 */
  PACK_STRUCT_FIELD(u8_t preflen);    /* Prefix len */
  PACK_STRUCT_FIELD(u8_t flags);      
#define ICMP6_OPT_PREF_L  0x80
#define ICMP6_OPT_PREF_A  0x40
  PACK_STRUCT_FIELD(u32_t valid);     
  PACK_STRUCT_FIELD(u32_t prefered);  /* seconds */
  PACK_STRUCT_FIELD(u32_t reserved);  /* seconds */
  PACK_STRUCT_FIELD(u32_t prefix[4]); 
}PACK_STRUCT_STRUCT;
PACK_STRUCT_END
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/epstruct.h"
#endif

#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/bpstruct.h"
#endif
PACK_STRUCT_BEGIN
struct icmp_opt_mtu {       
  PACK_STRUCT_FIELD(u8_t type);
  PACK_STRUCT_FIELD(u8_t len);        /* 1 */
  PACK_STRUCT_FIELD(u16_t reserved);
  PACK_STRUCT_FIELD(u32_t mtu);    
}PACK_STRUCT_STRUCT;
PACK_STRUCT_END
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/epstruct.h"
#endif


#endif /* __LWIP_ICMP_H__ */

