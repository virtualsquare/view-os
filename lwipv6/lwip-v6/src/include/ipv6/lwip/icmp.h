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

#include "lwip/arch.h"

#include "lwip/opt.h"
#include "lwip/pbuf.h"

#include "lwip/netif.h"

#define ICMP4_ER 0      /* echo reply */
#define ICMP4_DUR 3     /* destination unreachable */
#define ICMP4_SQ 4      /* source quench */
#define ICMP4_RD 5      /* redirect */
#define ICMP4_ECHO 8    /* echo */
#define ICMP4_TE 11     /* time exceeded */
#define ICMP4_PP 12     /* parameter problem */
#define ICMP4_TS 13     /* timestamp */
#define ICMP4_TSR 14    /* timestamp reply */
#define ICMP4_IRQ 15    /* information request */
#define ICMP4_IR 16     /* information reply */
#define ICMP6_DUR  1
#define ICMP6_TE   3
#define ICMP6_ECHO 128    /* echo */
#define ICMP6_ER   129      /* echo reply */
#define ICMP6_RA   134      /* router advertisement */
#define ICMP6_NS   135      /* neighbor solicitation */
#define ICMP6_NA   136      /* neighbor advertisement */

enum icmp_dur_type {
  ICMP_DUR_NET = 0,    /* net unreachable */
  ICMP_DUR_HOST = 1,   /* host unreachable */
  ICMP_DUR_PROTO = 2,  /* protocol unreachable */
  ICMP_DUR_PORT = 3,   /* port unreachable */
  ICMP_DUR_FRAG = 4,   /* fragmentation needed and DF set */
  ICMP_DUR_SR = 5      /* source route failed */
};

enum icmp_te_type {
  ICMP_TE_TTL = 0,     /* time to live exceeded in transit */
  ICMP_TE_FRAG = 1     /* fragment reassembly time exceeded */
};

void icmp_input(struct pbuf *p, struct ip_addr_list *inad, struct pseudo_iphdr *piphdr);

void icmp_neighbor_solicitation(struct ip_addr *ipaddr, struct ip_addr_list *inad);

void icmp_dest_unreach(struct pbuf *p, enum icmp_dur_type t);
void icmp_time_exceeded(struct pbuf *p, enum icmp_te_type t);

struct icmp_echo_hdr {
  u8_t type;
  u8_t icode;
  u16_t chksum;
  u16_t id;
  u16_t seqno;
};

struct icmp_dur_hdr {
  u8_t type;
  u8_t icode;
  u16_t chksum;
  u32_t unused;
};

struct icmp_te_hdr {
  u8_t type;
  u8_t icode;
  u16_t chksum;
  u32_t unused;
};

struct icmp_ns_hdr {
  u8_t type;
  u8_t icode;
  u16_t chksum;
  u32_t flags;
};

#define ICMPH_TYPE_SET(hdr,typ) (hdr)->type=(typ)

#endif /* __LWIP_ICMP_H__ */
    
