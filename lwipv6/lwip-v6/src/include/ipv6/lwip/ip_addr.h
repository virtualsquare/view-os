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
#ifndef __LWIP_IP_ADDR_H__
#define __LWIP_IP_ADDR_H__

#include "lwip/opt.h"
#include "lwip/arch.h"


struct ip_addr {
  u32_t addr[4];
};

struct ip4_addr {
  u32_t addr;
};

/* Added by Diego Billi */
extern const struct ip4_addr ip4_addr_broadcast;
#define IP4_ADDR_BROADCAST   ((struct ip4_addr *)&ip4_addr_broadcast)




extern const struct ip_addr ip_addr_any;
extern const struct ip_addr ip4_addr_any;
/** IP_ADDR_ can be used as a fixed IP address
 *  *  for the wildcard and the broadcast address
 *   */
#define IP_ADDR_ANY  ((struct ip_addr *)&ip_addr_any)
#define IP4_ADDR_ANY ((struct ip_addr *)&ip4_addr_any)

typedef struct {
	u32_t a1;
	u32_t a2;
	u32_t a3;
	u32_t a4;
} u128_t;

/* FOR SOCKET CALL! */

///struct in6_addr {
///	unsigned char   s6_addr[16];/* IPv6 address */
///};

///struct in_addr {
///	  u32_t s_addr;
///};


#define IP6_ADDR(ipaddr, a,b,c,d,e,f,g,h) do { (ipaddr)->addr[0] = htonl((u32_t)((a & 0xffff) << 16) | (b & 0xffff)); \
                                               (ipaddr)->addr[1] = htonl(((c & 0xffff) << 16) | (d & 0xffff)); \
                                               (ipaddr)->addr[2] = htonl(((e & 0xffff) << 16) | (f & 0xffff)); \
                                               (ipaddr)->addr[3] = htonl(((g & 0xffff) << 16) | (h & 0xffff)); } while(0)


#define IP4_ADDR(ip4addr, a,b,c,d) (ip4addr)->addr = htonl(((u32_t)((a) & 0xff) << 24) | ((u32_t)((b) & 0xff) << 16) | \
		((u32_t)((c) & 0xff) << 8) | (u32_t)((d) & 0xff))

#define IP4_ADDRX(ip4ax, a,b,c,d) (ip4ax) = htonl(((u32_t)((a) & 0xff) << 24) | ((u32_t)((b) & 0xff) << 16) | \
		((u32_t)((c) & 0xff) << 8) | (u32_t)((d) & 0xff))

#define IP64_PREFIX (htonl(0xffff))
#define IP64_CONV(ipaddr, ip4) do { \
	(ipaddr)->addr[0] = 0; \
	(ipaddr)->addr[1] = 0; \
	(ipaddr)->addr[2] = IP64_PREFIX; \
	(ipaddr)->addr[3] = (ip4)->addr; } while (0)
#define IP64_ADDR(ipaddr, a,b,c,d) do { \
	(ipaddr)->addr[0] = 0; \
	(ipaddr)->addr[1] = 0; \
	(ipaddr)->addr[2] = IP64_PREFIX; \
	IP4_ADDRX(((ipaddr)->addr[3]),(a),(b),(c),(d)); } while (0)
#define IP64_MASKCONV(ipaddr, ip4) do { \
	(ipaddr)->addr[0] = 0xffffffff; \
	(ipaddr)->addr[1] = 0xffffffff; \
	(ipaddr)->addr[2] = 0xffffffff; \
	(ipaddr)->addr[3] = (ip4)->addr; } while (0)
#define IP64_MASKADDR(ipaddr, a,b,c,d) do { \
	(ipaddr)->addr[0] = 0xffffffff; \
	(ipaddr)->addr[1] = 0xffffffff; \
	(ipaddr)->addr[2] = 0xffffffff; \
	IP4_ADDRX(((ipaddr)->addr[3]),(a),(b),(c),(d)); } while (0)
#define ip4_addr1(x) ((x)->addr[3] >> 24)
#define ip4_addr2(x) ((x)->addr[3] >> 16 & 0xff)
#define ip4_addr3(x) ((x)->addr[3] >> 8 & 0xff)
#define ip4_addr4(x) ((x)->addr[3] & 0xff)

int ip_addr_maskcmp(struct ip_addr *addr1, struct ip_addr *addr2,
        struct ip_addr *mask);
int ip_addr_cmp(struct ip_addr *addr1, struct ip_addr *addr2);
void ip_addr_set(struct ip_addr *dest, struct ip_addr *src);
void ip_addr_set_mask(struct ip_addr *dest, struct ip_addr *src,
		struct ip_addr *mask);
void ip64_addr_set(struct ip4_addr *dest, struct ip_addr *src);
void ip4_addr_set(struct ip4_addr *dest, struct ip4_addr *src);
#define ip4_addr_cmp(addr1, addr2) ((addr1)->addr == (addr2)->addr)


/*int ip_addr_isany(struct ip_addr *addr);*/
#define ip_addr_isany(addrx) (((addrx) == NULL) || \
		((((addrx)->addr[0] | \
		   (addrx)->addr[1] | \
		   (addrx)->addr[3]) == 0)&& \
		 (((addrx)->addr[2])==0 || \
		  ((addrx)->addr[2])==htonl(0xffff))))


/*
 * IPv6 Unspecified
 */
#define ip_addr_isunspecified(ipaddr) \
	(((ipaddr)->addr[0] == 0) && \
	 ((ipaddr)->addr[1] == 0) && \
	 ((ipaddr)->addr[2] == 0) && \
	 ((ipaddr)->addr[3] == 0))

#define IP6_ADDR_UNSPECIFIED(ipaddr)  do { \
	(ipaddr)->addr[0] = 0; \
	(ipaddr)->addr[1] = 0; \
	(ipaddr)->addr[2] = 0; \
	(ipaddr)->addr[3] = 0; } while (0);


/* 
 * IPv6 Link-scope addresses
 */

/* Creates link-scope address "ip" based on link address "hwaddr".
 *                      
 *         ethernet         00-80-ad-c8-a9-81
 *                         /  /  /     \  \  \
 *                       00-80-ad-FF-FE-c8-a9-81
 *                       |                    /
 *        invert bit     02                  /
 *                       |                  /
 *   fe80:0000:0000:0000:0280:adFF:FEc8:a981
 *
 */
#define IP6_ADDR_LINKSCOPE(ip, hwaddr) \
	IP6_ADDR((ip), 0xfe80, 0x0000, 0x0000, 0x0000,      \
		((((hwaddr)[0])&(0x02) ? ((hwaddr)[0])&(~(0x02)) : ((hwaddr)[0])&(0x02)  <<8) | (hwaddr)[1] ), \
		  ((hwaddr)[2]<<8 | 0xff), (0xfe00 | (hwaddr)[3] ), \
		  ((hwaddr)[4]<<8 | (hwaddr)[5]))

#define ip_addr_islinkscope(ip) \
	(((ip)->addr[0]==htonl(0xfe800000)) && ((ip)->addr[1]==0x00000000))

/*
 * IPv6 Multicast addresses
 */

#define ip_addr_ismulticast(addr1) ((ntohl((addr1)->addr[0]) >> 24) == 0xff)
/* #define ip_addr_isbroadcast(addr1, mask) ip_addr_ismulticast(addr1) */

#define ip_addr_isallnode(addr1) \
	((((addr1)->addr[0] == htonl(0xff010000)) || \
	  ((addr1)->addr[0] == htonl(0xff020000))) && \
 	 ((addr1)->addr[1] == 0) && \
	 ((addr1)->addr[2] == 0) && \
	 ((addr1)->addr[3] == 1))

#define ip_addr_isallrouter(addr1) \
	((((addr1)->addr[0] == htonl(0xff010000)) || \
	  ((addr1)->addr[0] == htonl(0xff020000))) && \
	 ((addr1)->addr[1] == 0) && \
	 ((addr1)->addr[2] == 0) && \
	 ((addr1)->addr[3] == 2))

#define IP6_NODELOCAL  0xff010000
#define IP6_LINKLOCAL  0xff020000

#define IP6_ADDR_ALLNODE(ipaddr, type)  do { \
	(ipaddr)->addr[0] = htonl((type)); \
	(ipaddr)->addr[1] = 0; \
	(ipaddr)->addr[2] = 0; \
	(ipaddr)->addr[3] = htonl(1); } while (0)

#define IP6_ADDR_ALLROUTER(ipaddr, type)  do { \
	(ipaddr)->addr[0] = htonl((type)); \
	(ipaddr)->addr[1] = 0; \
	(ipaddr)->addr[2] = 0; \
	(ipaddr)->addr[3] = htonl(2); } while (0)

/*
 * IPv6 Solicited node multicast addresses
 */
#define ip_addr_issolicited(addr1,myaddr) \
	  ((myaddr) != NULL && \
	   ((addr1)->addr[0] == htonl(0xff020000)) && \
	   ((addr1)->addr[1] == 0) && \
	   ((addr1)->addr[2] == 1) && \
	   ((addr1)->addr[3] == (((myaddr)->addr[3]) | htonl(0xff000000))))
            
#define IP6_ADDR_SOLICITED(solicited, ipaddr) do { \
	(solicited)->addr[0] = htonl(0xff020000); \
	(solicited)->addr[1] =       0x00000000; \
	(solicited)->addr[2] = htonl(0x00000001); \
	(solicited)->addr[3] = htonl(0xff000000) | (ipaddr)->addr[3]; } while (0)



#define ip_addr_is_v4comp(addr1) \
	(((addr1)->addr[0] == 0) && \
	((addr1)->addr[1] == 0) && \
	((addr1)->addr[2] == IP64_PREFIX))

#define ip_addr_is_v4broadcast_allones(addr1) \
	(((addr1)->addr[0] == 0) && \
	((addr1)->addr[1] == 0) && \
	((addr1)->addr[2] == IP64_PREFIX) && \
	((addr1)->addr[3] == 0xffffffff) )


#define ip_addr_is_v4broadcast(addr1,localaddr,mask) \
	(((addr1)->addr[0] == 0) && \
	((addr1)->addr[1] == 0) && \
	((addr1)->addr[2] == IP64_PREFIX) && \
	((addr1)->addr[3] == ((localaddr)->addr[3] | (0xffffffff & ~((mask)->addr[3])))))

#define ip_addr_is_v4multicast(addr1) \
	(((addr1)->addr[0] == 0) && \
	((addr1)->addr[1] == 0) && \
	((addr1)->addr[2] == IP64_PREFIX) && \
	(((addr1)->addr[3] & htonl(0xf0000000)) == htonl(0xe0000000)))

	
/*#if IP_DEBUG*/
void ip_addr_debug_print(int how, struct ip_addr *addr);
/*#endif*/ /* IP_DEBUG */



struct netif;

#if IPv6_AUTO_CONFIGURATION
#include "lwip/ip_autoconf.h"
#endif

struct ip_addr_list {
	struct ip_addr_list *next;
	struct ip_addr ipaddr;
	struct ip_addr netmask;
	struct netif *netif;
	char flags;

#if IPv6_AUTO_CONFIGURATION
	/* FIX: "flags" use NETLINK values (IFA_F_TENTATIVE), 
	        but "info.flag" doesn't. */
	struct addr_info info;
#endif
};

void ip_addr_list_add(struct ip_addr_list **ptail, struct ip_addr_list *el);

void ip_addr_list_del(struct ip_addr_list **ptail, struct ip_addr_list *el);

void ip_addr_list_init();

struct ip_addr_list *ip_addr_list_alloc();

void ip_addr_list_free(struct ip_addr_list *el);

void ip_addr_list_freelist(struct ip_addr_list *tail);

struct ip_addr_list *ip_addr_list_find(struct ip_addr_list *tail, struct ip_addr *addr, struct ip_addr *netmask);

struct ip_addr_list *ip_addr_list_maskfind(struct ip_addr_list *tail, struct ip_addr *addr);

struct ip_addr_list *ip_addr_list_deliveryfind(struct ip_addr_list *tail, struct ip_addr *addr, struct ip_addr *sender);

/* Added by Diego Billi */
struct ip_addr_list *ip_addr_list_masquarade_addr(struct ip_addr_list *tail, u8_t ipv);

#define ip_addr_list_first(x) (((x)==NULL) ? NULL : ((x)->next))

#if LWIP_PACKET
/* Conversion Macros to create fake ip_addr containing all the info
 * of sockaddr_ll structures (but sll_protocol).
 * This simplify the implementation as all the internal structures
 * can be reused */

///#include <netpacket/packet.h>
///#include "lwip/packet.h"

#define SALL2IPADDR(S,I) ({ \
	(I).addr[0] = (u32_t) ((S).sll_ifindex);\
  (I).addr[1] = (u32_t) (((S).sll_hatype << 16) + ((S).sll_pkttype << 8) + \
												 (S).sll_halen);\
	(I).addr[2] = (u32_t) (((S).sll_addr[0] << 24) + ((S).sll_addr[1] << 16) + \
												 ((S).sll_addr[2] << 8) + (S).sll_addr[3]); \
	(I).addr[3] = (u32_t) (((S).sll_addr[4] << 24) + ((S).sll_addr[5] << 16) + \
												 ((S).sll_addr[6] << 8) + (S).sll_addr[7]); \
})

#define IPADDR2SALL(I,S) ({ \
		register u32_t tmp; \
		(S).sll_ifindex = (int) ((I).addr[0]);\
		(S).sll_hatype = ((I).addr[1] >> 16); \
		(S).sll_pkttype = ((I).addr[1] >> 8 & 0xff); \
		(S).sll_halen = ((I).addr[1] & 0xff); \
		tmp = (I).addr[2]; \
		(S).sll_addr[3] = tmp & 0xff; tmp >>= 8; \
		(S).sll_addr[2] = tmp & 0xff; tmp >>= 8; \
		(S).sll_addr[1] = tmp & 0xff; tmp >>= 8; \
		(S).sll_addr[0] = tmp & 0xff; \
		tmp = (I).addr[3]; \
		(S).sll_addr[7] = tmp & 0xff; tmp >>= 8; \
		(S).sll_addr[6] = tmp & 0xff; tmp >>= 8; \
		(S).sll_addr[5] = tmp & 0xff; tmp >>= 8; \
		(S).sll_addr[4] = tmp & 0xff; \
})

#define IPSADDR_IFINDEX(I) ((I).addr[0])

#endif /* LWIP_PACKET */



/* added by Diego Billi 
 * Fill up to "len" bits of array "mask".
 */
#define SET_ADDR_MASK(mask, len) \
do { \
	const u8_t bitmap_bits[8] = { 0xff, 0x7f, 0x3f, 0x1f, 0x0f, 0x07, 0x03, 0x01 }; \
	int ___i;  \
	for (___i = 0; ___i < ((len)/8); ++___i) \
		(mask)[___i] = 0xff; \
	(mask)[(len)/8] |= ~bitmap_bits[((len)%8)];  \
} while(0); 


#endif /* __LWIP_IP_ADDR_H__ */
