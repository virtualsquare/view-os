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
 *   51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
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

#include "lwip/opt.h"
#include "lwip/def.h"
#include "lwip/ip_addr.h"
#include "lwip/inet.h"
#include "lwip/stack.h"
#include "lwip/memp.h"

/* Added by Diego Billi */
#define IP4_ADDR_BROADCAST_VALUE 0xffffffffUL
const struct ip4_addr ip4_addr_broadcast = { IP4_ADDR_BROADCAST_VALUE };

const struct ip_addr ip_addr_any = {{0,0,0,0}};
#if BYTE_ORDER == LITTLE_ENDIAN
const struct ip_addr ip4_addr_any = {{0,0,0xffff0000,0}};
#else
const struct ip_addr ip4_addr_any = {{0,0,0x0000ffff,0}};
#endif

int
ip_addr_maskcmp(struct ip_addr *addr1, struct ip_addr *addr2,
                struct ip_addr *mask)
{
  return((addr1->addr[0] & mask->addr[0]) == (addr2->addr[0] & mask->addr[0]) &&
	 (addr1->addr[1] & mask->addr[1]) == (addr2->addr[1] & mask->addr[1]) &&
	 (addr1->addr[2] & mask->addr[2]) == (addr2->addr[2] & mask->addr[2]) &&
	 (addr1->addr[3] & mask->addr[3]) == (addr2->addr[3] & mask->addr[3]));
}

int
ip_addr_cmp(struct ip_addr *addr1, struct ip_addr *addr2)
{
  return(addr1->addr[0] == addr2->addr[0] &&
         addr1->addr[1] == addr2->addr[1] &&
         addr1->addr[2] == addr2->addr[2] &&
         addr1->addr[3] == addr2->addr[3]);
}

void
ip_addr_set(struct ip_addr *dest, struct ip_addr *src)
{
	if (src == NULL)
		memcpy(dest, &ip_addr_any, sizeof(struct ip_addr));
	else
		memcpy(dest, src, sizeof(struct ip_addr));
}

void
ip_addr_set_mask(struct ip_addr *dest, struct ip_addr *src, struct ip_addr *mask)
{
	if (src == NULL)
		memcpy(dest, &ip_addr_any, sizeof(struct ip_addr));
	else {
		register int i;
		for (i=0;i<4;i++)
			dest->addr[i]=src->addr[i] & mask->addr[i];
	}
}

void
ip64_addr_set(struct ip4_addr *dest, struct ip_addr *src)
{
	if (src == NULL)
		memcpy(dest, &ip_addr_any.addr[3], sizeof(struct ip4_addr));
	else
		memcpy(dest, &(src->addr[3]), sizeof(struct ip4_addr));
}

void
ip4_addr_set(struct ip4_addr *dest, struct ip4_addr *src)
{
	if (src == NULL)
		memcpy(dest, &ip_addr_any.addr[3], sizeof(struct ip4_addr));
	else
		memcpy(dest, src, sizeof(struct ip4_addr));
}

/* #if IP_DEBUG*/
void
ip_addr_debug_print(int debk, struct ip_addr *addr)
{
	if (addr != NULL) {
		/* added by Diego Billi */
		if(ip_addr_is_v4comp(addr)) {
			LWIP_DEBUGF(debk,("%ld.%ld.%ld.%ld",
				ntohl(addr->addr[3]) >> 24 & 0xff,
				ntohl(addr->addr[3]) >> 16 & 0xff,
				ntohl(addr->addr[3]) >> 8 & 0xff,
				ntohl(addr->addr[3]) & 0xff));
 		} else {
			LWIP_DEBUGF(debk,("%lx:%lx:%lx:%lx:%lx:%lx:%lx:%lx",
				ntohl(addr->addr[0]) >> 16 & 0xffff,
				ntohl(addr->addr[0]) & 0xffff,
				ntohl(addr->addr[1]) >> 16 & 0xffff,
				ntohl(addr->addr[1]) & 0xffff,
				ntohl(addr->addr[2]) >> 16 & 0xffff,
				ntohl(addr->addr[2]) & 0xffff,
				ntohl(addr->addr[3]) >> 16 & 0xffff,
				ntohl(addr->addr[3]) & 0xffff));
		}
	}
	else
		LWIP_DEBUGF(debk,("IPv6 NULL ADDR"));
}

/*#endif*/ /* IP_DEBUG */

/*---------------------------------------------------------------------------*/

void ip_addr_list_init(struct stack *stack)
{
#if 0
	register int i;
	
	struct ip_addr_list *ip_addr_pool     = stack->ip_addr_pools;
	
	for (i = 0; i < IP_ADDR_POOL_SIZE-1; i++)
		ip_addr_pool[i].next = ip_addr_pool+(i+1);

	ip_addr_pool[i].next    = NULL;
	stack->ip_addr_freelist = ip_addr_pool;
#endif
}

void ip_addr_list_shutdown(struct stack *stack)
{
    
}

/*---------------------------------------------------------------------------*/


struct ip_addr_list *ip_addr_list_alloc(struct stack *stack)
{
	struct ip_addr_list *el;
#if 0
	if (stack->ip_addr_freelist == NULL)
		return NULL;
	else {
		el = stack->ip_addr_freelist;
		stack->ip_addr_freelist = stack->ip_addr_freelist->next;

		/* Added by Diego Billi */
		bzero(el, sizeof (struct ip_addr_list));
#endif
		el=memp_malloc(MEMP_ADDR);
		if (el)
			memset(el,0,sizeof(struct ip_addr_list));

		return el;
}

void ip_addr_list_free(struct stack *stack, struct ip_addr_list *el)
{
	memp_free(MEMP_ADDR,el);
	/*
	el->next = stack->ip_addr_freelist;
	stack->ip_addr_freelist = el;
	*/
}

void ip_addr_list_freelist(struct stack *stack, struct ip_addr_list *tail)
{
	/*
	if (tail == NULL)
		return;
	else {
		struct ip_addr_list *tail = tail->next;
		tail->next = stack->ip_addr_freelist;
		stack->ip_addr_freelist = tail;
	}
	*/
	if (tail != NULL) {
		struct ip_addr_list *next=tail->next;
		tail->next=NULL;
		while (tail != NULL) {
			next=tail->next;
			ip_addr_list_free(stack,tail);
			tail=next;
		}
  }
}

#define mask_wider(x,y) \
	(((y)->addr[0] & ~((x)->addr[0])) | \
	((y)->addr[1] & ~((x)->addr[1])) | \
	((y)->addr[2] & ~((x)->addr[2])) | \
	((y)->addr[3] & ~((x)->addr[3])))

void ip_addr_list_add(struct ip_addr_list **ptail, struct ip_addr_list *el)
{
	LWIP_ASSERT("ip_addr_list_add NULL handle",ptail != NULL);
	if (*ptail == NULL) 
		*ptail=el->next=el;
	else {
		el->next=(*ptail)->next;
		*ptail=(*ptail)->next=el;
	}
}

void ip_addr_list_del(struct ip_addr_list **ptail, struct ip_addr_list *el)
{
	LWIP_ASSERT("ip_addr_list_del NULL handle",ptail != NULL);
	if (*ptail == NULL)
		return;
	else {
		struct ip_addr_list *prev=*ptail;
		struct ip_addr_list *p;
		for (p=prev->next;p != el && p != *ptail; prev=p,p=p->next)
			;
		if (p == el) {
			if (p == prev)
				*ptail = NULL;
			else {
				prev->next=p->next;
				if (*ptail==p) *ptail=prev;
			}
		}
	}
}

struct ip_addr_list *ip_addr_list_find(struct ip_addr_list *tail, struct ip_addr *addr, struct ip_addr *netmask)
{
	struct ip_addr_list *el;
	if (tail == NULL)
		return NULL;
	el=tail=tail->next;
	do {
		if (ip_addr_cmp(&(el->ipaddr),addr) && 
				(netmask == NULL || 
				 ip_addr_cmp(&(el->netmask),netmask)))
			return el;
		el=el->next;
	} while (el != tail);
	return NULL;
}

struct ip_addr_list *ip_addr_list_maskfind(struct ip_addr_list *tail, struct ip_addr *addr)
{
	struct ip_addr_list *el;
	if (tail==NULL)
		return NULL;
	el=tail=tail->next;
	do {
		/*printf("ip_addr_list_maskfind ");
		ip_addr_debug_print(IP_DEBUG,&(el->ipaddr));
		printf(" - ");
		ip_addr_debug_print(IP_DEBUG,addr);
		printf(" - ");
		ip_addr_debug_print(IP_DEBUG,&(el->netmask));
		printf("\n"); */

		if (ip_addr_maskcmp(&(el->ipaddr),addr,&(el->netmask)))
			if ((ip_addr_islinkscope(&(el->ipaddr)) && ip_addr_islinkscope(addr)) ||
			    (!ip_addr_islinkscope(&(el->ipaddr)) && !ip_addr_islinkscope(addr)))
			return el;
		el=el->next;
	} while (el != tail);
	return NULL;
}

struct ip_addr_list *ip_addr_list_deliveryfind(struct ip_addr_list *tail, struct ip_addr *addr, struct ip_addr *sender)
{
	struct ip_addr_list *el;
	if (tail == NULL)
		return NULL;
	el=tail=tail->next;
	do {
		/*printf("ip_addr_list_deliveryfind ");
		ip_addr_debug_printf(&(el->ipaddr));
		printf(" - ");
		ip_addr_debug_printf(addr);
		printf(" - ");
		ip_addr_debug_printf(&(el->netmask));
		printf("\n"); */
		/* local address */
		if (ip_addr_cmp(&(el->ipaddr),addr))
			return el;
		/* bradcast only from local nodes */
		if (ip_addr_maskcmp(sender,&(el->ipaddr),&(el->netmask))) {
			/*printf("%x %x\n",(addr)->addr[3],((&(el->ipaddr))->addr[3] | 0xff000000));*/
			if (ip_addr_isallnode(addr)) {
				/*printf("direct\n");*/
				return el;
			}
			if (ip_addr_issolicited(addr,&(el->ipaddr))) {
				/*printf("solicited\n");*/
				return el;
			}
			if (ip_addr_is_v4comp(&(el->ipaddr)) && ip_addr_is_v4broadcast(addr,&el->ipaddr,&(el->netmask))) {
				/*printf("v4comp\n");*/
				return el;
			}
		}
		el=el->next;
	} while (el != tail);
	return NULL;
}

struct ip_addr_list *ip_addr_list_masquarade_addr(struct ip_addr_list *tail, u8_t ipv)
{
	struct ip_addr_list *el;
	if (tail==NULL)
		return NULL;

	/* FIX: we have ip_route_ipv6_select_source() and we should use it */

	if (ipv != 4 && ipv != 6)
		return NULL;



	el=tail=tail->next;
	do {
		if (ipv == 4) {
			if (ip_addr_is_v4comp(&el->ipaddr)) 
				return el;
		}
                else
			if (!(ip_addr_ismulticast(&el->ipaddr)) &&
			    !(ip_addr_islinkscope(&el->ipaddr)))
				return el;

		el=el->next;
	} while (el != tail);
	return NULL;
}

