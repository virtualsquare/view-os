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
 *   51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#if LWIP_USERFILTER

#ifndef __USERFILTER_H__
#define __USERFILTER_H__

/*
 * Trip of IPv4/IPv6 packets throw Userfilter's hooks in the stack.
 *
 *                            Apps
 *                     .---> Lwipv6 --->.
 *                     |                |
 *                     |                |
 *                    [2]              [4]
 *                     |                |
 *                     |            [routing]
 *                     |                |
 *                     |                |
 *     +--->[1]--->[routing]-->[3]----->+--->[5]--->+
 *     |                                            |
 *     |                                            |
 *   input                                       output
 *   netif                                       netif
 *
 *  [1] PRE_ROUTING
 *  [2] LOCAL_IN
 *  [3] FORWARD
 *  [4] LOCAL_OUT
 *  [5] POST_ROUTING
 *
 * ATTENTION: When userfilter is enable, Fragmentation should be handled in a 
 *            particular way.
 *
 *            Ingoing packets are NOT reassembled BEFORE any PRE_ROUTING
 *            filtering [1]. User's hooks should use defragmentation
 *            function at [1] before any other operation.
 *
 *            Outgoing packets are fragmented AFTER any POST_ROUTING [5]
 *            filtering.  
 *
 *            In this way, filtering code is sure that it's working on
 *            entire packets.
 */

typedef enum {
	UF_IP_PRE_ROUTING = 0,      
	UF_IP_LOCAL_IN,         
	UF_IP_FORWARD,          
	UF_IP_LOCAL_OUT,        
	UF_IP_POST_ROUTING,     

	UF_IP_NUMHOOKS          
} uf_hook_t;


/* Hook handler verdicts. After computation an handler must
 * return one of these values.
 * ATTENTION: DO NOT change order or position of UF_DROP and UF_ACCEPT!
 */
typedef enum {
	UF_DROP,      /* packet must be dropped */ 
	UF_ACCEPT,    /* packet can pass to the next handler */
	UF_REPEAT,    /* packet have to repeat the last handler */
	UF_STOLEN,    /* packet has been "stolen" by the handler. */

	UF_MAX_VERDICT
} uf_verdict_t;


/* 
 * Hook handler function.
 * ATTENTION: hook handlers must not call pbuf_free() on 'p'. The handler
 * can return UF_DROP and tell to Userfilter to free the memory.
 */
typedef uf_verdict_t  uf_hookfun_t(uf_hook_t hooknum, struct pbuf **p,  struct netif *inif, struct netif *outif);

/* Hook handler priority */
typedef short int uf_priority_t; 

/* Hook handler descriptor */
struct uf_hook_handler
{
	struct uf_hook_handler *next; /* used internaly */

	uf_hook_t      hooknum;	 /* handled hook */
	uf_hookfun_t  *hook;	 /* User fills in from here down. */
	uf_priority_t  priority; /* ascending priority. */
};

/* Stack Hooks table. you SHOULD NOT access it directy! Possible race conditions. */
extern  struct uf_hook_handler  * uf_hooks_list[UF_IP_NUMHOOKS];

/*--------------------------------------------------------------------------*/
/* Functions */
/*--------------------------------------------------------------------------*/

/*
 * Initialize hooks. Call this first.
 */
int userfilter_init(void);

/* 
 * ATTENTION: don't register/unregister hooks when the stack is active.
 * These functions are not thread-safe.
 */

/* 
 * Register a new hook (with ascending priority). If there are other 
 * handlers with same priority, 'h' is registered after them. 
 * Return 1 on success, 0 on failure. 
 */
int uf_register_hook(struct uf_hook_handler *h);

/* 
 * Unregister a hook. On success returns 1. If 'h' is not found, 
 * return 0. 
 */
int uf_unregister_hook(struct uf_hook_handler *h);

/*
 * Pass 'p' to all handlers registered ad hook 'hooknum'.
 * Returns 1 if 'p' can go along (after a UF_ACCEPT verdict).
 * Return  0 if 'p' has been captured by one of the hooks. (after a UF_STOLEN)
 * Returns < 0 if 'p' has been dropped by a hook. (for a UF_DROP verdict).
 * If 'freedrop' is 1 then dropped packet 'p' is freed before exit.
 */
int uf_visit_hook(uf_hook_t  hooknum, struct pbuf **p, struct netif *in, struct netif *out, u8_t freebuf); 

#define UF_FREE_BUF      1
#define UF_DONTFREE_BUF  0

/*
 * Used inside ip6.c source. 
 */
#define UF_HOOK(hook, pbuf, inif, outif, freebuf) \
	({ int ___r = 1;                                                       \
	if (uf_hooks_list[(hook)] != NULL)                                  \
	___r = uf_visit_hook((hook), (pbuf), (inif), (outif), (freebuf)); \
	___r; /* return value */                                            \
	})
	

/*--------------------------------------------------------------------------*/
/* Debug */
/*--------------------------------------------------------------------------*/

#ifdef LWIP_DEBUG

#define STR_VERDICT(v) ( \
	(v)==UF_ACCEPT ? "ACCEPT" : \
	(v)==UF_DROP   ? "DROP"   : \
	(v)==UF_STOLEN ? "STOLEN" : \
	(v)==UF_REPEAT ? "REPEAT" : \
	"***BUG***" )

#define STR_HOOKNAME(hook) ( \
	(hook)==UF_IP_PRE_ROUTING  ? "PRE_ROUTING"  : \
	(hook)==UF_IP_LOCAL_IN     ? "LOCAL_IN"     : \
	(hook)==UF_IP_FORWARD      ? "FORWARD"      : \
	(hook)==UF_IP_LOCAL_OUT    ? "LOCAL_OUT"    : \
	(hook)==UF_IP_POST_ROUTING ? "POST_ROUTING" : \
	"***BUG***" )

#endif

#endif  /* USERFILTER */

#endif  /* LWIP_USERFILTER */

