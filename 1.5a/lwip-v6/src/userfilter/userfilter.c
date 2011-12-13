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

#include "lwip/opt.h"
#include "lwip/def.h"
#include "lwip/debug.h"
#include "lwip/sys.h"
#include "lwip/netif.h"
#include "lwip/stack.h"

#if LWIP_USERFILTER

#include "lwip/userfilter.h"

//#ifndef USERFILTER_DEBUG
//#define USERFILTER_DEBUG     DBG_OFF
//#endif

/* linked list of filters */
struct uf_item {
	struct uf_item *next;
	struct uf_hook_handler *uf_h;
};

/* Table of registered hooks */
struct stack_userfilter {
	struct uf_item  *uf_hooks_list[UF_IP_NUMHOOKS];
	sys_sem_t uf_mutex;
};

/*--------------------------------------------------------------------------*/
/* Variabiles */
/*--------------------------------------------------------------------------*/

#define UF_LOCK(stack)     sys_sem_wait_timeout(stack->stack_userfilter->uf_mutex, 0)
#define UF_UNLOCK(stack)   sys_sem_signal(stack->stack_userfilter->uf_mutex)

/*--------------------------------------------------------------------------*/
/* Functions */
/*--------------------------------------------------------------------------*/

int 
userfilter_init(struct stack *stack)
{
	int i;
	
	stack->stack_userfilter=mem_malloc(sizeof(struct stack_userfilter));
	if (stack->stack_userfilter == NULL)
		return -1;
	else {
		stack->stack_userfilter->uf_mutex = sys_sem_new(1);

		LWIP_DEBUGF(USERFILTER_DEBUG, ("%s: init hooks table\n", __func__));
		for (i=0; i < UF_IP_NUMHOOKS; i++)
			stack->stack_userfilter->uf_hooks_list[i] = NULL;

		return 1;
	}
}

int 
userfilter_shutdown(struct stack *stack)
{
	if (stack->stack_userfilter == NULL)
		    return -1;
	else {
		int i;
		for (i=0; i < UF_IP_NUMHOOKS; i++) {
			struct uf_item *ufscan;
			ufscan=stack->stack_userfilter->uf_hooks_list[i];
			while(ufscan != NULL) {
				struct uf_item *ufold=ufscan;
				ufscan=ufscan->next;
				mem_free(ufold);
			}
		}
		mem_free(stack->stack_userfilter);
		stack->stack_userfilter=NULL;
		return 1;
	}
}

int uf_register_hook(struct stack *stack, struct uf_hook_handler *h)
{
	struct uf_item *current;
	struct uf_item *last;
	struct uf_item *new;

	if (stack->stack_userfilter == NULL)
		return -1;
	
	UF_LOCK(stack);

	if (h->hooknum < UF_IP_PRE_ROUTING || h->hooknum > UF_IP_POST_ROUTING) {
		LWIP_DEBUGF(USERFILTER_DEBUG, ("%s: wrong hook number %d...\n", __func__, h->hooknum));
		UF_UNLOCK(stack);
		return -1 ;
	}

	new=mem_malloc(sizeof(struct uf_item));
	if (new==NULL) {
		UF_UNLOCK(stack);
		return -1 ;
	}
	new->uf_h = h;
	    
	/* Find the first registered hook with priority greater than 'h' */
	last = NULL;
	current = stack->stack_userfilter->uf_hooks_list[h->hooknum] ;
	while (current != NULL)
	{
		/* found the handler  position in the hook */
		if (current->uf_h->priority > h->priority) 
			break;
		last = current;
		current = current->next;
	}

	new->next = current;

	/* if 'h' is not the first element of the list */
	if (last != NULL) 
		last->next = new;
	else
		stack->stack_userfilter->uf_hooks_list[h->hooknum] = new;
	
	LWIP_DEBUGF(USERFILTER_DEBUG, ("%s: registered hook %s, p=%p fun=%p\n", __func__, STR_HOOKNAME (h->hooknum), h, h->hook));

	UF_UNLOCK(stack);

	return 1;
}
	
int uf_unregister_hook(struct stack *stack, struct uf_hook_handler *h)
{
	int ret = 0;
	struct uf_item *current;
	struct uf_item *last;
	
	if (stack->stack_userfilter == NULL)
		return -1;
	
	UF_LOCK(stack);

	if (h->hooknum < UF_IP_PRE_ROUTING || h->hooknum > UF_IP_POST_ROUTING) {
		LWIP_DEBUGF(USERFILTER_DEBUG, ("%s: wrong hook number %d...\n", __func__, h->hooknum));
		UF_UNLOCK(stack);
		return -1 ;
	}

	/* Find 'h' in the list of registered hooks */
	last = NULL;
	current = stack->stack_userfilter->uf_hooks_list[h->hooknum] ;
	while (current != NULL)
	{
		/* found */
		if (current->uf_h == h) {
			/* if 'h' is the first element */
			if (last == NULL)
				stack->stack_userfilter->uf_hooks_list[h->hooknum]  = current->next;
			else
				last->next = current->next;
			mem_free(current);
			ret = 1;
			break;
		}
		
		last = current;
		current = current->next;
	}

	if (ret == 1)	
		LWIP_DEBUGF(USERFILTER_DEBUG, ("%s: hook %s, unregistered handler p=%p fun=%p\n", __func__, STR_HOOKNAME(h->hooknum), h, h->hook));
	else
		LWIP_DEBUGF(USERFILTER_DEBUG, ("%s: hook %s, not found handler p=%p fun=%p\n", __func__, STR_HOOKNAME(h->hooknum), h, h->hook));

	UF_UNLOCK(stack);

	return ret;
}


INLINE static uf_verdict_t 
uf_iterate(struct stack *stack, uf_hook_t  hooknum, struct pbuf **p, struct netif *in, struct netif *out)
{
	struct uf_item *currhook;
	uf_verdict_t ret = UF_ACCEPT;

	LWIP_DEBUGF(USERFILTER_DEBUG, ("\n%s: %s START (pbuf=%p)\n", __func__, STR_HOOKNAME(hooknum), *p));
	
	currhook = stack->stack_userfilter->uf_hooks_list[hooknum];
	while (currhook != NULL)
	{
		LWIP_DEBUGF(USERFILTER_DEBUG, ("%s: hook=%p...\n", __func__, currhook->uf_h->hook));
		ret = currhook->uf_h->hook(stack, hooknum, p, in, out);
		if (ret != UF_ACCEPT) {
			if (ret == UF_REPEAT) {
				LWIP_DEBUGF(USERFILTER_DEBUG, ("%s: hook=%p need REPEAT!\n", __func__, currhook->uf_h->hook));
				/* repeat last */
				continue;
			} else
				break;
		}
		currhook = currhook->next;
	}

	LWIP_DEBUGF(USERFILTER_DEBUG, ("%s: %s STOP -> %s \n", __func__,  STR_HOOKNAME(hooknum), STR_VERDICT(ret)));

	return ret;
}

int uf_visit_hook(struct stack *stack, uf_hook_t  hooknum, struct pbuf **p, struct netif *in, struct netif *out, u8_t freebuf)
{
	int ret = 0;

	if (stack->stack_userfilter == NULL)
		return -1;
	
	UF_LOCK(stack);

	ret = uf_iterate(stack, hooknum, p, in, out);
	if (ret == UF_ACCEPT)
		ret = 1;
	else 
	if (ret == UF_DROP) {
		if (freebuf == UF_FREE_BUF)
			pbuf_free(*p);
		ret = -1;
	}	
	else
	/* I know, this is paranoic! */
	if (ret == UF_STOLEN)
		ret = 0;

	UF_UNLOCK(stack);

	return ret;
}

#endif /* LWIP_USERFILTER */
