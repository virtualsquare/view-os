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

#ifdef LWIP_USERFILTER

#include "lwip/debug.h"
#include "lwip/netif.h"
#include "lwip/userfilter.h"


#ifndef USERFILTER_DEBUG
#define USERFILTER_DEBUG     DBG_OFF
#endif

/****************************************************************************/
/* Variabiles */
/****************************************************************************/

/* Table of registered hooks */
struct uf_hook_handler  * uf_hooks_list[UF_IP_NUMHOOKS];

/****************************************************************************/
/* Functions */
/****************************************************************************/

int userfilter_init(void)
{
	int i;
	
	LWIP_DEBUGF(USERFILTER_DEBUG, ("%s: init hooks table\n", __func__));
	for (i=0; i < UF_IP_NUMHOOKS; i++)
		uf_hooks_list[i] = NULL;
	
	return 1;
}

int uf_register_hook(struct uf_hook_handler *h)
{
	int ret = 0;
	struct uf_hook_handler *current;
	struct uf_hook_handler *last;
	
	/* Find the first registered hook with priority greater than 'h' */
	last = NULL;
	current = uf_hooks_list[h->hooknum] ;
	while (current != NULL)
	{
		/* found the handler  position in the hook */
		if (current->priority > h->priority) 
			break;
		last = current;
		current = current->next;
	}

	h->next = current;

	/* if 'h' is not the first element of the list */
	if (last != NULL) 
		last->next = h;
	else
		uf_hooks_list[h->hooknum] = h;
	
	ret = 1;
	LWIP_DEBUGF(USERFILTER_DEBUG, ("%s: registered hook %s, p=%p fun=%p\n", __func__, STR_HOOKNAME (h->hooknum), h, h->hook));

	return ret;
}
	
int uf_unregister_hook(struct uf_hook_handler *h)
{
	int ret = 0;
	struct uf_hook_handler *current;
	struct uf_hook_handler *last;
	
	/* Find 'h' in the list of registered hooks */
	last = NULL;
	current = uf_hooks_list[h->hooknum] ;
	while (current != NULL)
	{
		/* found */
		if (current == h) {
			/* if 'h' is the first element */
			if (last == NULL)
				uf_hooks_list[h->hooknum]  = h->next;
			else
				last->next = h->next;
			h->next = NULL;
			ret = 1;
		}
		
		last = current;
		current = current->next;
	}

	if (ret == 1)	
		LWIP_DEBUGF(USERFILTER_DEBUG, ("%s: hook %s, unregistered handler p=%p fun=%p\n", __func__, STR_HOOKNAME(h->hooknum), h, h->hook));
	else
		LWIP_DEBUGF(USERFILTER_DEBUG, ("%s: hook %s, not found handler p=%p fun=%p\n", __func__, STR_HOOKNAME(h->hooknum), h, h->hook));

	return ret;
}


static inline uf_verdict_t uf_iterate(uf_hook_t  hooknum, struct pbuf **p, struct netif *in, struct netif *out)
{
	struct uf_hook_handler *currhook;
	uf_verdict_t ret=UF_ACCEPT;

	LWIP_DEBUGF(USERFILTER_DEBUG, ("\n%s: %s START (pbuf=%p)\n", __func__, STR_HOOKNAME(hooknum), *p));
	
	currhook = uf_hooks_list[hooknum];
	while (currhook != NULL)
	{
		LWIP_DEBUGF(USERFILTER_DEBUG, ("%s: hook=%p...\n", __func__, currhook->hook));
		ret = currhook->hook(hooknum, p, in, out);
		if (ret != UF_ACCEPT) {
			if (ret == UF_REPEAT) {
				LWIP_DEBUGF(USERFILTER_DEBUG, ("%s: hook=%p need REPEAT!\n", __func__, currhook->hook));
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

int uf_visit_hook(uf_hook_t  hooknum, struct pbuf **p, struct netif *in, struct netif *out, u8_t freebuf)
{
	int ret = 0;

	ret = uf_iterate(hooknum, p, in, out);
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

	return ret;
}

#endif /* LWIP_USERFILTER */

