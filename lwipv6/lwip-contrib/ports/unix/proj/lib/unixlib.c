/*
 * Copyright (c) 2001-2003 Swedish Institute of Computer Science.
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
 * Author: Kieran Mansley <kjm25@cam.ac.uk>
 *
 * $Id$
 */

/*-----------------------------------------------------------------------------------*/
/* unixlib.c
 *
 * The initialisation functions for a shared library
 *
 * You may need to configure this file to your own needs - it is only an example
 * of how lwIP can be used as a self initialising shared library.
 *
 * In particular, you should change the gateway, ipaddr, and netmask to be the values
 * you would like the stack to use.
 */
/*-----------------------------------------------------------------------------------*/
#include <stdio.h>
#include <unistd.h>
#include <time.h>

#include "lwip/sys.h"
#include "lwip/mem.h"
#include "lwip/memp.h"
#include "lwip/pbuf.h"
#include "lwip/tcp.h"
#include "lwip/tcpip.h"
#include "lwip/netif.h"
#include "lwip/stats.h"


#include "netif/vdeif.h"
#include "netif/tunif.h"
#include "netif/tapif.h"
#include "netif/loopif.h"

#ifdef IPv6_RADVCONF
#include "lwip/radvconf.h"
#endif

#define IFF_RUNNING 0x40


struct netif *lwip_vdeif_add(void *arg)
{
#ifndef IPv6_AUTO_CONFIGURATION
	struct ip_addr ipaddr, netmask;
#endif
	struct netif *pnetif;
	pnetif=mem_malloc(sizeof (struct netif));

	//netif_add(pnetif, arg, vdeif_init, tcpip_input);
	//tcpip_netif_add(pnetif, arg, vdeif_init, tcpip_input);
	tcpip_netif_add(pnetif, arg, vdeif_init, tcpip_input, tcpip_change);

#ifndef IPv6_AUTO_CONFIGURATION
	//IP6_ADDR(&ipaddr, 0xfe80,0x0,0x0,0x0,
	//		(pnetif->hwaddr[0]<<8 |pnetif->hwaddr[1]),
	//		(pnetif->hwaddr[2]<<8 | 0xff),
	//		(0xfe00 | pnetif->hwaddr[3]),
	//		(pnetif->hwaddr[4]<<8 |pnetif->hwaddr[5]));
	//IP6_ADDR(&netmask, 0xffff,0xffff,0xffff,0xffff,0x0,0x0,0x0,0x0);
	//netif_add_addr(pnetif,&ipaddr, &netmask);

	/* Link-scope address */
	IP6_ADDR_LINKSCOPE(&ipaddr, pnetif->hwaddr);
	IP6_ADDR(&netmask, 0xffff,0xffff,0xffff,0xffff,0x0,0x0,0x0,0x0);
	netif_add_addr(pnetif, &ipaddr, &netmask);

#endif
	return(pnetif);
}

struct netif *lwip_tapif_add(void *arg)
{
#ifndef IPv6_AUTO_CONFIGURATION
	struct ip_addr ipaddr, netmask;
#endif
	struct netif *pnetif;
	pnetif=mem_malloc(sizeof (struct netif));

	//netif_add(pnetif, arg, tapif_init, tcpip_input);
	tcpip_netif_add(pnetif, arg, tapif_init, tcpip_input, tcpip_change);

#ifndef IPv6_AUTO_CONFIGURATION
	//IP6_ADDR(&ipaddr, 0xfe80,0x0,0x0,0x0,
	//		(pnetif->hwaddr[0]<<8 |pnetif->hwaddr[1]),
	//		(pnetif->hwaddr[2]<<8 | 0xff),
	//		(0xfe00 | pnetif->hwaddr[3]),
	//		(pnetif->hwaddr[4]<<8 |pnetif->hwaddr[5]));
	//IP6_ADDR(&netmask, 0xffff,0xffff,0xffff,0xffff,0x0,0x0,0x0,0x0);
	//netif_add_addr(pnetif,&ipaddr, &netmask);

	/* Link-scope address */
	IP6_ADDR_LINKSCOPE(&ipaddr, pnetif->hwaddr);
	IP6_ADDR(&netmask, 0xffff,0xffff,0xffff,0xffff,0x0,0x0,0x0,0x0);
	netif_add_addr(pnetif, &ipaddr, &netmask);
#endif
	return(pnetif);
}

struct netif *lwip_tunif_add(void *arg)
{
#ifndef IPv6_AUTO_CONFIGURATION
	struct ip_addr ipaddr, netmask;
#endif	
	struct netif *pnetif;
	pnetif=mem_malloc(sizeof (struct netif));

	//netif_add(pnetif, arg, tunif_init, tcpip_input);
	//tcpip_netif_add(pnetif, arg, tunif_init, tcpip_input);
	tcpip_netif_add(pnetif, arg, tunif_init, tcpip_input, tcpip_change);

	/* missing? */

	/* Link-scope address */
#ifndef IPv6_AUTO_CONFIGURATION
	IP6_ADDR_LINKSCOPE(&ipaddr, pnetif->hwaddr);
	IP6_ADDR(&netmask, 0xffff,0xffff,0xffff,0xffff,0x0,0x0,0x0,0x0);
	netif_add_addr(pnetif, &ipaddr, &netmask);
#endif

	return(pnetif);
}

static void lwip_loopif_add()
{
	static struct netif loopif;
	struct ip_addr ipaddr, netmask;

	//netif_add(&loopif,NULL, loopif_init, tcpip_input);
	//tcpip_netif_add(&loopif,NULL, loopif_init, tcpip_input);
	tcpip_netif_add(&loopif,NULL, loopif_init, tcpip_input, tcpip_change);

	IP6_ADDR(&ipaddr, 0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x1);
	IP6_ADDR(&netmask, 0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff);
	netif_add_addr(&loopif,&ipaddr, &netmask);

	IP64_ADDR(&ipaddr, 127,0,0,1);
	IP64_MASKADDR(&netmask, 255,0,0,0);
	netif_add_addr(&loopif,&ipaddr, &netmask);
}

int lwip_add_addr(struct netif *netif,struct ip_addr *ipaddr, struct ip_addr *netmask)
{
	return netif_add_addr(netif,ipaddr,netmask);
}

int lwip_del_addr(struct netif *netif,struct ip_addr *ipaddr, struct ip_addr *netmask)
{
	return netif_del_addr(netif,ipaddr,netmask);
}

int lwip_add_route(struct ip_addr *addr, struct ip_addr *netmask, struct ip_addr *nexthop, struct netif *netif, int flags)
{
	if (netif==NULL) 
		netif=netif_find_direct_destination(nexthop);
	if (netif==NULL)
		return -ENETUNREACH;
	else
		return ip_route_list_add(addr,netmask,nexthop,netif,flags);
}

int lwip_del_route(struct ip_addr *addr, struct ip_addr *netmask, struct ip_addr *nexthop, struct netif *netif, int flags)
{
	if (netif==NULL) 
		netif=netif_find_direct_destination(nexthop);
	if (netif==NULL)
		return -ENETUNREACH;
	else
		return ip_route_list_del(addr,netmask,nexthop,netif,flags);
}

int lwip_ifup(struct netif *netif)
{
	netif_set_up(netif);
	return 0;
}

int lwip_ifdown(struct netif *netif)
{
	netif_set_down(netif);
	return 0;
}

int lwip_radv_load_configfile(void *arg)
{
#ifdef IPv6_RADVCONF
	return radv_load_configfile((char*)arg);
#endif
	return -1;
}





extern int _nofdfake;
static void
init_done(void *arg)
{
	sys_sem_t *sem;
	sem = arg;
	
	if (!_nofdfake) /* no extra messages for umview! */
		printf("unixlib: lwip init done\n");
	
	sys_sem_signal(*sem);
}

static void
shutdown_done(void *arg)
{
	sys_sem_t *sem;
	sem = arg;
	
	if (!_nofdfake) /* no extra messages for umview! */
		printf("unixlib: lwip shutdown done\n");
	
	sys_sem_signal(*sem);
}


void _init(void){
	sys_sem_t sem;

	if (getenv("_INSIDE_UMVIEW_MODULE") != NULL)
		_nofdfake=1;
	srand(getpid()+time(NULL));
	
	/* Init stack's structures */
	stats_init();
	sys_init();
	mem_init();
	memp_init();
	pbuf_init();
	netif_init();

	sem = sys_sem_new(0);
	tcpip_init(init_done, &sem);
	sys_sem_wait(sem);
	sys_sem_free(sem);

	/* Add loop interface at least */	
	lwip_loopif_add();
}

void _fini(void){
	sys_sem_t sem;

	sem = sys_sem_new(0);
	tcpip_shutdown(shutdown_done, &sem);
	sys_sem_wait(sem);
	sys_sem_free(sem);

	netif_cleanup();
}
