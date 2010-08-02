/*   This is part of LWIPv6
 *   
 *   LWIPV6_SLIRP interface
 *   Copyright 2010 Renzo Davoli University of Bologna - Italy
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
 *   51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * (some code from tapif interface by Adam Dunkels <adam@sics.se>, BSD)
 */


#include "lwip/opt.h"
#ifdef LWSLIRP

#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>

#include "lwip/debug.h"

#include "lwip/def.h"
#include "lwip/ip.h"
#include "lwip/mem.h"
#include "lwip/pbuf.h"
#include "lwip/sys.h"

#include "netif/etharp.h"

#ifdef IPv6_AUTO_CONFIGURATION
#include "lwip/ip_autoconf.h"
#endif

#if LWIP_NL
#include "lwip/arphdr.h"
#endif

#if defined(LWIP_DEBUG) && defined(LWIP_TCPDUMP)
#include "netif/tcpdump.h"
#endif /* LWIP_DEBUG && LWIP_TCPDUMP */

#include <sys/ioctl.h>
#include <sys/un.h>
#include <stdint.h>
#include <libgen.h>
#include <sys/poll.h>

/*-----------------------------------------------------------------------------------*/

#ifndef SLIRPIF_DEBUG
#define SLIRPIF_DEBUG    DBG_OFF
#endif

#define IFNAME0 's'
#define IFNAME1 'l'

/*-----------------------------------------------------------------------------------*/

static const struct eth_addr ethbroadcast = { {0xff, 0xff, 0xff, 0xff, 0xff, 0xff} };

struct slirpif {
	/* Add whatever per-interface state that is needed here. */
	char *path; /* for future msocket extension */
};

/* Forward declarations. */
static err_t slirpif_output(struct netif *netif, struct pbuf *p, struct ip_addr *ipaddr);

/* ctl: create slirp sockets */
static err_t slirpif_ctl(struct netif *netif, int request, void *arg)
{
	struct slirpif *slirpif = netif->state;

	if (slirpif) {
		switch (request) {
			case NETIFCTL_CLEANUP:
				if (slirpif->path)
					mem_free(slirpif->path);
				mem_free(slirpif);
				break;
			case NETIFCTL_SLIRPSOCK_DGRAM:
				return socket(AF_INET6, SOCK_DGRAM, 0);
				/* return msocket(slirpif->path, AF_INET6, SOCK_DGARM, 0); */
			case NETIFCTL_SLIRPSOCK_STREAM:
				return socket(AF_INET6, SOCK_STREAM, 0);
				/* return msocket(slirpif->path, AF_INET6, SOCK_STREAM, 0); */
		}
		return ERR_OK;
	}
}

static err_t slirpif_output(struct netif *netif, struct pbuf *p, struct ip_addr *ipaddr)
{
	struct pbuf *r, *q;
	char *ptr;
	LWIP_DEBUGF(SLIRPIF_DEBUG, ("%s: start\n",__func__));

	/*printf("slirpif_output %x:%x:%x:%x\n",
	   ipaddr->addr[0],
	   ipaddr->addr[1],
	   ipaddr->addr[2],
	   ipaddr->addr[3]); */

	if (! (netif->flags & NETIF_FLAG_UP)) {
		return ERR_OK;
	}

	//printf("VDEbuf_alloc\n");
	r = pbuf_alloc(PBUF_RAW, p->tot_len, PBUF_RAM);
	//printf("VDEbuf done\n");
	if (r != NULL) {
		ptr = r->payload;

		for(q = p; q != NULL; q = q->next) {
			memcpy(ptr, q->payload, q->len);
			ptr += q->len;
		}
		netif->input( r, netif );

		return ERR_OK;
	}

	return ERR_MEM;
}

/*-----------------------------------------------------------------------------------*/
/*
 * slirpif_init():
 *
 * Should be called at the beginning of the program to set up the
 * network interface. It calls the function low_level_init() to do the
 * actual setup of the hardware.
 *
 */
/*-----------------------------------------------------------------------------------*/
err_t slirpif_init(struct netif * netif)
{
	struct slirpif *slirpif;

	slirpif = mem_malloc(sizeof(struct slirpif));
	memset(slirpif, 0, sizeof(struct slirpif));
	if (!slirpif)
		return ERR_MEM;

	netif->state = slirpif;
	netif->name[0] = IFNAME0;
	netif->name[1] = IFNAME1;
	netif->link_type = NETIF_SLIRPIF;
	netif->num=netif_next_num(netif,NETIF_SLIRPIF);
	netif->output = slirpif_output;
	netif->netifctl = slirpif_ctl;
	netif->mtu = 65535;
	/* hardware address length */
	netif->hwaddr_len = 6;
	netif->flags |= NETIF_FLAG_BROADCAST;
#if LWIP_NL
	netif->type = ARPHRD_ETHER;
#endif

	return ERR_OK;
}
#endif

