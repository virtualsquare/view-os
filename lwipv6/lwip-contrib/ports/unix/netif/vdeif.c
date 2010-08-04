/*   This is part of LWIPv6
 *   
 *   VDE (virtual distributed ethernet) interface for ale4net
 *   (based on tapif interface Adam Dunkels <adam@sics.se>)
 *   Copyright 2005 Renzo Davoli University of Bologna - Italy
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
 */

/* tapif interface Adam Dunkels <adam@sics.se>
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
 */

#include "lwip/opt.h"


#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
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
#include <libvdeplug_dyn.h>
#include <sys/poll.h>
#include <pwd.h>

struct vdepluglib vdeplug;

/*-----------------------------------------------------------------------------------*/

#ifndef VDEIF_DEBUG
#define VDEIF_DEBUG    DBG_OFF
#endif

#define IFNAME0 'v'
#define IFNAME1 'd'

/*-----------------------------------------------------------------------------------*/

static const struct eth_addr ethbroadcast = { {0xff, 0xff, 0xff, 0xff, 0xff, 0xff} };

struct vdeif {
	struct eth_addr *ethaddr;
	/* Add whatever per-interface state that is needed here. */
	VDECONN *vdefd;
	VDESTREAM *vdestream;
	int posfd;
};

/* Forward declarations. */
static void vdeif_input(struct netif *netif, int posfd, void *arg);
static void vdeif_stream_input(struct netif *netif, int posfd, void *arg);
static ssize_t vdeif_streampkt_input(void *opaque, void *buf, size_t count);
static err_t vdeif_output(struct netif *netif, struct pbuf *p, struct ip_addr *ipaddr);

#define BUFSIZE        2048
#define ETH_ALEN       6

/*-----------------------------------------------------------------------------------*/

static void
arp_timer(void *arg)
{
	etharp_tmr((struct netif *) arg );
	sys_timeout(ARP_TMR_INTERVAL, (sys_timeout_handler)arp_timer, arg);
}

#define MAXDESCR 128
/*-----------------------------------------------------------------------------------*/
static int low_level_init(struct netif *netif, char *path)
{
	struct vdeif *vdeif;
	int randaddr;
	char descr[MAXDESCR+1];

	libvdeplug_dynopen(vdeplug);

	if (!vdeplug.vde_close)
		return ERR_IF;

	vdeif = netif->state;

	randaddr = rand();

	/* Obtain MAC address from network interface. */

	/* (We just fake an address...) */
	vdeif->ethaddr->addr[0] = 0x2;
	vdeif->ethaddr->addr[1] = 0x2;
	vdeif->ethaddr->addr[2] = randaddr >> 24;
	vdeif->ethaddr->addr[3] = randaddr >> 16;
	vdeif->ethaddr->addr[4] = randaddr >> 8;
	vdeif->ethaddr->addr[5] = 0x6;

	/* Do whatever else is needed to initialize interface. */

	snprintf(descr, MAXDESCR, "%sLWIPv6 if=vd%c", 
		(getenv("_INSIDE_UMVIEW_MODULE") != NULL) ? "UMVIEW-" : "", 
		netif->num + '0');
	if (path==NULL || *path != '-') {
		vdeif->vdefd=vdeplug.vde_open(path,descr,NULL);
		vdeif->vdestream=NULL;
		if (vdeif->vdefd && 
				(vdeif->posfd=netif_addfd(netif, 
																	vdeplug.vde_datafd(vdeif->vdefd),
																	vdeif_input, NULL, 0))>=0
		 ) 
			return ERR_OK;
		else 
			return ERR_IF;
	} else {
		int fdin;
		int fdout;
		if (path[1]=0) {
			fdin=STDIN_FILENO;
			fdout=STDOUT_FILENO;
		} else {
			/* XXX not supported yet : connect to sockets or fifos */
			return ERR_IF;
		}
		vdeif->vdefd=NULL;
		vdeif->vdestream=vdeplug.vdestream_open(netif,fdout,vdeif_streampkt_input,NULL);
		if (vdeif->vdestream != NULL &&
				(vdeif->posfd=netif_addfd(netif, fdin, 
																	vdeif_stream_input, NULL, 0))>=0)
			return ERR_OK;
		else
			return ERR_IF;
	}
}

/* cleanup: garbage collection */
static err_t vdeif_ctl(struct netif *netif, int request, void *arg)
{
	struct vdeif *vdeif = netif->state;

	if (vdeif) {

		switch (request) {
			case NETIFCTL_CLEANUP:
				if (vdeif->vdefd)
					vdeplug.vde_close(vdeif->vdefd);
				if (vdeif->vdestream)
					vdeplug.vdestream_close(vdeif->vdestream);

				/* Unset ARP timeout on this interface */
				sys_untimeout((sys_timeout_handler)arp_timer, netif);

				netif_delfd(netif->stack, vdeif->posfd);
				mem_free(vdeif);
		}
	}
	return ERR_OK;
}


/*-----------------------------------------------------------------------------------*/
/*
 * low_level_output():
 *
 * Should do the actual transmission of the packet. The packet is
 * contained in the pbuf that is passed to the function. This pbuf
 * might be chained.
 *
 */
/*-----------------------------------------------------------------------------------*/

static err_t low_level_output(struct netif *netif, struct pbuf *p)
{
	struct pbuf *q;
	char buf[1514];
	char *bufptr;
	struct vdeif *vdeif;

	LWIP_DEBUGF(VDEIF_DEBUG, ("%s: start\n", __func__));

	if (p->tot_len > 1514)
		return ERR_MEM;

	vdeif = netif->state;
	/* initiate transfer(); */

	bufptr = &buf[0];

	for (q = p; q != NULL; q = q->next) {
		/* Send the data from the pbuf to the interface, one pbuf at a
		   time. The size of the data in each pbuf is kept in the ->len
		   variable. */
		/* send data from(q->payload, q->len); */
		memcpy(bufptr, q->payload, q->len);
		bufptr += q->len;
	}

	if (vdeif->vdefd) {
		/* signal that packet should be sent(); */
		if (vdeplug.vde_send(vdeif->vdefd, buf, p->tot_len, 0) == -1) {
		}
	} else {
		if (vdeplug.vdestream_send(vdeif->vdestream, buf, p->tot_len) == -1) {
		}
	}

	LWIP_DEBUGF(VDEIF_DEBUG, ("%s: end\n", __func__));

	return ERR_OK;
}

/*-----------------------------------------------------------------------------------*/
/* low_level_pbuf_copy2pbuf
 */

static inline struct pbuf *low_level_pbuf_copy2pbuf(char *buf, u16_t len)
{
	struct pbuf *p, *q;
	char *bufptr;
	/* We allocate a pbuf chain of pbufs from the pool. */
	p = pbuf_alloc(PBUF_RAW, len, PBUF_POOL);
	if (p != NULL) {
		/* We iterate over the pbuf chain until we have read the entire
			 packet into the pbuf. */
		bufptr = &buf[0];
		for (q = p; q != NULL; q = q->next) {
			/* Read enough bytes to fill this pbuf in the chain. The
				 available data in the pbuf is given by the q->len
				 variable. */
			/* read data into(q->payload, q->len); */
			memcpy(q->payload, bufptr, q->len);
			bufptr += q->len;
		}
		/* acknowledge that packet has been read(); */
	}
	else {
		/* drop packet(); */
		fprintf(stderr, "vdeif: dropped packet (pbuf)\n");
	}
	return p;
}

/*-----------------------------------------------------------------------------------*/
/*
 * low_level_input():
 *
 * Should allocate a pbuf and transfer the bytes of the incoming
 * packet from the interface into the pbuf.
 *
 */
/*-----------------------------------------------------------------------------------*/

static struct pbuf *low_level_input(struct vdeif *vdeif, u16_t ifflags)
{
	struct pbuf *p;
	char buf[1514];
	u16_t len;

	LWIP_DEBUGF(VDEIF_DEBUG, ("%s: reading...\n", __func__));

	/* Obtain the size of the packet and put it into the "len" variable. */
	len = vdeplug.vde_recv(vdeif->vdefd, buf, sizeof(buf), 0);

	LWIP_DEBUGF(VDEIF_DEBUG, ("%s: read %d bytes (is UP? = %d)\n", __func__, len, ifflags & NETIF_FLAG_UP));

	//printf("MACS: %x:%x:%x:%x:%x:%x   %x:%x:%x:%x:%x:%x %x\n",
	//buf[0], buf[1], buf[2], buf[3], buf[4], buf[5],
	//vdeif->ethaddr->addr[0], vdeif->ethaddr->addr[1], vdeif->ethaddr->addr[2],
	//vdeif->ethaddr->addr[3], vdeif->ethaddr->addr[4], vdeif->ethaddr->addr[5],
	//ifflags); 

	if (!(ETH_RECEIVING_RULE(buf, vdeif->ethaddr->addr, ifflags))) {
		LWIP_DEBUGF(VDEIF_DEBUG, ("%s: RECEIVING_RULE = false\n", __func__));
		/*printf("PACKET DROPPED\n");
		   printf("%x:%x:%x:%x:%x:%x %x:%x:%x:%x:%x:%x %x\n",
		   buf[0], buf[1], buf[2], buf[3], buf[4], buf[5],
		   vdeif->ethaddr->addr[0], vdeif->ethaddr->addr[1], vdeif->ethaddr->addr[2],
		   vdeif->ethaddr->addr[3], vdeif->ethaddr->addr[4], vdeif->ethaddr->addr[5],
		   ifflags); */
		return NULL;
	}

	return low_level_pbuf_copy2pbuf(buf, len);
	return p;
}

static struct pbuf *low_level_stream_input(struct vdeif *vdeif, u16_t ifflags, 
		char *buf, u16_t len)
{
	struct pbuf *p;

	if (!(ETH_RECEIVING_RULE(buf, vdeif->ethaddr->addr, ifflags))) {
		LWIP_DEBUGF(VDEIF_DEBUG, ("%s: RECEIVING_RULE = false\n", __func__));
		/*printf("PACKET DROPPED\n");
			printf("%x:%x:%x:%x:%x:%x %x:%x:%x:%x:%x:%x %x\n",
			buf[0], buf[1], buf[2], buf[3], buf[4], buf[5],
			vdeif->ethaddr->addr[0], vdeif->ethaddr->addr[1], vdeif->ethaddr->addr[2],
			vdeif->ethaddr->addr[3], vdeif->ethaddr->addr[4], vdeif->ethaddr->addr[5],
			ifflags); */
		return NULL;
	}

	return low_level_pbuf_copy2pbuf(buf, len);
	return p;
}

/*-----------------------------------------------------------------------------------*/
/*
 * vdeif_output():
 *
 * This function is called by the TCP/IP stack when an IP packet
 * should be sent. It calls the function called low_level_output() to
 * do the actuall transmission of the packet.
 *
 */
/*-----------------------------------------------------------------------------------*/
static err_t vdeif_output(struct netif *netif, struct pbuf *p, struct ip_addr *ipaddr)
{
	LWIP_DEBUGF(VDEIF_DEBUG, ("%s: start\n",__func__));

	/*printf("vdeif_output %x:%x:%x:%x\n",
	   ipaddr->addr[0],
	   ipaddr->addr[1],
	   ipaddr->addr[2],
	   ipaddr->addr[3]); */
	if (!(netif->flags & NETIF_FLAG_UP)) {
		LWIP_DEBUGF(VDEIF_DEBUG, ("vdeif_output: interface DOWN, discarded\n"));
		return ERR_OK;
	}
	else {
		LWIP_DEBUGF(VDEIF_DEBUG, ("%s: output.\n",__func__));
		return etharp_output(netif, ipaddr, p);
	}
}

/*-----------------------------------------------------------------------------------*/
/* vdeif_input_dispatch
 * dispatch the packet to the upper layers 
 */
static inline void vde_dispatch_input(struct netif *netif, struct pbuf *p)
{
	struct vdeif *vdeif=netif->state;
	struct eth_hdr *ethhdr;

	ethhdr = p->payload;
	/* printf("vdeif_input %x %d\n",htons(ethhdr->type),p->tot_len); */

#ifdef LWIP_PACKET
	ETH_CHECK_PACKET_IN(netif, p);
#endif
	switch (htons(ethhdr->type)) {
#ifdef IPv6
		case ETHTYPE_IP6:
		case ETHTYPE_IP:
#else
		case ETHTYPE_IP:
#endif
			LWIP_DEBUGF(VDEIF_DEBUG, ("vdeif_input: IP packet\n"));
			etharp_ip_input(netif, p);
			pbuf_header(p, -14);
#if defined(LWIP_DEBUG) && defined(LWIP_TCPDUMP)
			tcpdump(p);
#endif /* LWIP_DEBUG && LWIP_TCPDUMP */
			netif->input(p, netif);
			break;
		case ETHTYPE_ARP:
			LWIP_DEBUGF(VDEIF_DEBUG, ("vdeif_input: ARP packet\n"));
			etharp_arp_input(netif, vdeif->ethaddr, p);
			break;
		default:
			pbuf_free(p);
			break;
	}
}


/*-----------------------------------------------------------------------------------*/
/*
 * vdeif_input():
 *
 * This function should be called when a packet is ready to be read
 * from the interface. It uses the function low_level_input() that
 * should handle the actual reception of bytes from the network
 * interface.
 *
 */
/*-----------------------------------------------------------------------------------*/
static void vdeif_input(struct netif *netif, int posfd, void *arg)
{
	struct vdeif *vdeif=netif->state;
	struct pbuf *p;

	p = low_level_input(vdeif, netif->flags);

	if (p == NULL) {
		LWIP_DEBUGF(VDEIF_DEBUG, ("vdeif_input: low_level_input returned NULL\n"));
		return;
	}

	vde_dispatch_input(netif, p);
}

static void vdeif_stream_input(struct netif *netif, int posfd, void *arg)
{
	struct vdeif *vdeif=netif->state;
	char buf[1514];
	u16_t len;

	len=read(netif->stack->netif_pfd[posfd].fd,buf,1514);
	vdeplug.vdestream_recv(vdeif->vdestream,buf,len);
}

static ssize_t vdeif_streampkt_input(void *opaque, void *buf, size_t count)
{
	struct netif *netif=opaque;
	struct vdeif *vdeif=netif->state;
	struct pbuf *p;

	p = low_level_stream_input(vdeif, netif->flags, buf, count);
	if (p == NULL) {
		LWIP_DEBUGF(VDEIF_DEBUG, ("vdeif_input: low_level_input returned NULL\n"));
		return;
	}

	vde_dispatch_input(netif, p);
	return count;
}

/*-----------------------------------------------------------------------------------*/
/*
 * vdeif_init():
 *
 * Should be called at the beginning of the program to set up the
 * network interface. It calls the function low_level_init() to do the
 * actual setup of the hardware.
 *
 */
/*-----------------------------------------------------------------------------------*/
err_t vdeif_init(struct netif * netif)
{
	struct vdeif *vdeif;
	char *path;

	vdeif = mem_malloc(sizeof(struct vdeif));
	memset(vdeif, 0, sizeof(struct vdeif));
	if (!vdeif)
		return ERR_MEM;

	path = netif->state; /*state is temporarily used to store the VDE path */
	netif->state = vdeif;
	netif->name[0] = IFNAME0;
	netif->name[1] = IFNAME1;
	netif->link_type = NETIF_VDEIF;
	netif->num=netif_next_num(netif,NETIF_VDEIF);
	netif->output = vdeif_output;
	netif->linkoutput = low_level_output;
	netif->netifctl = vdeif_ctl;
	netif->mtu = 1500;
	/* hardware address length */
	netif->hwaddr_len = 6;
	netif->flags |= NETIF_FLAG_BROADCAST;
#if LWIP_NL
	netif->type = ARPHRD_ETHER;
#endif

	vdeif->ethaddr = (struct eth_addr *) &(netif->hwaddr[0]);
	if (low_level_init(netif, path) < 0) {
		mem_free(vdeif);
		return ERR_IF;
	}

	etharp_init();

	sys_timeout(ARP_TMR_INTERVAL, (sys_timeout_handler)arp_timer, netif);

	return ERR_OK;
}

/*-----------------------------------------------------------------------------------*/

	//tv.tv_sec = ARP_TMR_INTERVAL / 1000;
	//tv.tv_usec = (ARP_TMR_INTERVAL % 1000) * 1000;

	//while (1) {
		//ret = select(vdeif->fddata + 1, &fdset, NULL, NULL, NULL);
		//if (tv.tv_sec == 0 && tv.tv_usec == 0) {
		//	etharp_tmr(netif);
		//	tv.tv_sec = ARP_TMR_INTERVAL / 1000;
		//	tv.tv_usec = (ARP_TMR_INTERVAL % 1000) * 1000;
		//}
