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
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
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


#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>

#include "lwip/debug.h"

#include "lwip/opt.h"
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

#ifdef linux
#include <sys/ioctl.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <stdint.h>
#include <libgen.h>
#include "vde.h"
#include <sys/poll.h>
#include <pwd.h>

#endif /* linux */

#ifndef VDEIF_DEBUG
#define VDEIF_DEBUG    DBG_OFF
#endif

#define IFNAME0 'v'
#define IFNAME1 'd'

static const struct eth_addr ethbroadcast = { {0xff, 0xff, 0xff, 0xff, 0xff, 0xff} };

struct vdeif {
	struct eth_addr *ethaddr;
	/* Add whatever per-interface state that is needed here. */
	int connected_fd;
	int fddata;
	struct sockaddr_un dataout;
	struct sockaddr_un datain;
	int intno;
};

/* Forward declarations. */
static void vdeif_input(struct netif *netif);
static err_t vdeif_output(struct netif *netif, struct pbuf *p, struct ip_addr *ipaddr);

static void vdeif_thread(void *data);

#define SWITCH_MAGIC   0xfeedface
#define BUFSIZE        2048
#define ETH_ALEN       6

enum request_type { REQ_NEW_CONTROL, REQ_NEW_PORT0 };

#define MAXDESCR 128
struct request_v3 {
	uint32_t magic;
	uint32_t version;
	enum request_type type;
	struct sockaddr_un sock;
	char description[MAXDESCR];
};


static int send_fd(char *name, int fddata, struct sockaddr_un *datasock, struct sockaddr_un *datain, int intno, int ifnum)
{
	int pid = getpid();
	struct request_v3 req;
	int fdctl;
	struct passwd *callerpwd;
	int port = 0;
	enum request_type rtype = REQ_NEW_CONTROL;
	struct sockaddr_un sock;

	callerpwd = getpwuid(getuid());

	if ((fdctl = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		return ERR_IF;
	}

	if (name == NULL)
		name = VDESTDSOCK;
	else {
		char *split;

		if (name[strlen(name) - 1] == ']' && (split = rindex(name, '[')) != NULL) {
			*split = 0;
			split++;
			port = atoi(split);
			if (port == 0)
				rtype = REQ_NEW_PORT0;
			if (*name == 0)
				name = VDESTDSOCK;
		}
	}

	sock.sun_family = AF_UNIX;
	snprintf(sock.sun_path, sizeof(sock.sun_path), "%s/ctl", name);
	LWIP_DEBUGF(VDEIF_DEBUG, ("vdeif: connecting to '%s'.\n", sock.sun_path));
	if (connect(fdctl, (struct sockaddr *) &sock, sizeof(sock))) {
		if (name == VDESTDSOCK) {
			name = VDETMPSOCK;
			snprintf(sock.sun_path, sizeof(sock.sun_path), "%s/ctl", name);
			LWIP_DEBUGF(VDEIF_DEBUG, ("vdeif: connecting to '%s'.\n", sock.sun_path));
			if (connect(fdctl, (struct sockaddr *) &sock, sizeof(sock))) {
				snprintf(sock.sun_path, sizeof(sock.sun_path), "%s", name);
				if (connect(fdctl, (struct sockaddr *) &sock, sizeof(sock))) {
					return ERR_IF;
				}
			}
		}
		/* added for compatibility with old versions of vde_switch */
		else {
			snprintf(sock.sun_path, sizeof(sock.sun_path), "%s", name);
			LWIP_DEBUGF(VDEIF_DEBUG, ("vdeif: connecting to '%s'.\n", sock.sun_path));
			if (connect(fdctl, (struct sockaddr *) &sock, sizeof(sock))) {
				return ERR_IF;
			}
		}

	}

	req.magic = SWITCH_MAGIC;
	req.version = 3;
	req.type = rtype + (port << 8);
	req.sock.sun_family = AF_UNIX;
	snprintf(req.description, MAXDESCR, "%sLWIPv6 user=%s PID=%d if=vd%c", 
		(getenv("_INSIDE_UMVIEW_MODULE") != NULL) ? "UMVIEW-" : "", 
		callerpwd->pw_name, getpid(), ifnum + '0');

	/* First choice, return socket from the switch close to the control dir */
	memset(req.sock.sun_path, 0, sizeof(req.sock.sun_path));
	sprintf(req.sock.sun_path, "%s.%05d-%02d", name, pid, intno);
	if (bind(fddata, (struct sockaddr *) &req.sock, sizeof(req.sock)) < 0) {
		/* if it is not possible -> /tmp */
		memset(req.sock.sun_path, 0, sizeof(req.sock.sun_path));
		sprintf(req.sock.sun_path, "/tmp/vde.%05d-%02d", pid, intno);
		if (bind(fddata, (struct sockaddr *) &req.sock, sizeof(req.sock)) < 0)
			return ERR_IF;
	}
	memcpy(datain, &req.sock, sizeof(struct sockaddr_un));

	if (send(fdctl, &req, sizeof(req) - MAXDESCR + strlen(req.description), 0) < 0) {
		return ERR_IF;
	}

	if (recv(fdctl, datasock, sizeof(struct sockaddr_un), 0) < 0) {
		return ERR_IF;
	}

	return fdctl;
}

static char *mem_strdup(const char *s)
{
	if (s == NULL)
		return NULL;
	else {
		int l = strlen(s);
		char *rv;

		if ((rv = mem_malloc(l + 1)) == NULL)
			return NULL;
		else {
			strcpy(rv, s);
			return rv;
		}
	}
}

/*-----------------------------------------------------------------------------------*/
static int low_level_init(struct netif *netif, char *path)
{
	struct vdeif *vdeif;
	int randaddr;

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

	vdeif->intno = netif->num;
	if ((vdeif->fddata = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0) {
		return ERR_IF;
	}
	vdeif->connected_fd = send_fd(path, vdeif->fddata, &(vdeif->dataout), &(vdeif->datain), vdeif->intno, netif->num);

	if (vdeif->connected_fd >= 0) {
		sys_thread_new(vdeif_thread, netif, DEFAULT_THREAD_PRIO);
		return ERR_OK;
	}
	else {
		return ERR_IF;
	}
}

/* cleanup: garbage collection */
static err_t cleanup(struct netif *netif)
{
	struct vdeif *vdeif = netif->state;

	if (vdeif) {
		unlink(vdeif->datain.sun_path);
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

	/* signal that packet should be sent(); */
	if (sendto(vdeif->fddata, buf, p->tot_len, 0, (struct sockaddr *) &(vdeif->dataout), sizeof(struct sockaddr_un)) == -1) {
	}
	return ERR_OK;
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
	struct pbuf *p, *q;
	u16_t len;
	char buf[1514];
	char *bufptr;
	struct sockaddr_un datain;
	socklen_t datainsize = sizeof(struct sockaddr_un);

	/* Obtain the size of the packet and put it into the "len" variable. */
	len = recvfrom(vdeif->fddata, buf, sizeof(buf), 0, (struct sockaddr *) &datain, &datainsize);

	if (!(ETH_RECEIVING_RULE(buf, vdeif->ethaddr->addr, ifflags))) {
		/*printf("PACKET DROPPED\n");
		   printf("%x:%x:%x:%x:%x:%x %x:%x:%x:%x:%x:%x %x\n",
		   buf[0], buf[1], buf[2], buf[3], buf[4], buf[5],
		   vdeif->ethaddr->addr[0], vdeif->ethaddr->addr[1], vdeif->ethaddr->addr[2],
		   vdeif->ethaddr->addr[3], vdeif->ethaddr->addr[4], vdeif->ethaddr->addr[5],
		   ifflags); */
		return NULL;
	}
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
static void vdeif_thread(void *arg)
{
	struct netif *netif;
	struct vdeif *vdeif;
	fd_set fdset;
	int ret;
	//struct timeval tv;

	netif = arg;
	vdeif = netif->state;

	//tv.tv_sec = ARP_TMR_INTERVAL / 1000;
	//tv.tv_usec = (ARP_TMR_INTERVAL % 1000) * 1000;

	while (1) {
		FD_ZERO(&fdset);
		FD_SET(vdeif->fddata, &fdset);

		LWIP_DEBUGF(VDEIF_DEBUG, ("vde_thread: waiting4packet\n"));
		/* Wait for a packet to arrive. */
		//ret = select(vdeif->fddata + 1, &fdset, NULL, NULL, &tv);
		ret = select(vdeif->fddata + 1, &fdset, NULL, NULL, NULL);

		//if (tv.tv_sec == 0 && tv.tv_usec == 0) {
		//	etharp_tmr(netif);
		//	tv.tv_sec = ARP_TMR_INTERVAL / 1000;
		//	tv.tv_usec = (ARP_TMR_INTERVAL % 1000) * 1000;
		//}

		if (ret == 1) {
			/* Handle incoming packet. */
			vdeif_input(netif);
		}
		else if (ret == -1 && errno != EINTR) {
			perror("vdeif_thread: select");
		}
	}
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
	/*printf("vdeif_output %x:%x:%x:%x\n",
	   ipaddr->addr[0],
	   ipaddr->addr[1],
	   ipaddr->addr[2],
	   ipaddr->addr[3]); */
	if (!(netif->flags & NETIF_FLAG_UP)) {
		LWIP_DEBUGF(VDEIF_DEBUG, ("vdeif_output: interface DOWN, discarded\n"));
		return ERR_OK;
	}
	else
		return etharp_output(netif, ipaddr, p);
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
static void vdeif_input(struct netif *netif)
{
	struct vdeif *vdeif;
	struct eth_hdr *ethhdr;
	struct pbuf *p;


	vdeif = netif->state;

	p = low_level_input(vdeif, netif->flags);

	if (p == NULL) {
		LWIP_DEBUGF(VDEIF_DEBUG, ("vdeif_input: low_level_input returned NULL\n"));
		return;
	}

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

static void
arp_timer(void *arg)
{
	etharp_tmr((struct netif *) arg );
	sys_timeout(ARP_TMR_INTERVAL, (sys_timeout_handler)arp_timer, arg);
}

//#ifdef IPv6_AUTO_CONFIGURATION  
//static void
//ipv6_autoconf_timer(void *arg)
//{
//	ip_autoconf_tmr((struct netif *) arg);
//	sys_timeout(AUTOCONF_TMR_INTERVAL, (sys_timeout_handler)ipv6_autoconf_timer, arg);
//}
//#endif

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
	static u8_t num = 0;
	char *path;

	vdeif = mem_malloc(sizeof(struct vdeif));
	memset(vdeif, 0, sizeof(struct vdeif));
	if (!vdeif)
		return ERR_MEM;

	path = netif->state; /*state is temporarily used to store the VDE path */
	netif->state = vdeif;
	netif->name[0] = IFNAME0;
	netif->name[1] = IFNAME1;
	netif->num = num++;
	netif->output = vdeif_output;
	netif->linkoutput = low_level_output;
	netif->cleanup = cleanup;
	netif->mtu = 1500;
	/* hardware address length */
	netif->hwaddr_len = 6;
	netif->flags |= NETIF_FLAG_BROADCAST;
#ifdef LWIP_NL
	netif->type = ARPHRD_ETHER;
#endif

	vdeif->ethaddr = (struct eth_addr *) &(netif->hwaddr[0]);
	if (low_level_init(netif, path) < 0) {
		mem_free(vdeif);
		return ERR_IF;
	}

	etharp_init();

	sys_timeout(ARP_TMR_INTERVAL, (sys_timeout_handler)arp_timer, netif);

//#ifdef IPv6_AUTO_CONFIGURATION
//	sys_timeout(AUTOCONF_TMR_INTERVAL, (sys_timeout_handler)ipv6_autoconf_timer, netif);
//#endif

	return ERR_OK;
}

/*-----------------------------------------------------------------------------------*/
