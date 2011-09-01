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
#ifndef __LWIP_NETIF_H__
#define __LWIP_NETIF_H__

#include "lwip/opt.h"

#include "lwip/err.h"

#include "lwip/ip_addr.h"
#include "lwip/ip_route.h"

#include "lwip/inet.h"
#include "lwip/pbuf.h"

#define NETIF_LOOPIF 0
#define NETIF_TAPIF 1
#define NETIF_TUNIF 2
#define NETIF_VDEIF 3
#define NETIF_SLIRPIF 4
#define NETIF_SLIPIF 5
#define NETIF_NUMIF 6

#if IPv6_AUTO_CONFIGURATION
#include "lwip/ip_autoconf.h"
#endif

#if IPv6_ROUTER_ADVERTISEMENT
#include "lwip/ip_radv.h"
#endif

/** must be the maximum of all used hardware address lengths
    across all types of interfaces in use */
#define NETIF_MAX_HWADDR_LEN 6U

/** TODO: define the use (where, when, whom) of netif flags */

/** whether the network interface is 'up'. this is
 * a software flag used to control whether this network
 * interface is enabled and processes traffic.
 */
#define NETIF_FLAG_UP 0x1U
/** if set, the netif has broadcast capability */
#define NETIF_FLAG_BROADCAST 0x2U
/** if set, the netif is one end of a point-to-point connection */
#define NETIF_FLAG_POINTTOPOINT 0x04U
/** if set, the interface is configured using DHCP */
#define NETIF_FLAG_DHCP 0x08U
/** if set, the interface has an active link
 *  (set by the network interface driver) */
#define NETIF_FLAG_LINK_UP 0x10
/* not used buf kept for comaptibility with LWIP
#define NETIF_FLAG_ETHARP       0x20U
#define NETIF_FLAG_ETHERNET     0x40U
#define NETIF_FLAG_IGMP         0x80U
*/

/* Promisquous mode: pass all the traffic up to the stack */
#define NETIF_PROMISC 0x100U
/** if set, the netif id the loopback interface */
#define NETIF_FLAG_LOOPBACK 0x200U

/* if set use IPv6 AUTOCONF */
#define NETIF_FLAG_AUTOCONF 0x1000U
/* if set this interface supports Router Advertising */
#define NETIF_FLAG_RADV	    0x2000U

#define NETIF_STD_FLAGS (NETIF_FLAG_AUTOCONF)
#define NETIF_ADD_FLAGS (NETIF_FLAG_AUTOCONF | NETIF_FLAG_RADV)
#define NETIF_IFUP_FLAGS (NETIF_FLAG_DHCP)

/** Generic data structure used for all lwIP network interfaces.
 *  The following fields should be filled in by the initialization
 *  function for the device driver: hwaddr_len, hwaddr[], mtu, flags */

struct netif {
  /** pointer to next in linked list */
  struct netif *next;

  /** IP address configuration in network byte order */
	struct ip_addr_list *addrs;

  /** This function is called by the network device driver
   *  to pass a packet up the TCP/IP stack. */
  err_t (* input)(struct pbuf *p, struct netif *inp);

  /** This function is called by the IP module when it wants
   *  to send a packet on the interface. This function typically
   *  first resolves the hardware address, then sends the packet. */
  err_t (* output)(struct netif *netif, struct pbuf *p,
       struct ip_addr *ipaddr);

  /** This function is called by the ARP module when it wants
   *  to send a packet on the interface. This function outputs
   *  the pbuf as-is on the link medium. */
  err_t (* linkoutput)(struct netif *netif, struct pbuf *p);

#define NETIFCTL_CLEANUP 1
#define NETIFCTL_SLIRPSOCK_DGRAM 0x100
#define NETIFCTL_SLIRPSOCK_STREAM 0x101
	/* netif netifctl function */
  err_t (* netifctl)(struct netif *netif, int request, void *arg);

  /** This field can be set by the device driver and could point
   *  to state information for the device. */
  void *state;

#define NETIF_CHANGE_UP    1
#define NETIF_CHANGE_DOWN  2
#define NETIF_CHANGE_MTU   3
  void (* change)(struct netif *netif, u32_t type);

#if LWIP_DHCP
  /** the DHCP client state information for this netif */
  struct dhcp *dhcp;
#endif

#if IPv6_AUTO_CONFIGURATION
  struct autoconf *autoconf;
#endif

#if IPv6_ROUTER_ADVERTISEMENT
  struct radv *radv;
#endif

  /** number of bytes used in hwaddr */
  unsigned char hwaddr_len;
  /** link level hardware address of this interface */
  unsigned char hwaddr[NETIF_MAX_HWADDR_LEN];
  /** maximum transfer unit (in bytes) */
  u16_t mtu;
  /** link type */
  u8_t link_type;
  /** descriptive abbreviation */
  char name[2];
  /** number of this interface */
  u8_t num;
	/* unique id */
	u8_t id;
	/** NETIF_FLAG_* */
	u16_t flags;

#ifdef LWIP_NL
	u16_t type;
	/* type */
#endif

  /* Stack identifier */
  struct stack *stack;
};


struct netif_fddata {
	int fd;
	short events;
	struct netif *netif;
	void (*fun)(struct netif_fddata *fddata, short revents);
	void *opaque; 
	int flags;
	int refcnt;
};

/* netif_init() must be called first. */
void netif_init(struct stack *stack);

void netif_shutdown(struct stack *stack);

/* netif_cleanup() must be called for a final garbage collection. */
void netif_cleanup(struct stack *stack);

struct netif_fddata *netif_addfd(struct netif *netif, int fd, 
		void (*fun)(struct netif_fddata *fddata, short revents),
		void *opaque, int flags, short events);

void netif_thread_wake(struct stack *stack);

#define NETIF_ARGS_1SEC_POLL 0x1
/* range 0x1000-0x8000 reserved for LWSLIRP_LISTEN */

#if 0
struct netif_args {
	void (*fun)(struct netif *netif, int posfd, void *arg, short revents);
	struct netif *netif;
	void *funarg;
	int flags;
};
#endif

struct netif * netif_add(
	struct stack *stack,
	struct netif *netif, 
	void *state, 
	err_t (* init  )(struct netif *netif),
	err_t (* input )(struct pbuf *p, struct netif *netif),
	void  (* change)(struct netif *netif, u32_t type) );

u8_t netif_next_num(struct netif *netif,int netif_model);

int
netif_add_addr(struct netif *netif,struct ip_addr *ipaddr, struct ip_addr *netmask);
int
netif_del_addr(struct netif *netif,struct ip_addr *ipaddr, struct ip_addr *netmask);

void netif_remove(struct netif * netif);

struct ifreq;
int netif_ioctl(struct stack *stack, int cmd,struct ifreq *ifr);

/* Returns a network interface given its name. The name is of the form
   "et0", where the first two letters are the "name" field in the
   netif structure, and the digit is in the num field in the same
   structure. */
struct netif *netif_find(struct stack *stack, char *name);
struct netif *netif_find_id(struct stack *stack, int id);
struct netif * netif_find_direct_destination(struct stack *stack, struct ip_addr *addr);

/* These functions change interface state and inform IP layer */
void netif_set_up(struct netif *netif, int flags);
u8_t netif_is_up(struct netif *netif);
void netif_set_down(struct netif *netif);

/* These functions change interface state BUT DO NOT inform IP layer */
void netif_set_up_low(struct netif *netif);
void netif_set_down_low(struct netif *netif);


#endif /* __LWIP_NETIF_H__ */


/* void netif_set_default(struct netif *netif);
void netif_set_ipaddr(struct netif *netif, struct ip_addr *ipaddr);
void netif_set_netmask(struct netif *netif, struct ip_addr *netmast);
void netif_set_gw(struct netif *netif, struct ip_addr *gw);
void netif_set_up(struct netif *netif);
void netif_set_down(struct netif *netif);
u8_t netif_is_up(struct netif *netif); */


//struct netif *netif_add(struct netif *netif, 
//      void *state,
//      err_t (* init)(struct netif *netif),
//      err_t (* input)(struct pbuf *p, struct netif *netif));
