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
 * This file is part of the lwIP TCP/IP stack.
 * 
 * Author: Adam Dunkels <adam@sics.se>
 *
 */
#ifndef __LWIPOPTS_H__
#define __LWIPOPTS_H__

/* ---------- Memory options ---------- */

/* MEM_ALIGNMENT: should be set to the alignment of the CPU for which
   lwIP is compiled. 4 byte alignment -> define MEM_ALIGNMENT to 4, 2
   byte alignment -> define MEM_ALIGNMENT to 2. */
#define MEM_ALIGNMENT           4

/* MEM_SIZE: the size of the heap memory. If the application will send
a lot of data that needs to be copied, this should be set high. */
//#define MEM_SIZE                1600
#define MEM_SIZE                65536

/* MEMP_NUM_PBUF: the number of memp struct pbufs. If the application
   sends a lot of data out of ROM (or other static memory), this
   should be set high. */
#define MEMP_NUM_PBUF           256
//#define MEMP_NUM_PBUF           16

/* MEMP_NUM_UDP_PCB: the number of UDP protocol control blocks. One
   per active UDP "connection". */
//#define MEMP_NUM_UDP_PCB        4
#define MEMP_NUM_UDP_PCB        8

/* MEMP_NUM_TCP_PCB: the number of simulatenously active TCP
   connections. */
//#define MEMP_NUM_TCP_PCB        5
#define MEMP_NUM_TCP_PCB        16

/* MEMP_NUM_TCP_PCB_LISTEN: the number of listening TCP
   connections. */
#define MEMP_NUM_TCP_PCB_LISTEN 8

/* MEMP_NUM_TCP_SEG: the number of simultaneously queued TCP
   segments. */
#define MEMP_NUM_TCP_SEG        16

/* MEMP_NUM_SYS_TIMEOUT: the number of simulateously active
   timeouts. */
//#define MEMP_NUM_SYS_TIMEOUT    3
#define MEMP_NUM_SYS_TIMEOUT    8


/* The following four are used only with the sequential API and can be
   set to 0 if the application only will use the raw API. */
/* MEMP_NUM_NETBUF: the number of struct netbufs. */
//#define MEMP_NUM_NETBUF         2
#define MEMP_NUM_NETBUF         8

/* MEMP_NUM_NETCONN: the number of struct netconns. */
//#define MEMP_NUM_NETCONN        4
#define MEMP_NUM_NETCONN        8

/* MEMP_NUM_APIMSG: the number of struct api_msg, used for
   communication between the TCP/IP stack and the sequential
   programs. */
#define MEMP_NUM_API_MSG        64

/* MEMP_NUM_TCPIPMSG: the number of struct tcpip_msg, which is used
   for sequential API communication and incoming packets. Used in
   src/api/tcpip.c. */
#define MEMP_NUM_TCPIP_MSG      64

/* These two control is reclaimer functions should be compiled
   in. Should always be turned on (1). */
#define MEM_RECLAIM             1
#define MEMP_RECLAIM            1


/* ---------- Pbuf options ---------- */

/* PBUF_POOL_SIZE: the number of buffers in the pbuf pool. */
//#define PBUF_POOL_SIZE          6
#define PBUF_POOL_SIZE          64

/* PBUF_POOL_BUFSIZE: the size of each pbuf in the pbuf pool. */
//#define PBUF_POOL_BUFSIZE       128
#define PBUF_POOL_BUFSIZE       32768

/* PBUF_LINK_HLEN: the number of bytes that should be allocated for a
   link level header. */
#define PBUF_LINK_HLEN          16


/* ---------- ARP options ---------- */

#define ARP_TABLE_SIZE      10

#define ARP_QUEUEING        1


/* ---------- IP options ---------- */

/* Define IP_FORWARD to 1 if you wish to have the ability to forward
   IP packets across network interfaces. If you are going to run lwIP
   on a device with only one network interface, define this to 0. */
#define IP_FORWARD              1

/* If defined to 1, IP options are allowed (but not parsed). If
   defined to 0, all packets with IP options are dropped. */
#define IP_OPTIONS              1

/* ---------- ICMP options ---------- */

#define ICMP_TTL                255


/* ---------- UDP options ---------- */

#define LWIP_UDP                1
#define UDP_TTL                 255


/* ---------- TCP options ---------- */

#define LWIP_TCP                1
#define TCP_TTL                 255

/* Controls if TCP should queue segments that arrive out of
   order. Define to 0 if your device is low on memory. */
#define TCP_QUEUE_OOSEQ         1

/* TCP Maximum segment size. */
//#define TCP_MSS                 128
//#define TCP_MSS                 1024
#define TCP_MSS                 1488

/* TCP sender buffer space (bytes). */
#define TCP_SND_BUF             32768

/* TCP sender buffer space (pbufs). This must be at least = 2 *
   TCP_SND_BUF/TCP_MSS for things to work. */
#define TCP_SND_QUEUELEN        4 * TCP_SND_BUF/TCP_MSS

/* TCP receive window. */
#define TCP_WND                 32768

/* Maximum number of retransmissions of data segments. */
#define TCP_MAXRTX              12

/* Maximum number of retransmissions of SYN segments. */
#define TCP_SYNMAXRTX           4


/* ---------- TCP/UDP sub-system thread ---------- */

/* TCP/UDP sub-system thread priority */
#define TCPIP_THREAD_PRIO       3


/* ---------- DHCP options ---------- */

/* Define LWIP_DHCP to 1 if you want DHCP configuration of
   interfaces. DHCP is not implemented in lwIP 0.5.1, however, so
   turning this on does currently not work. */
#define LWIP_DHCP               0

/* 1 if you want to do an ARP check on the offered address
   (recommended). */
#define DHCP_DOES_ARP_CHECK     1




/* ---------- Statistics options ---------- */
//#define STATS

/* By default, statistics are enabled */
#define LWIP_STATS   1

#ifdef STATS
#define LINK_STATS   1
#define IP_STATS     1
#define ICMP_STATS   1
#define UDP_STATS    1
#define TCP_STATS    1
#define MEM_STATS    1
#define MEMP_STATS   1
#define PBUF_STATS   1
#define SYS_STATS    1
#endif /* STATS */


/* ---------- Debug options ------------- */

#define DBG_MIN_LEVEL 0

#define DBG_TYPES_ON    (DBG_ON|DBG_TRACE|DBG_STATE|DBG_FRESH|DBG_HALT)

/* Memory Debug */
#define MEMP_DEBUG                  DBG_OFF
#define PBUF_DEBUG                  DBG_OFF

/* Ethernet layer debug */
#define ETHARP_DEBUG                DBG_OFF

	/* VDE interface debug */
	#define VDEIF_DEBUG         DBG_OFF

	/* TUN interface debug */
	#define TUNIF_DEBUG         DBG_OFF

	/* TAP interface debug */
	#define TAPIF_DEBUG         DBG_OFF

/* IP Layer debug */
#define IP_DEBUG                    DBG_OFF

#define ROUTE_DEBUG                 DBG_OFF


/* De/Fragmentation code (IPv4, IPv6) debug */
#if defined(IPv4_FRAGMENTATION) || defined (IPv6_FRAGMENTATION)
	#define IP_REASS_DEBUG      DBG_OFF
#endif

/* PathMTU Discovery Protocol debug. Code not working yet */
#ifdef IPv6_PMTU_DISCOVERY
	#define PMTU_DEBUG          DBG_OFF
#endif


#ifdef IPv6_AUTO_CONFIGURATION
	#define IP_AUTOCONF_DEBUG   DBG_OFF
#endif


#ifdef IPv6_ROUTER_ADVERTISEMENT
	#define IP_RADV_DEBUG       DBG_OFF
#endif
#ifdef IPv6_RADVCONF
	#define IP_RADVCONF_DEBUG   DBG_OFF
#endif



/* UserFilter sub-system debug  */
#ifdef LWIP_USERFILTER
	#define USERFILTER_DEBUG    DBG_OFF

/* NAT sub-system debug */
#ifdef LWIP_NAT
	#define NAT_DEBUG           DBG_OFF
#endif

#endif



/* ICMPv4/v6 protocol debug */
#define ICMP_DEBUG                  DBG_OFF

/* TCP/UDP sub-system debug */
#define TCPIP_DEBUG                 DBG_OFF

/* Sockets debug */
#define SOCKETS_DEBUG               DBG_OFF



#endif /* __LWIPOPTS_H__ */
