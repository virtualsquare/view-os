/*   This is part of Slirpvde6
 *   Developed for the VDE project
 *   Virtual Distributed Ethernet
 *   
 *   Copyright 2010 Renzo Davoli
 *	 based on the work of Andrea Forni 2005
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
#ifndef _LWSLIRP_H_
#define _LWSLIRP_H_

#ifdef LWSLIRP

#include <sys/socket.h>
#include <netinet/in.h>
#include "lwip/ip_addr.h"
#include "lwip/tcp.h"
#include "lwip/udp.h"
#include "lwip/err.h"

#if 0
#ifndef SOCKETVDE_DEBUG
#define SOCKETVDE_DEBUG 0x00U
#endif
#endif

/* 
 * Converts the struct in6_addr "from" to a the LWIP struct ip_addr "to".
 *
 * from: struct in6_addr *
 * to: struct ip_addr *
 */
#define  SO_IN6_ADDR2IP_ADDR(from, to) IP6_ADDR((to), \
		(((from)->s6_addr[0] << 8) | ((from)->s6_addr[1])), \
		(((from)->s6_addr[2] << 8) | ((from)->s6_addr[3])), \
		(((from)->s6_addr[4] << 8) | ((from)->s6_addr[5])), \
		(((from)->s6_addr[6] << 8) | ((from)->s6_addr[7])), \
		(((from)->s6_addr[8] << 8) | ((from)->s6_addr[9])), \
		(((from)->s6_addr[10] << 8) | ((from)->s6_addr[11])), \
		(((from)->s6_addr[12] << 8) | ((from)->s6_addr[13])), \
		(((from)->s6_addr[14] << 8) | ((from)->s6_addr[15])))
/* 
 * Converts the struct ip_addr "from" to a the struct in6_addr "to".
 *
 * from: struct ip_addr *
 * to: struct in6_addr *
 */
#define SO_IP_ADDR2IN6_ADDR(from, to) do { \
	(to)->s6_addr[0] = (from)->addr[0] & 0xffff; \
	(to)->s6_addr[1] = ((from)->addr[0] >> 8) & 0xffff; \
	(to)->s6_addr[2] = ((from)->addr[0] >> 16) & 0xffff; \
	(to)->s6_addr[3] = ((from)->addr[0] >> 24) & 0xffff; \
	\
	(to)->s6_addr[4] = (from)->addr[1] & 0xffff; \
	(to)->s6_addr[5] = ((from)->addr[1] >> 8) & 0xffff; \
	(to)->s6_addr[6] = ((from)->addr[1] >> 16) & 0xffff; \
	(to)->s6_addr[7] = ((from)->addr[1] >> 24) & 0xffff; \
	\
	(to)->s6_addr[8] = (from)->addr[2] & 0xffff; \
	(to)->s6_addr[9] = ((from)->addr[2] >> 8) & 0xffff; \
	(to)->s6_addr[10] = ((from)->addr[2] >> 16) & 0xffff; \
	(to)->s6_addr[11] = ((from)->addr[2] >> 24) & 0xffff; \
	\
	(to)->s6_addr[12] = (from)->addr[3] & 0xffff; \
	(to)->s6_addr[13] = ((from)->addr[3] >> 8) & 0xffff; \
	(to)->s6_addr[14] = ((from)->addr[3] >> 16) & 0xffff; \
	(to)->s6_addr[15] = ((from)->addr[3] >> 24) & 0xffff; \
}while(0)

/* 
 * Converts the struct in_addr "from" to a the LWIP struct ip_addr "to".
 *
 * from: struct in_addr *
 * to: struct ip_addr *
 */
#define  SO_IN_ADDR2IP_ADDR(from, to) IP64_ADDR((to), \
		(((from)->s_addr) & 0x000000ff), \
		((((from)->s_addr) >> 8) & 0x000000ff), \
		((((from)->s_addr) >> 16) & 0x000000ff), \
		((((from)->s_addr) >> 24) & 0x000000ff))

# if 0
/*
 * Socket state bits. (peer means the host on the Internet,
 * local host means the host on the other end of the modem)
 */

int so_ip_addr_cmp(struct in6_addr *addr1, struct ip_addr *addr2);

void so_recvfrom(struct udp_pcb *pcb);
void so_recvoob(struct tcp_pcb *pcb, fd_set *writefds);
int so_read (struct tcp_pcb *pcb, fd_set *writefds);
int so_write(struct tcp_pcb *pcb, fd_set *readfds, fd_set *xfds);

/* Callback functions registered into the TCP pcbs */
err_t so_tcp_accept(void *arg, struct tcp_pcb *pcb, err_t err);
err_t so_tcp_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err);

/* err_t so_tcp_connected(void *arg, struct tcp_pcb *pcb, err_t err) */
#if SOCKETVDE_DEBUG
void so_debug_print_state(int debk, struct tcp_pcb *pcb);
#else

#define so_debug_print_state(debk, pcb)

#endif /* SOCKETVDE_DEBUG*/
#endif

int slirp_tcp_fconnect(struct tcp_pcb_listen *lpcb, u16_t dest_port, 
		struct ip_addr *dest_addr, struct netif *slirpif);
void slirp_tcp_update_listen2data(struct tcp_pcb *pcb);
void slirp_tcp_close(struct tcp_pcb *pcb);
err_t slirp_tcp_accept(void *arg, struct tcp_pcb *pcb, err_t err);
err_t slirp_tcp_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err);

/* Callback function registered into the UDP pcbs */
#define UDP_PERMANENT 1
int slirp_udp_bind(struct udp_pcb *pcb, struct netif *slirpif, int flags);

void slirp_udp_recv(void *arg, struct udp_pcb *pcb, struct pbuf *p,
		struct ip_addr *addr, u16_t port);

/* lwipv6 keeps slirp listen items as 
	args for netif_fd structure (as there is an open socket per
 forwarded port */

#define SLIRP_LISTEN_UDP 0x1000
#define SLIRP_LISTEN_TCP 0x2000
#define SLIRP_LISTEN_UNIXSTREAM 0x3000
#define SLIRP_LISTEN_TYPEMASK 0x7000
#define SLIRP_LISTEN_ONCE 0x8000

int slirp_listen_add(struct netif *slirpif,
		struct ip_addr *dest,  u16_t destport,
		void *src,  u16_t srcport, int flags);

int slirp_listen_del(struct netif *slirpif,
		struct ip_addr *dest,  u16_t destport,
		void *src,  u16_t srcport, int flags);

#endif
#endif

