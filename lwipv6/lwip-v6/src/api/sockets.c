/*   This is part of LWIPv6
 *   Developed for the Ale4NET project
 *   Application Level Environment for Networking
 *   
 *   Copyright 2004 Renzo Davoli University of Bologna - Italy
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
 * Improved by Marc Boucher <marc@mbsi.ca> and David Haas <dhaas@alum.rpi.edu>
 *
 */

#include <linux/limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>

#include "lwip/opt.h"
#include "lwip/api.h"
#include "lwip/arch.h"
#include "lwip/sys.h"
#include "lwip/mem.h"

#define LWIP_TIMEVAL_PRIVATE
#include "lwip/sockets.h"

#ifdef LWIP_NL
#include "lwip/netlink.h"
#endif

#ifdef LWIP_PACKET
#include <netpacket/packet.h>
#endif

#include "lwip/native_syscalls.h"
#define NUM_SOCKETS MEMP_NUM_NETCONN

#define SOCK_IP64_CONV(ipaddr, ip4)  do { \
	(ipaddr)->addr[0] = 0; \
	(ipaddr)->addr[1] = 0; \
	(ipaddr)->addr[2] =  IP64_PREFIX; \
	memcpy(&((ipaddr)->addr[3]),(ip4),sizeof(struct ip4_addr)); } while (0)

#define SOCK_IP46_CONV(ip4, ipaddr)  (memcpy((ip4),&((ipaddr)->addr[3]),sizeof(struct ip4_addr)))
int _nofdfake = 0;

static char *domain_name(int domain) {
	switch (domain) {
		case PF_INET: return "PF_INET";
		case PF_INET6: return "PF_INET6";
#ifdef LWIP_NL
		case PF_NETLINK: return "PF_NETLINK";
#endif
#ifdef LWIP_PACKET
		case PF_PACKET: return "PF_PACKET";
#endif
	}
	return "UNKNOWN";
}

#define SO_REUSE 1

static short lwip_sockmap[OPEN_MAX];
#ifdef FAKE_SYSCALL
static char initialized=0;
#endif

struct lwip_socket {
	u16_t family;
	struct netconn *conn;
	struct netbuf *lastdata;
	u16_t lastoffset;
	u16_t rcvevent;
	u16_t sendevent;
	u16_t  flags;
	int fdfake;
	int err;
};

struct lwip_select_cb
{
	struct lwip_select_cb *next;
	int sem_signalled;
	fd_set *readset;
	fd_set *writeset;
	fd_set *exceptset;
	int pipe[2]; 
};


static struct lwip_socket sockets[NUM_SOCKETS];
static struct lwip_select_cb *select_cb_list = 0;
#ifdef LWIP_NL
#define NOT_CONN_SOCKET ((struct netconn *)(-1))
#endif

static sys_sem_t socksem = 0;
static sys_sem_t selectsem = 0;

static u16_t so_map[]={
	0, /*not used */
	SOF_DEBUG, /*SO_DEBUG*/
	SOF_REUSEADDR, /*SO_REUSEADDR*/
	0, /* SO_TYPE         */
	0, /* SO_ERROR        */
	SOF_DONTROUTE, /* SO_DONTROUTE    */
	SOF_BROADCAST, /* SO_BROADCAST    */
	0, /* SO_SNDBUF       */
	0, /* SO_RCVBUF       */
	SOF_KEEPALIVE, /* SO_KEEPALIVE    */
	SOF_OOBINLINE, /* SO_OOBINLINE    */
	0, /* SO_NO_CHECK     */
	0, /* SO_PRIORITY     */
	SOF_LINGER, /* SO_LINGER       */
	0, /* SO_BSDCOMPAT    */
	SOF_REUSEPORT, /* SO_REUSEPORT    */ 
	0, /* SO_RCVLOWAT     */
	0, /* SO_SNDLOWAT     */
	0, /* SO_RCVTIMEO     */
	0, /* SO_SNDTIMEO     */
	0, /* SO_PASSCRED     */
	0, /* SO_PEERCRED     */
	0, /* SO_SECURITY_AUTHENTICATION              */
	0, /* SO_SECURITY_ENCRYPTION_TRANSPORT        */
	0, /* SO_SECURITY_ENCRYPTION_NETWORK          */
	0, /* SO_BINDTODEVICE */
	0, /* SO_ATTACH_FILTER        */
	0, /* SO_DETACH_FILTER        */
	0, /* SO_PEERNAME             */
	0, /* SO_TIMESTAMP            */
	SOF_ACCEPTCONN /* SO_ACCEPTCONN           */
};

static void
event_callback(struct netconn *conn, enum netconn_evt evt, u16_t len);

static int err_to_errno_table[11] = {
	0,      /* ERR_OK    0      No error, everything OK. */
	ENOMEM,    /* ERR_MEM  -1      Out of memory error.     */
	ENOBUFS,    /* ERR_BUF  -2      Buffer error.            */
	ECONNABORTED,  /* ERR_ABRT -3      Connection aborted.      */
	ECONNRESET,    /* ERR_RST  -4      Connection reset.        */
	ESHUTDOWN,    /* ERR_CLSD -5      Connection closed.       */
	ENOTCONN,    /* ERR_CONN -6      Not connected.           */
	EINVAL,    /* ERR_VAL  -7      Illegal value.           */
	EIO,    /* ERR_ARG  -8      Illegal argument.        */
	EHOSTUNREACH,  /* ERR_RTE  -9      Routing problem.         */
	EADDRINUSE    /* ERR_USE  -10     Address in use.          */
};

#define ERRNO
#define err_to_errno(err) \
	(-(err) < (sizeof(err_to_errno_table)/sizeof(int))) ? \
err_to_errno_table[-(err)] : EIO

#ifdef ERRNO
int lwip_errno;
#define set_errno(err) do { \
	errno = (err); \
	lwip_errno = (err); \
} while (0)
#else
#define set_errno(err)
#endif

#define sock_set_errno(sk, e) do { \
	sk->err = (e); \
	set_errno(sk->err); \
} while (0)

	static struct lwip_socket *
get_socket(int s)
{
	struct lwip_socket *sock;
	int index=(int)lwip_sockmap[s];

	if ((index < 0) || (index > NUM_SOCKETS)) {
		LWIP_DEBUGF(SOCKETS_DEBUG, ("get_socket(%d): invalid\n", s));
		set_errno(EBADF);
		return NULL;
	}

	sock = &sockets[index];

	if (!sock->conn) {
		LWIP_DEBUGF(SOCKETS_DEBUG, ("get_socket(%d): not active\n", s));
		set_errno(EBADF);
		return NULL;
	}

	return sock;
}

extern int socket(int domain, int type, int protocol);
	static int
alloc_socket(struct netconn *newconn,u16_t family)
{
	int i,fd;

	if (!socksem)
		socksem = sys_sem_new(1);

	/* Protect socket array */
	sys_sem_wait(socksem);

	/* allocate a new socket identifier */
	for(i = 0; i < NUM_SOCKETS; ++i) {
		if (!sockets[i].conn) {
			sockets[i].family = family;
			sockets[i].conn = newconn;
			sockets[i].lastdata = NULL;
			sockets[i].lastoffset = 0;
			sockets[i].rcvevent = 0;
			sockets[i].sendevent = 1; /* TCP send buf is empty */
			sockets[i].flags = 0;
			sockets[i].err = 0;
			sys_sem_signal(socksem);
			/*
			 * it is better to open a fake socket to satisfy S_ISSOCK()*/
			//fd=open("/dev/null",O_RDONLY);
			/**/
			if (_nofdfake)
				fd=i;
			else
#ifdef FAKE_SYSCALL
				fd=native_socket(PF_INET, SOCK_DGRAM, 0);
#else
				fd=socket(PF_INET, SOCK_DGRAM, 0);
#endif
			if (fd < 0) {
				sys_sem_signal(socksem);
				return -1;
			} 
			//printf("alloc_socket %d %d %d\n",i,fd,NUM_SOCKETS);
			sockets[i].fdfake=fd;
			lwip_sockmap[fd]=i;
			return fd;
		}
	}
	sys_sem_signal(socksem);
	return -1;
}

	int
lwip_accept(int s, struct sockaddr *addr, socklen_t *addrlen)
{
	struct lwip_socket *sock;
	struct netconn *newconn;
	struct ip_addr naddr;
	u16_t port;
	int newsock;

	LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_accept(%d)...\n", s));
	sock = get_socket(s);
	if (!sock
#ifdef LWIP_NL
			|| sock->family == PF_NETLINK
#endif
#ifdef LWIP_PACKET
			|| sock->family == PF_PACKET
#endif
		 ) {
		set_errno(EBADF);
		return -1;
	}

	newconn = netconn_accept(sock->conn);

	/* get the IP address and port of the remote host */
	netconn_peer(newconn, &naddr, &port);

	if (sock->family == PF_INET) {
		struct sockaddr_in sin;
		memset(&sin, 0, sizeof(sin));
		sin.sin_family = sock->family;
		sin.sin_port = htons(port);
		/*memcpy(&(sin.sin_addr.s_addr),&(naddr.addr[3]),sizeof(sin.sin_addr.s_addr));*/
		SOCK_IP46_CONV(&(sin.sin_addr.s_addr),&(naddr));

		if (*addrlen > sizeof(sin))
			*addrlen = sizeof(sin);

		memcpy(addr, &sin, *addrlen);
	}           
	else {      
		struct sockaddr_in6 sin;
		memset(&sin, 0, sizeof(sin));
		sin.sin6_family = sock->family;
		sin.sin6_port = htons(port);
		memcpy(&(sin.sin6_addr),&(naddr.addr),sizeof(sin.sin6_addr));

		if (*addrlen > sizeof(sin))
			*addrlen = sizeof(sin);

		memcpy(addr, &sin, *addrlen);
	}

	newsock = alloc_socket(newconn,sock->family);
	if (newsock == -1) {
		netconn_delete(newconn);
		sock_set_errno(sock, ENOBUFS);
		return -1;
	}
	newconn->callback = event_callback;
	sock = get_socket(newsock);

	sys_sem_wait(socksem);
	/* old version (count of lost message in socket -- negative) */
	/*sock->rcvevent += -1 - newconn->socket;*/
	//printf("-----sock->rcvevent %d\n",sock->rcvevent);
	/* with async call it should not be needed */
	sock->rcvevent =0;
	newconn->socket = newsock;
	sys_sem_signal(socksem);

	LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_accept(%d) returning new sock=%d addr=", s, newsock));
	ip_addr_debug_print(SOCKETS_DEBUG, &naddr);
	LWIP_DEBUGF(SOCKETS_DEBUG, (" port=%u\n", port));

	sock_set_errno(sock, 0);
	return newsock;
}

	int
lwip_bind(int s, struct sockaddr *name, socklen_t namelen)
{
	struct lwip_socket *sock;
	struct ip_addr local_addr;
	u16_t local_port;
	err_t err;

	sock = get_socket(s);
	if (!sock) {
		set_errno(EBADF);
		return -1;
	}
#ifdef LWIP_NL
	if (sock->family == PF_NETLINK) {
		return netlink_bind(sock->conn,name,namelen);
	} 
	else 
#endif
	{
#ifdef LWIP_PACKET
		if (sock->family == PF_PACKET) {
			struct sockaddr_ll *packname=(struct sockaddr_ll *)name;
			SALL2IPADDR(*packname,local_addr);
			local_port=packname->sll_protocol;
		} else
#endif
			if (sock->family == PF_INET) {
				SOCK_IP64_CONV(&(local_addr),&(((struct sockaddr_in *)name)->sin_addr.s_addr));
				local_port = ((struct sockaddr_in *)name)->sin_port;
			}
			else {
				memcpy(&(local_addr.addr),&(((struct sockaddr_in6 *)name)->sin6_addr),sizeof(local_addr.addr));
				local_port = ((struct sockaddr_in6 *)name)->sin6_port;
			}

		LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_bind(%d, addr=", s));
		ip_addr_debug_print(SOCKETS_DEBUG, &local_addr);
		LWIP_DEBUGF(SOCKETS_DEBUG, (" port=%u)\n", ntohs(local_port)));

		err = netconn_bind(sock->conn, &local_addr, ntohs(local_port));

		if (err != ERR_OK) {
			LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_bind(%d) failed, err=%d\n", s, err));
			sock_set_errno(sock, err_to_errno(err));
			return -1;
		}

		LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_bind(%d) succeeded\n", s));
		sock_set_errno(sock, 0);
		return 0;
	}
}

	int
lwip_close(int s)
{
	struct lwip_socket *sock;
	int err=0;

	LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_close(%d)\n", s));
	if (!socksem)
		socksem = sys_sem_new(1);

	/* We cannot allow multiple closes of the same socket. */
	sys_sem_wait(socksem);

	sock = get_socket(s);
	if (!sock) {
		sys_sem_signal(socksem);
		set_errno(EBADF);
		return -1;
	}

#ifdef LWIP_NL
	if (sock->family == PF_NETLINK) {
		err=netlink_close(sock->conn);
		sock->conn = NULL;
	}
	else 
#endif
	{
		netconn_delete(sock->conn);
		if (sock->lastdata) {
			netbuf_delete(sock->lastdata);
		}
		sock->lastdata = NULL;
		sock->lastoffset = 0;
		sock->conn = NULL;
	}
	lwip_sockmap[sock->fdfake]=-1;
	sys_sem_signal(socksem);
	if (! _nofdfake)
		close(sock->fdfake);
	sock_set_errno(sock, err);
	return err;
}

	int
lwip_connect(int s, struct sockaddr *name, socklen_t namelen)
{
	struct lwip_socket *sock;
	err_t err;

	sock = get_socket(s);
	if (!sock) {
		set_errno(EBADF);
		return -1;
	}

	if (((struct sockaddr_in *)name)->sin_family == PF_UNSPEC) {
		LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_connect(%d, PF_UNSPEC)\n", s));
		err = netconn_disconnect(sock->conn);
	}  
#ifdef LWIP_NL
	else if (sock->family == PF_NETLINK)
		err=netlink_connect(sock->conn,name,namelen);
#endif
#ifdef LWIP_PACKET
	//
#endif
	else 
	{
		struct ip_addr remote_addr;
		u16_t remote_port;

		if(sock->family == PF_INET) {
			SOCK_IP64_CONV(&(remote_addr),&(((struct sockaddr_in *)name)->sin_addr.s_addr));
			remote_port = ((struct sockaddr_in *)name)->sin_port;
		}
		else {
			memcpy(&(remote_addr.addr),&(((struct sockaddr_in6 *)name)->sin6_addr),sizeof(remote_addr.addr));
			remote_port = ((struct sockaddr_in6 *)name)->sin6_port;
		}

		LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_connect(%d, addr=", s));
		ip_addr_debug_print(SOCKETS_DEBUG, &remote_addr);
		LWIP_DEBUGF(SOCKETS_DEBUG, (" port=%u)\n", ntohs(remote_port)));

		err = netconn_connect(sock->conn, &remote_addr, ntohs(remote_port));
	}

	if (err != ERR_OK) {
		LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_connect(%d) failed, err=%d\n", s, err));
		sock_set_errno(sock, err_to_errno(err));
		return -1;
	}

	LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_connect(%d) succeeded\n", s));
	sock_set_errno(sock, 0);
	return 0;
}

	int
lwip_listen(int s, int backlog)
{
	struct lwip_socket *sock;
	err_t err;

	LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_listen(%d, backlog=%d)\n", s, backlog));
	sock = get_socket(s);
	if (!sock
#ifdef LWIP_NL
			|| sock->family == PF_NETLINK
#endif
#ifdef LWIP_PACKET
			|| sock->family == PF_PACKET
#endif
		 ) {
		set_errno(EBADF);
		return -1;
	}

	err = netconn_listen(sock->conn);

	if (err != ERR_OK) {
		LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_listen(%d) failed, err=%d\n", s, err));
		sock_set_errno(sock, err_to_errno(err));
		return -1;
	}

	sock_set_errno(sock, 0);
	return 0;
}

	int
lwip_recvfrom(int s, void *mem, int len, unsigned int flags,
		struct sockaddr *from, socklen_t *fromlen)
{
	struct lwip_socket *sock;
	struct netbuf *buf;
	u16_t buflen, copylen;
	struct ip_addr *addr;
	u16_t port;


	LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_recvfrom(%d, %p, %d, 0x%x, ..)\n", s, mem, len, flags));
	sock = get_socket(s);
	if (!sock) {
		set_errno(EBADF);
		return -1;
	}

#ifdef LWIP_NL
	if (sock->family == PF_NETLINK) {
		return netlink_recvfrom(sock->conn,mem,len,flags,from,fromlen);
	} else
#endif
	{
		/* Check if there is data left from the last recv operation. */
		if (sock->lastdata) {
			buf = sock->lastdata;
		} else {
			/* If this is non-blocking call, then check first */
			if (((flags & MSG_DONTWAIT) || (sock->flags & O_NONBLOCK))
					&& !sock->rcvevent)
			{
				LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_recvfrom(%d): returning EWOULDBLOCK\n", s));
				sock_set_errno(sock, EWOULDBLOCK);
				return -1;
			}

			//printf("netconn_recv\n");
			/* No data was left from the previous operation, so we try to get
				 some from the network. */
			buf = netconn_recv(sock->conn);

			if (!buf) {
				char *p=mem;
				/* We should really do some error checking here. */
				LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_recvfrom(%d): buf == NULL!\n", s));
				*p=0;
				sock_set_errno(sock, 0);
				return 0;
			}
		}

		buflen = netbuf_len(buf);

		buflen -= sock->lastoffset;

		if (len > buflen) {
			copylen = buflen;
		} else {
			copylen = len;
		}

		/* copy the contents of the received buffer into
			 the supplied memory pointer mem */
		netbuf_copy_partial(buf, mem, copylen, sock->lastoffset);

		/* Check to see from where the data was. */
		if (from && fromlen) {
			if (sock->family == PF_INET) {
				struct sockaddr_in sin;

				addr = netbuf_fromaddr(buf);
				port = netbuf_fromport(buf);

				memset(&sin, 0, sizeof(sin));
				/*sin.sin_len = sizeof(sin);*/
				sin.sin_family = PF_INET;
				sin.sin_port = htons(port);
				SOCK_IP46_CONV(&(sin.sin_addr.s_addr),addr);

				if (*fromlen > sizeof(sin))
					*fromlen = sizeof(sin);

				memcpy(from, &sin, *fromlen);
			}
			else if (sock->family == PF_INET6) {
				struct sockaddr_in6 sin;

				addr = netbuf_fromaddr(buf);
				port = netbuf_fromport(buf);

				memset(&sin, 0, sizeof(sin));
				sin.sin6_family = PF_INET6;
				sin.sin6_port = htons(port);
				memcpy(&(sin.sin6_addr),&(addr->addr),sizeof(sin.sin6_addr));

				if (*fromlen > sizeof(sin))
					*fromlen = sizeof(sin);

				memcpy(from, &sin, *fromlen);
			}
#ifdef LWIP_PACKET
			else if (sock->family == PF_PACKET) {
				struct sockaddr_ll sll;

				addr = netbuf_fromaddr(buf);
				port = netbuf_fromport(buf);

				memset(&sll, 0, sizeof(sll));
				IPADDR2SALL(*addr,sll);
				sll.sll_protocol = htons(port);

				if (*fromlen > sizeof(sll))
					*fromlen = sizeof(sll);

				memcpy(from, &sll, *fromlen);
			}
#endif

			LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_recvfrom(%d): addr=", s));
			ip_addr_debug_print(SOCKETS_DEBUG, addr);
			LWIP_DEBUGF(SOCKETS_DEBUG, (" port=%u len=%u\n", port, copylen));
		} else {
#if SOCKETS_DEBUG > 0
			addr = netbuf_fromaddr(buf);
			port = netbuf_fromport(buf);

			LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_recvfrom(%d): addr=", s));
			ip_addr_debug_print(SOCKETS_DEBUG, addr);
			LWIP_DEBUGF(SOCKETS_DEBUG, (" port=%u len=%u\n", port, copylen));
#endif
		}

		/* If this is a TCP socket, check if there is data left in the
			 buffer. If so, it should be saved in the sock structure for next
			 time around. */
		if (netconn_type(sock->conn) == NETCONN_TCP && buflen - copylen > 0) {
			sock->lastdata = buf;
			sock->lastoffset += copylen;
		} else {
			sock->lastdata = NULL;
			sock->lastoffset = 0;
			netbuf_delete(buf);
		}

		sock_set_errno(sock, 0);
		return copylen;
	}
}

	int
lwip_read(int s, void *mem, int len)
{
	return lwip_recvfrom(s, mem, len, 0, NULL, NULL);
}

	int
lwip_recv(int s, void *mem, int len, unsigned int flags)
{
	return lwip_recvfrom(s, mem, len, flags, NULL, NULL);
}

	int
lwip_send(int s, void *data, int size, unsigned int flags)
{
	struct lwip_socket *sock;
	struct netbuf *buf;
	err_t err;

	LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_send(%d, data=%p, size=%d, flags=0x%x)\n", s, data, size, flags));

	sock = get_socket(s);
	if (!sock) {
		set_errno(EBADF);
		return -1;
	}

#ifdef LWIP_NL
	if (sock->family == PF_NETLINK)  {
		return netlink_send(sock->conn,data,size,flags);
	}
	else 
#endif
	{
		/*netconn parms are u16*/
		if (size > USHRT_MAX) size=USHRT_MAX;
		switch (netconn_type(sock->conn)) {
			case NETCONN_RAW:
			case NETCONN_UDP:
			case NETCONN_UDPLITE:
#ifdef LWIP_PACKET
			case NETCONN_PACKET_RAW:
			case NETCONN_PACKET_DGRAM:
#endif
				/* create a buffer */
				buf = netbuf_new();

				if (!buf) {
					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_send(%d) ENOBUFS\n", s));
					sock_set_errno(sock, ENOBUFS);
					return -1;
				}

				/* make the buffer point to the data that should
					 be sent */
				netbuf_ref(buf, data, size);

				/* send the data */
				err = netconn_send(sock->conn, buf);

				/* deallocated the buffer */
				netbuf_delete(buf);
				break;
			case NETCONN_TCP:
				err = netconn_write(sock->conn, data, size, NETCONN_COPY);
				break;
			default:
				err = ERR_ARG;
				break;
		}
		if (err != ERR_OK) {
			LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_send(%d) err=%d\n", s, err));
			sock_set_errno(sock, err_to_errno(err));
			return -1;
		}

		LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_send(%d) ok size=%d\n", s, size));
		sock_set_errno(sock, 0);
		return size;
	}
}

	int
lwip_sendto(int s, void *data, int size, unsigned int flags,
		struct sockaddr *to, socklen_t tolen)
{
	struct lwip_socket *sock;
	struct ip_addr remote_addr, addr;
	u16_t remote_port, port;
	int ret,connected;

	sock = get_socket(s);
	if (!sock) {
		set_errno(EBADF);
		return -1;
	}

#ifdef LWIP_NL
	if (sock->family == PF_NETLINK)  {
		return netlink_sendto(sock->conn,data,size,flags,to,tolen);
	}
	else 
#endif
	{
		/* get the peer if currently connected */
		connected = (netconn_peer(sock->conn, &addr, &port) == ERR_OK);

		if (tolen>0) {
			if (sock->family == PF_INET) {
				SOCK_IP64_CONV(&(remote_addr),&(((struct sockaddr_in *)to)->sin_addr.s_addr));
				remote_port = ((struct sockaddr_in *)to)->sin_port;
			}
			else if (sock->family == PF_INET6) {
				memcpy(&(remote_addr.addr),&(((struct sockaddr_in6 *)to)->sin6_addr),sizeof(remote_addr.addr));
				remote_port = ((struct sockaddr_in *)to)->sin_port;
			}
#ifdef LWIP_PACKET
			else if (sock->family == PF_PACKET) {
				SALL2IPADDR(*(struct sockaddr_ll *)to,remote_addr);
				remote_port=(((struct sockaddr_ll *)to)->sll_protocol);
			}
#endif
			LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_sendto(%d, data=%p, size=%d, flags=0x%x to=", s, data, size, flags));
			ip_addr_debug_print(SOCKETS_DEBUG, &remote_addr);
			LWIP_DEBUGF(SOCKETS_DEBUG, (" port=%u\n", ntohs(remote_port)));

			netconn_connect(sock->conn, &remote_addr, ntohs(remote_port));
		}

		ret = lwip_send(s, data, size, flags);

		/* reset the remote address and port number
			 of the connection */
		if (connected) {
			if (tolen>0) netconn_connect(sock->conn, &addr, port);
		} else
			netconn_disconnect(sock->conn);
		return ret;
	}
}

	int
lwip_socket(int domain, int type, int protocol)
{
	struct netconn *conn;
	int i;

	if (domain != PF_INET && domain != PF_INET6
#ifdef LWIP_NL
			&& domain != PF_NETLINK
#endif
#ifdef LWIP_PACKET
			&& domain != PF_PACKET
#endif
		 ) {
		set_errno(EAFNOSUPPORT);
		return -1;
	}

#if defined(LWIP_NL) || defined(LWIP_PACKET)
	switch(domain) {
#ifdef LWIP_NL
		case PF_NETLINK:
			switch (type) {
				case SOCK_RAW:
				case SOCK_DGRAM:
					if (protocol != 0) {
						set_errno(EINVAL);
						return -1;
					} else {
						LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_socket(%s,XXX, %d) = ", domain_name(domain), protocol));
						conn = netlink_open(type,protocol);
					}
					break;
				default:
					set_errno(EINVAL);
					return -1;
			}
			break;
#endif
#ifdef LWIP_PACKET
		case PF_PACKET:
			switch (type) {
				case SOCK_RAW:
					conn = netconn_new_with_proto_and_callback(NETCONN_PACKET_RAW, protocol, event_callback);
					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_socket(%s, SOCK_RAW, %d) = ", domain_name(domain), protocol));
					break;
				case SOCK_DGRAM:
					conn = netconn_new_with_proto_and_callback(NETCONN_PACKET_DGRAM, protocol, event_callback);
					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_socket(%s, SOCK_DGRAM, %d) = ", domain_name(domain), protocol));
					break;
				default:
					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_socket(%d, %d/UNKNOWN, %d) = -1\n", domain, type, protocol));
					set_errno(EINVAL);
					return -1;
			}
			break;
#endif
		case PF_INET:
		case PF_INET6:
#endif
			/* create a netconn */
			switch (type) {
				case SOCK_RAW:
					conn = netconn_new_with_proto_and_callback(NETCONN_RAW, protocol, event_callback);
					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_socket(%s, SOCK_RAW, %d) = ", domain_name(domain), protocol));
					break;
				case SOCK_DGRAM:
					conn = netconn_new_with_callback(NETCONN_UDP, event_callback);
					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_socket(%s, SOCK_DGRAM, %d) = ", domain_name(domain), protocol));
					break;
				case SOCK_STREAM:
					conn = netconn_new_with_callback(NETCONN_TCP, event_callback);
					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_socket(%s, SOCK_STREAM, %d) = ", domain_name(domain), protocol));
					break;
				default:
					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_socket(%d, %d/UNKNOWN, %d) = -1\n", domain, type, protocol));
					set_errno(EINVAL);
					return -1;
			}
#ifdef LWIP_NL
	}
#endif

	if (!conn) {
		LWIP_DEBUGF(SOCKETS_DEBUG, ("-1 / ENOBUFS (could not create netconn)\n"));
		set_errno(ENOBUFS);
		return -1;
	}

	i = alloc_socket(conn,domain);

	if (i == -1
#ifdef LWIP_NL
			&& domain != PF_NETLINK
#endif
		 ) {
		netconn_delete(conn);
		set_errno(ENOBUFS);
		return -1;
	}
#ifdef LWIP_NL
	if (domain != PF_NETLINK)
#endif
		conn->socket = i;
	LWIP_DEBUGF(SOCKETS_DEBUG, ("%d\n", i));
	set_errno(0);
	return i;
}

	int
lwip_write(int s, void *data, int size)
{
	return lwip_send(s, data, size, 0);
}

	static int
lwip_selscan(int maxfdp1, fd_set *readset, fd_set *writeset, fd_set *exceptset)
{
	int i, nready = 0;
	fd_set lreadset, lwriteset, lexceptset;
	struct lwip_socket *p_sock;

	FD_ZERO(&lreadset);
	FD_ZERO(&lwriteset);
	FD_ZERO(&lexceptset);

	/* Go through each socket in each list to count number of sockets which
		 currently match */
	for(i = 0; i < maxfdp1; i++)
	{
		if (FD_ISSET(i, readset))
		{
			/* See if netconn of this socket is ready for read */
			p_sock = get_socket(i);
			if (p_sock && (p_sock->lastdata || p_sock->rcvevent || p_sock->conn->recv_avail))
			{
				FD_SET(i, &lreadset);
				LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_selscan: fd=%d ready for reading\n", i));
				nready++;
			}
		}
		if (FD_ISSET(i, writeset))
		{
			/* See if netconn of this socket is ready for write */
			p_sock = get_socket(i);
			if (p_sock && p_sock->sendevent)
			{
				FD_SET(i, &lwriteset);
				LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_selscan: fd=%d ready for writing\n", i));
				nready++;
			}
		}
	}
	*readset = lreadset;
	*writeset = lwriteset;
	FD_ZERO(exceptset);

	return nready;
}

#if 0
pfdset(int max, fd_set *fds)
{
	register int i;
	if (fds == NULL)
		printf("NULL");
	else
		for (i=0;i<max;i++)
			printf("%d|",FD_ISSET(i,fds));
	printf("\n");
}
#endif


struct um_sel_wait {
	void (* cb)(); 
	void *arg; 
	int fd; 
	int how;
	struct um_sel_wait *next;
};
static struct um_sel_wait *um_sel_head=NULL;

static void um_sel_add(void (* cb)(), void *arg, int fd, int how)
{
	struct um_sel_wait *new=(struct um_sel_wait *)mem_malloc(sizeof(struct um_sel_wait));
	//printf("UMSELECT ADD %d how %x arg %x\n",fd,how,arg);
	new->cb=cb;
	new->arg=arg;
	new->fd=fd;
	new->how=how;
	new->next=um_sel_head;
	um_sel_head=new;
}

/* recursive is simpler but maybe not optimized */
static struct um_sel_wait *um_sel_rec_del(struct um_sel_wait *p,void *arg)
{
	if (p==NULL) 
		return NULL;
	else {
		struct um_sel_wait *next=um_sel_rec_del(p->next,arg);
		if (p->arg == arg) {
			free(p);
			return(next);
		} else {
			p->next=next;
			return(p);
		}
	}
}

static void um_sel_del(void *arg)
{
	//printf("UMSELECT DEL arg %x\n",arg);
	um_sel_head=um_sel_rec_del(um_sel_head,arg);
}

static struct um_sel_wait *um_sel_rec_signal(struct um_sel_wait *p,int fd, int how)
{
	if (p==NULL) 
		return NULL;
	else {
		if (fd == p->fd && (how & p->how) != 0) {
			/* found */
			struct um_sel_wait *next=um_sel_rec_del(p->next,p->arg);
			//printf("UMSELECT SIGNALED %d\n",fd);
			p->cb(p->arg);
			free(p);
			return um_sel_rec_signal(next,fd,how);
		} else {
			p->next=um_sel_rec_signal(p->next,fd,how);
			return p;
		}
	}
}

static void um_sel_signal(int fd, int how)
{
	//printf("UMSELECT SIGNAL fd %d how %x\n",fd,how);
	um_sel_head=um_sel_rec_signal(um_sel_head,fd,how);
}

int lwip_select_register(void (* cb)(), void *arg, int fd, int how)
{
	struct lwip_socket *psock=get_socket(fd);
	int rv=0;
	/*printf("UMSELECT REGISTER %s %d how %x arg %x psock %x\n",
	(cb != NULL)?"REG" : "DEL" ,
	fd,how,arg,psock);*/
	if (!selectsem)
		selectsem = sys_sem_new(1);
	sys_sem_wait(selectsem);
	if (psock) {
		//printf("R %d L %d S %d\n", psock->rcvevent, psock->lastdata, psock->sendevent);
#ifdef LWIP_NL
		if (psock->family == PF_NETLINK)
			rv=how;
		else
#endif
		if ((rv= (how & 0x1) * (psock->lastdata || psock->rcvevent || psock->conn->recv_avail) +
					(how & 0x2) * psock->sendevent +
					(how & 0x4) * 0) == 0 && cb != NULL)
			um_sel_add(cb,arg,fd,how);
	} 
	if (cb == NULL || rv>0)
		um_sel_del(arg);
	sys_sem_signal(selectsem);
	/*printf("UMSELECT REGISTER returns %x\n",rv);*/
	return rv;
}


	static void
event_callback(struct netconn *conn, enum netconn_evt evt, u16_t len)
{
	int s;
	struct lwip_socket *sock;
	struct lwip_select_cb *scb;

	/*printf("event_callback %p ",conn);*/
	/* Get socket */
	if (conn)
	{
		s = conn->socket;
		if (s < 0)
		{
			/* Data comes in right away after an accept, even though
			 * the server task might not have created a new socket yet.
			 * Just count down (or up) if that's the case and we
			 * will use the data later. Note that only receive events
			 * can happen before the new socket is set up. */
			/* if should not be needed with async accept 
			 * I have left a message to see if this event may happen */
			
			if (evt == NETCONN_EVT_RCVPLUS)
				/* conn->socket--;*/
				/*printf("----socket hack needed %d\n",conn->socket)*/;
			return;
		}

		sock = get_socket(s);
		if (!sock)
			return;
	}
	else
		return;

	if (!selectsem)
		selectsem = sys_sem_new(1);

	sys_sem_wait(selectsem);
	/* Set event as required */
	switch (evt)
	{
		case NETCONN_EVT_RCVPLUS:
			sock->rcvevent++;
			break;
		case NETCONN_EVT_RCVMINUS:
			sock->rcvevent--;
			break;
		case NETCONN_EVT_SENDPLUS:
			sock->sendevent = 1;
			break;
		case NETCONN_EVT_SENDMINUS:
			sock->sendevent = 0;
			break;
	}
	um_sel_signal(sock->fdfake, 
			0x1 * (sock->rcvevent || sock->lastdata || sock->conn->recv_avail) +
			0x2 * sock->sendevent +
			0x4 * 0 );
	/*printf("EVENT fd %d R%d S%d\n",s,sock->rcvevent,sock->sendevent);*/
	sys_sem_signal(selectsem);

	/* Now decide if anyone is waiting for this socket */
	/* NOTE: This code is written this way to protect the select link list
		 but to avoid a deadlock situation by releasing socksem before
		 signalling for the select. This means we need to go through the list
		 multiple times ONLY IF a select was actually waiting. We go through
		 the list the number of waiting select calls + 1. This list is
		 expected to be small. */
	while (1)
	{
		sys_sem_wait(selectsem);
		for (scb = select_cb_list; scb; scb = scb->next)
		{
			if (scb->sem_signalled == 0)
			{
				/* Test this select call for our socket */
				if (scb->readset && FD_ISSET(s, scb->readset))
					if (sock->rcvevent)
						break;
				if (scb->writeset && FD_ISSET(s, scb->writeset))
					if (sock->sendevent)
						break;
			}
		}
		if (scb)
		{
			scb->sem_signalled = 1;
			write(scb->pipe[1],"\0",1);
			sys_sem_signal(selectsem);
		} else {
			sys_sem_signal(selectsem);
			break;
		}
	}

}




	int
lwip_shutdown(int s, int how)
{
	LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_shutdown(%d, how=%d)\n", s, how));
	return lwip_close(s); /* XXX temporary hack until proper implementation */
}

	int
lwip_getpeername (int s, struct sockaddr *name, socklen_t *namelen)
{
	struct lwip_socket *sock;
	struct ip_addr naddr;
	u16_t port;

	sock = get_socket(s);
	if (!sock
#ifdef LWIP_NL
			|| sock->family == PF_NETLINK
#endif
#ifdef LWIP_PACKET
			|| sock->family == PF_PACKET
#endif
		 ) {
		set_errno(EBADF);
		return -1;
	}

	/* get the IP address and port of the remote host */
	netconn_peer(sock->conn, &naddr, &port);

	LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_getpeername(%d, addr=", s));
	ip_addr_debug_print(SOCKETS_DEBUG, &naddr);
	LWIP_DEBUGF(SOCKETS_DEBUG, (" port=%d)\n", port));

	if (sock->family == PF_INET) {
		struct sockaddr_in sin;
		memset(&sin, 0, sizeof(sin));
		sin.sin_family = PF_INET;
		sin.sin_port = htons(port);
		/*memcpy(&(sin.sin_addr.s_addr),&(naddr.addr),sizeof(sin.sin_addr.s_addr));*/
		SOCK_IP46_CONV(&(sin.sin_addr.s_addr),&(naddr));

		if (*namelen > sizeof(sin))
			*namelen = sizeof(sin);

		memcpy(name, &sin, *namelen);
	}
	else {
		struct sockaddr_in6 sin;
		memset(&sin, 0, sizeof(sin));
		sin.sin6_family = PF_INET6;
		sin.sin6_port = htons(port);
		memcpy(&(sin.sin6_addr),&(naddr.addr),sizeof(sin.sin6_addr));

		if (*namelen > sizeof(sin))
			*namelen = sizeof(sin);

		memcpy(name, &sin, *namelen);
	}

	sock_set_errno(sock, 0);

	return 0;
}

	int
lwip_getsockname (int s, struct sockaddr *name, socklen_t *namelen)
{
	struct lwip_socket *sock;
	struct ip_addr *naddr;
	u16_t port;

	sock = get_socket(s);
	if (!sock) {
		set_errno(EBADF);
		return -1;
	}

#ifdef LWIP_NL
	if (sock->family == PF_NETLINK) {
		return netlink_getsockname (sock->conn,name,namelen);
	}
	else 
#endif
	{
		/* get the IP address and port of the remote host */
		netconn_addr(sock->conn, &naddr, &port);

		LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_getsockname(%d, addr=", s));
		ip_addr_debug_print(SOCKETS_DEBUG, naddr);
		LWIP_DEBUGF(SOCKETS_DEBUG, (" port=%d)\n", port));

		if (sock->family == PF_INET) {
			struct sockaddr_in sin;
			memset(&sin, 0, sizeof(sin));
			sin.sin_family = PF_INET;
			sin.sin_port = htons(port);
			/*memcpy(&(sin.sin_addr.s_addr),&(naddr.addr),sizeof(sin.sin_addr.s_addr));*/
			SOCK_IP46_CONV(&(sin.sin_addr.s_addr),naddr);

			if (*namelen > sizeof(sin))
				*namelen = sizeof(sin);

			memcpy(name, &sin, *namelen);
			/*printf("%x %d\n",sin.sin_addr.s_addr,*namelen);*/
		}
		else {
			struct sockaddr_in6 sin;
			memset(&sin, 0, sizeof(sin));
			sin.sin6_family = PF_INET6;
			sin.sin6_port = htons(port);
			memcpy(&(sin.sin6_addr),naddr,sizeof(sin.sin6_addr));

			if (*namelen > sizeof(sin))
				*namelen = sizeof(sin);

			memcpy(name, &sin, *namelen);
		}

		sock_set_errno(sock, 0);
		return 0;
	}
}

	int
lwip_getsockopt (int s, int level, int optname, void *optval, socklen_t *optlen)
{
	int err = 0;
	struct lwip_socket *sock = get_socket(s);

	if (!sock) {
		set_errno(EBADF);
		return -1;
	}
#ifdef LWIP_NL
	if(sock->family == PF_NETLINK) {
		int err=netlink_getsockopt(sock, level, optname, optval, optlen); 
		if (err != 0) {
			sock_set_errno(sock, err);
			return -1;
		} else
			return 0;
	}
#endif

	if( NULL == optval || NULL == optlen ) {
		sock_set_errno( sock, EFAULT );
		return -1;
	}

	/* Do length and type checks for the various options first, to keep it readable. */
	switch( level ) {

		/* Level: SOL_SOCKET */
		case SOL_SOCKET:
			switch(optname) {

				case SO_ACCEPTCONN:
				case SO_BROADCAST:
					/* UNIMPL case SO_DEBUG: */
					/* UNIMPL case SO_DONTROUTE: */
				case SO_ERROR:
				case SO_KEEPALIVE:
					/* UNIMPL case SO_OOBINLINE: */
					/* UNINPL case SO_RCVBUF: */
					/* UNINPL case SO_SNDBUF: */
					/* UNIMPL case SO_RCVLOWAT: */
					/* UNIMPL case SO_SNDLOWAT: */
#if SO_REUSE
				case SO_REUSEADDR:
				case SO_REUSEPORT:
#endif /* SO_REUSE */
				case SO_TYPE:
					/* UNIMPL case SO_USELOOPBACK: */
					if( *optlen < sizeof(int) ) {
						err = EINVAL;
					}
					break;

				default:
					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_getsockopt(%d, SOL_SOCKET, UNIMPL: optname=0x%x, ..)\n", s, optname));
					err = ENOPROTOOPT;
			}  /* switch */
			break;

			/* Level: IPPROTO_IP */
		case IPPROTO_IP:
			switch(optname) {
				/* UNIMPL case IP_HDRINCL: */
				/* UNIMPL case IP_RCVDSTADDR: */
				/* UNIMPL case IP_RCVIF: */
				case IP_TTL:
				case IP_TOS:
					if( *optlen < sizeof(int) ) {
						err = EINVAL;
					}
					break;

				default:
					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_getsockopt(%d, IPPROTO_IP, UNIMPL: optname=0x%x, ..)\n", s, optname));
					err = ENOPROTOOPT;
			}  /* switch */
			break;

			/* Level: IPPROTO_TCP */
		case IPPROTO_TCP:
			if( *optlen < sizeof(int) ) {
				err = EINVAL;
				break;
			}

			/* If this is no TCP socket, ignore any options. */
			if ( sock->conn->type != NETCONN_TCP ) return 0;

			switch( optname ) {
				case TCP_NODELAY:
				case TCP_KEEPALIVE:
					break;

				default:
					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_getsockopt(%d, IPPROTO_TCP, UNIMPL: optname=0x%x, ..)\n", s, optname));
					err = ENOPROTOOPT;
			}  /* switch */
			break;

			/* UNDEFINED LEVEL */
		default:
			LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_getsockopt(%d, level=0x%x, UNIMPL: optname=0x%x, ..)\n", s, level, optname));
			err = ENOPROTOOPT;
	}  /* switch */


	if( 0 != err ) {
		sock_set_errno(sock, err);
		return -1;
	}



	/* Now do the actual option processing */

	switch(level) {

		/* Level: SOL_SOCKET */
		case SOL_SOCKET:
			switch( optname ) {

				/* The option flags */
				case SO_ACCEPTCONN:
				case SO_BROADCAST:
					/* UNIMPL case SO_DEBUG: */
					/* UNIMPL case SO_DONTROUTE: */
				case SO_KEEPALIVE:
					/* UNIMPL case SO_OOBINCLUDE: */
#if SO_REUSE
				case SO_REUSEADDR:
				case SO_REUSEPORT:
#endif /* SO_REUSE */
					/*case SO_USELOOPBACK: UNIMPL */
					*(int*)optval = sock->conn->pcb.tcp->so_options & so_map[optname];
					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_getsockopt(%d, SOL_SOCKET, optname=0x%x, ..) = %s\n", s, optname, (*(int*)optval?"on":"off")));
					break;

				case SO_TYPE:
					switch (sock->conn->type) {
						case NETCONN_RAW:
							*(int*)optval = SOCK_RAW;
							break;
						case NETCONN_TCP:
							*(int*)optval = SOCK_STREAM;
							break;
						case NETCONN_UDP:
						case NETCONN_UDPLITE:
						case NETCONN_UDPNOCHKSUM:
							*(int*)optval = SOCK_DGRAM;
							break;
						default: /* unrecognized socket type */
							*(int*)optval = sock->conn->type;
							LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_getsockopt(%d, SOL_SOCKET, SO_TYPE): unrecognized socket type %d\n", s, *(int *)optval));
					}  /* switch */
					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_getsockopt(%d, SOL_SOCKET, SO_TYPE) = %d\n", s, *(int *)optval));
					break;

				case SO_ERROR:
					*(int *)optval = sock->err;
					sock->err = 0;
					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_getsockopt(%d, SOL_SOCKET, SO_ERROR) = %d\n", s, *(int *)optval));
					break;
			}  /* switch */
			break;

			/* Level: IPPROTO_IP */
		case IPPROTO_IP:
			switch( optname ) {
				case IP_TTL:
					*(int*)optval = sock->conn->pcb.tcp->ttl;
					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_getsockopt(%d, IPPROTO_IP, IP_TTL) = %d\n", s, *(int *)optval));
					break;
				case IP_TOS:
					*(int*)optval = sock->conn->pcb.tcp->tos;
					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_getsockopt(%d, IPPROTO_IP, IP_TOS) = %d\n", s, *(int *)optval));
					break;
			}  /* switch */
			break;

			/* Level: IPPROTO_TCP */
		case IPPROTO_TCP:
			switch( optname ) {
				case TCP_NODELAY:
					*(int*)optval = (sock->conn->pcb.tcp->flags & TF_NODELAY);
					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_getsockopt(%d, IPPROTO_TCP, TCP_NODELAY) = %s\n", s, (*(int*)optval)?"on":"off") );
					break;
				case TCP_KEEPALIVE:
					*(int*)optval = sock->conn->pcb.tcp->keepalive;
					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_getsockopt(%d, IPPROTO_IP, TCP_KEEPALIVE) = %d\n", s, *(int *)optval));
					break;
			}  /* switch */
			break;
	}


	sock_set_errno(sock, err);
	return err ? -1 : 0;
}

	int
lwip_setsockopt (int s, int level, int optname, const void *optval, socklen_t optlen)
{
	struct lwip_socket *sock;
	int err = 0;

	//printf("lwip_setsockopt %d %d\n",level,optname);
	sock = get_socket(s);
	if (!sock) {
		set_errno(EBADF);
		return -1;
	}
	if( NULL == optval ) {
		sock_set_errno( sock, EFAULT );
		printf("fault\n");
		return -1;
	}

#ifdef LWIP_NL
	if(sock->family == PF_NETLINK) {
		int err=netlink_setsockopt(sock, level, optname, optval, optlen);
		if (err != 0) {
			sock_set_errno(sock, err);
			return -1;
		} else
			return 0;
	}
#endif


	/* Do length and type checks for the various options first, to keep it readable. */
	switch( level ) {

		/* Level: SOL_SOCKET */
		case SOL_SOCKET:
			switch(optname) {

				case SO_BROADCAST:
					/* UNIMPL case SO_DEBUG: */
					/* UNIMPL case SO_DONTROUTE: */
				case SO_KEEPALIVE:
					/* UNIMPL case SO_OOBINLINE: */
					/* UNIMPL case SO_RCVBUF: */
					/* UNIMPL case SO_SNDBUF: */
					/* UNIMPL case SO_RCVLOWAT: */
					/* UNIMPL case SO_SNDLOWAT: */
#if SO_REUSE
				case SO_REUSEADDR:
				case SO_REUSEPORT:
#endif /* SO_REUSE */
					/* UNIMPL case SO_USELOOPBACK: */
					if( optlen < sizeof(int) ) {
						err = EINVAL;
					}
					break;
				case SO_ATTACH_FILTER:
					break;
				default:
					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_setsockopt(%d, SOL_SOCKET, UNIMPL: optname=0x%x, ..)\n", s, optname));
					err = ENOPROTOOPT;
			}  /* switch */
			break;

			/* Level: IPPROTO_IP */
		case IPPROTO_IP:
			switch(optname) {
				/* UNIMPL case IP_HDRINCL: */
				/* UNIMPL case IP_RCVDSTADDR: */
				/* UNIMPL case IP_RCVIF: */
				case IP_TTL:
				case IP_TOS:
					if( optlen < sizeof(int) ) {
						err = EINVAL;
					}
					break;
				default:
					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_setsockopt(%d, IPPROTO_IP, UNIMPL: optname=0x%x, ..)\n", s, optname));
					err = ENOPROTOOPT;
			}  /* switch */
			break;

			/* Level: IPPROTO_TCP */
		case IPPROTO_TCP:
			if( optlen < sizeof(int) ) {
				err = EINVAL;
				break;
			}

			/* If this is no TCP socket, ignore any options. */
			if ( sock->conn->type != NETCONN_TCP ) return 0;

			switch( optname ) {
				case TCP_NODELAY:
				case TCP_KEEPALIVE:
					break;

				default:
					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_setsockopt(%d, IPPROTO_TCP, UNIMPL: optname=0x%x, ..)\n", s, optname));
					err = ENOPROTOOPT;
			}  /* switch */
			break;

			/* Level IPPROTO_IPV6 */      
		case IPPROTO_IPV6:
			switch( optname ) {
				case IPV6_HOPLIMIT:
					break;
				default:
					printf("IPPROTO_IPV6 %d\n",optname);
					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_setsockopt(%d, IPPROTO_IPV6, UNIMPL: optname=0x%x, ..)\n", s, optname));
					err = ENOPROTOOPT;
			}
			break;

			/* Level IPPROTO_ICMPV6 */      
		case IPPROTO_ICMPV6:
			switch( optname ) {
				case ICMPV6_FILTER:
					break;
				default:
					printf("IPPROTO_ICMPV6 %d\n",optname);
					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_setsockopt(%d, IPPROTO_ICMPV6, UNIMPL: optname=0x%x, ..)\n", s, optname));
					err = ENOPROTOOPT;
			}
			break;

			/* Level IPPROTO_RAW */      
		case IPPROTO_RAW:
			switch( optname ) {
				case IPV6_CHECKSUM:
					if( optlen < sizeof(int) ) {
						err = EINVAL;
					}
					break;
				default:
					//printf("IPPROTO_RAW %d\n",optname);
					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_setsockopt(%d, IPPROTO_RAW, UNIMPL: optname=0x%x, ..)\n", s, optname));
					err = ENOPROTOOPT;
			}
			break;

#ifdef LWIP_PACKET
		case SOL_PACKET: 
			switch( optname ) { 
				case PACKET_ADD_MEMBERSHIP:
				case PACKET_DROP_MEMBERSHIP: 
					{
						const struct packet_mreq *pm = optval;
						if (optlen < sizeof(struct packet_mreq)) {
							err = EINVAL;
						} else {
							printf("PACKET_MEMBERSHIP %d %d %d %d\n",
									optname,pm->mr_ifindex,pm->mr_type,pm->mr_alen);
						}
					}
					break;
					//case PACKET_RECV_OUTPUT:
					//case PACKET_RX_RING:
					//case PACKET_STATISTICS:
				default:
					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_setsockopt(%d, IPPROTO_RAW, UNIMPL: optname=0x%x, ..)\n", s, optname));
					err = ENOPROTOOPT;
					break;
			}
			break;
#endif

			/* UNDEFINED LEVEL */      
		default:
			LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_setsockopt(%d, level=0x%x, UNIMPL: optname=0x%x, ..)\n", s, level, optname));
			err = ENOPROTOOPT;
	}  /* switch */

	if( 0 != err ) {
		sock_set_errno(sock, err);
		return -1;
	}



	/* Now do the actual option processing */

	switch(level) {

		/* Level: SOL_SOCKET */
		case SOL_SOCKET:
			switch(optname) {

				/* The option flags */
				case SO_BROADCAST:
					/* UNIMPL case SO_DEBUG: */
					/* UNIMPL case SO_DONTROUTE: */
				case SO_KEEPALIVE:
					/* UNIMPL case SO_OOBINCLUDE: */
#if SO_REUSE
				case SO_REUSEADDR:
				case SO_REUSEPORT:
#endif /* SO_REUSE */
					/* UNIMPL case SO_USELOOPBACK: */
					if ( *(int*)optval ) {
						sock->conn->pcb.tcp->so_options |= so_map[optname];
					} else {
						sock->conn->pcb.tcp->so_options &= ~(so_map[optname]);
					}
					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_setsockopt(%d, SOL_SOCKET, optname=0x%x, ..) -> %s\n", s, optname, (*(int*)optval?"on":"off")));
					break;
			}  /* switch */
			break;

			/* Level: IPPROTO_IP */
		case IPPROTO_IP:
			switch( optname ) {
				case IP_TTL:
					sock->conn->pcb.tcp->ttl = (u8_t)(*(int*)optval);
					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_setsockopt(%d, IPPROTO_IP, IP_TTL, ..) -> %u\n", s, sock->conn->pcb.tcp->ttl));
					break;
				case IP_TOS:
					sock->conn->pcb.tcp->tos = (u8_t)(*(int*)optval);
					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_setsockopt(%d, IPPROTO_IP, IP_TOS, ..)-> %u\n", s, sock->conn->pcb.tcp->tos));
					break;
			}  /* switch */
			break;

			/* Level: IPPROTO_TCP */
		case IPPROTO_TCP:
			switch( optname ) {
				case TCP_NODELAY:
					if ( *(int*)optval ) {
						sock->conn->pcb.tcp->flags |= TF_NODELAY;
					} else {
						sock->conn->pcb.tcp->flags &= ~TF_NODELAY;
					}
					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_setsockopt(%d, IPPROTO_TCP, TCP_NODELAY) -> %s\n", s, (*(int *)optval)?"on":"off") );
					break;
				case TCP_KEEPALIVE:
					sock->conn->pcb.tcp->keepalive = (u32_t)(*(int*)optval);
					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_setsockopt(%d, IPPROTO_TCP, TCP_KEEPALIVE) -> %u\n", s, (int) sock->conn->pcb.tcp->keepalive));
					break;
			}  /* switch */

			/* Level IPPROTO_IPV6 */      
		case IPPROTO_IPV6:
			switch( optname ) {
				case IPV6_HOPLIMIT:
					/*sock->conn->pcb.tcp->ttl = (u8_t)(*(int*)optval);*/
					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_setsockopt(%d, IPPROTO_IPV6, IPV6_HOPLIMIT, ..) -> %u\n", s, sock->conn->pcb.tcp->ttl));
					break;
				default:
					break;
			}
			break;

			/* Level IPPROTO_ICMPV6 */      
		case IPPROTO_ICMPV6:
			switch( optname ) {
				default:
					break;
			}
			break;

			/* Level IPPROTO_RAW */      
		case IPPROTO_RAW:
			switch( optname ) {
				case IPV6_CHECKSUM:
					sock->conn->pcb.raw->so_options |= SOF_IPV6_CHECKSUM;
					sock->conn->pcb.raw->checksumoffset=*(int*)optval;
				default:
					break;
			}
			break;

	}  /* switch */

	sock_set_errno(sock, err);
	return err ? -1 : 0;
}

int lwip_ioctl(int s, long cmd, void *argp)
{
	struct lwip_socket *sock = get_socket(s);

	if (!sock
#ifdef LWIP_NL
			|| sock->family == PF_NETLINK
#endif
#ifdef LWIP_SOCKET
			|| sock->family == PF_SOCKET
#endif
		 ) {
		printf("lwip_ioctl %d %ld BADF\n",s,cmd);
		set_errno(EBADF);
		return -1;
	}

	switch (cmd) {
		case FIONREAD:
			if (!argp) {
				sock_set_errno(sock, EINVAL);
				return -1;
			}

			*((u32_t*)argp) = sock->conn->recv_avail;

			LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_ioctl(%d, FIONREAD, %p) = %lu\n", s, argp, *((u32_t*)argp)));
			sock_set_errno(sock, 0);
			return 0;

		case FIONBIO:
			if (argp && *(u32_t*)argp)
				sock->flags |= O_NONBLOCK;
			else
				sock->flags &= ~O_NONBLOCK;
			LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_ioctl(%d, FIONBIO, %d)\n", s, !!(sock->flags & O_NONBLOCK)));
			sock_set_errno(sock, 0);
			return 0;

		case SIOCGIFTXQLEN: /* XXX hack */
			if (!argp) {
				sock_set_errno(sock, EINVAL);
				return -1;
			}

			*((u16_t*)argp) = 0;

			LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_ioctl(%d, SIOCGIFTXQLEN, %p) = %u\n", s, argp, *((u16_t*)argp)));
			sock_set_errno(sock, 0);
			return 0;

		case SIOCGSTAMP:
			{
				struct timezone tz;
				struct timeval tv;
				gettimeofday(&tv,&tz);
				memcpy(argp,&tv,sizeof(struct timeval));  
			}
			return 0;
		default:

			if (cmd >= SIOCGIFNAME && cmd <= SIOCSIFTXQLEN) {
				int err;
				err=netif_ioctl(cmd, argp);
				sock_set_errno(sock, err);
				LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_ioctl(%d, SIO TO NETIF) ret=%d\n",s,err));
				if (err)
					return -1;
				else
					return 0;
			}
			else {

				LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_ioctl(%d, UNIMPL: 0x%lx, %p)\n", s, cmd, argp));
				sock_set_errno(sock, ENOSYS); /* not yet implemented */
				return -1;
			}
	}
}

int lwip_fcntl(int s, int cmd, int arg)
{
	struct lwip_socket *sock = get_socket(s);
	LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_fcntl(%d, %x)\n",s,cmd));

	if (!sock
#ifdef LWIP_NL
			|| sock->family == PF_NETLINK
#endif
#ifdef LWIP_SOCKET
			|| sock->family == PF_SOCKET
#endif
		 ) {
		set_errno(EBADF);
		return -1;
	}

	switch (cmd) {
		case F_GETFL:
			return sock->flags;
		case F_SETFL:
			sock->flags = arg;
			return 0;
		default:
			return -1;
	}
}

static int fdsplit(int max, 
		fd_set *rfd,
		fd_set *wfd,
		fd_set *efd,
		fd_set *rlfd,
		fd_set *wlfd,
		fd_set *elfd,
		fd_set *rnfd,
		fd_set *wnfd,
		fd_set *enfd)
{
	int lcount=0;
	register int i;
	if (rfd)
		*rlfd=*rnfd=*rfd;
	else {
		FD_ZERO(rlfd);
		FD_ZERO(rnfd);
	}
	if (wfd)
		*wlfd=*wnfd=*wfd;
	else {
		FD_ZERO(wlfd);
		FD_ZERO(wnfd);
	}
	if (efd)
		*elfd=*enfd=*efd;
	else {
		FD_ZERO(elfd);
		FD_ZERO(enfd);
	}
	for (i=0;i<max;i++) {
		if (lwip_sockmap[i] >= 0) {
			if(FD_ISSET(i,rlfd) || FD_ISSET(i,wlfd) || FD_ISSET(i,elfd))
				lcount++;
			FD_CLR(i,rnfd);
			FD_CLR(i,wnfd);
			FD_CLR(i,enfd);
		} else 
		{
			FD_CLR(i,rlfd);
			FD_CLR(i,wlfd);
			FD_CLR(i,elfd);
		}
	}
	return lcount;
}

int lwip_select(int maxfdp1, fd_set *readset, fd_set *writeset, fd_set *exceptset,
		struct timeval *timeout)
{
	int i;
	int nready,nready_native,nlwip;
	fd_set lreadset, lwriteset, lexceptset;
	fd_set lnreadset, lnwriteset, lnexceptset;
	int maxfdpipe=maxfdp1;
	u32_t msectimeout;
	struct lwip_select_cb select_cb;
	struct lwip_select_cb *p_selcb;
	struct timeval now;

	LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_select(%d, %p, %p, %p, tvsec=%ld tvusec=%ld)\n", maxfdp1, (void *)readset, (void *) writeset, (void *) exceptset, timeout ? timeout->tv_sec : -1L, timeout ? timeout->tv_usec : -1L));
	/*pfdset(maxfdp1,readset);
		pfdset(maxfdp1,writeset);
		pfdset(maxfdp1,exceptset);*/

	select_cb.next = 0;
	select_cb.readset = readset;
	select_cb.writeset = writeset;
	select_cb.exceptset = exceptset;
	select_cb.sem_signalled = 0;

	nlwip = fdsplit (maxfdp1, readset, writeset, exceptset,
			&lreadset, &lwriteset, &lexceptset,
			&lnreadset, &lnwriteset, &lnexceptset);

	if (nlwip == 0) {
#ifdef FAKE_SYSCALL
		nready_native=native_select(maxfdp1,readset,writeset,exceptset,timeout);
#else
		nready_native=select(maxfdp1,readset,writeset,exceptset,timeout);
#endif
		return nready_native;
	}

	now.tv_sec=now.tv_usec=0;
	/* Protect ourselves searching through the list */
	if (!selectsem)
		selectsem = sys_sem_new(1);
	sys_sem_wait(selectsem);

	/* Go through each socket in each list to count number of sockets which
		 currently match */
	nready = lwip_selscan(maxfdp1, &lreadset, &lwriteset, &lexceptset);
#ifdef FAKE_SYSCALL
	nready_native = native_select(maxfdp1,&lnreadset,&lnwriteset,&lnexceptset, &now);
#else
	nready_native = select(maxfdp1,&lnreadset,&lnwriteset,&lnexceptset, &now);
#endif

	/* If we don't have any current events, then suspend if we are supposed to */
	if (!(nready+nready_native))
	{
		if (timeout && timeout->tv_sec == 0 && timeout->tv_usec == 0)
		{
			sys_sem_signal(selectsem);
			if (readset)
				FD_ZERO(readset);
			if (writeset)
				FD_ZERO(writeset);
			if (exceptset)
				FD_ZERO(exceptset);

			LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_select: no timeout, returning 0\n"));
			set_errno(0);

			return 0;
		}

		nlwip = fdsplit (maxfdp1, readset, writeset, exceptset,
				&lreadset, &lwriteset, &lexceptset,
				&lnreadset, &lnwriteset, &lnexceptset);
		/* add our semaphore to list */
		/* We don't actually need any dynamic memory. Our entry on the
		 * list is only valid while we are in this function, so it's ok
		 * to use local variables */

		pipe(select_cb.pipe); 
		/* Note that we are still protected */
		/* Put this select_cb on top of list */
		select_cb.next = select_cb_list;
		select_cb_list = &select_cb;

		/* Now we can safely unprotect */
		sys_sem_signal(selectsem);

		/* Now just wait to be woken */
		if (timeout == 0)
			/* Wait forever */
			msectimeout = 0;
		else
			msectimeout =  ((timeout->tv_sec * 1000) + ((timeout->tv_usec + 500)/1000));

		FD_SET(select_cb.pipe[0], &lnreadset); 
		if (select_cb.pipe[0]+1 > maxfdpipe)
			maxfdpipe = select_cb.pipe[0]+1;
#ifdef FAKE_SYSCALL
		nready_native=native_select(maxfdpipe,&lnreadset,&lnwriteset,&lnexceptset,timeout); 
#else
		nready_native=select(maxfdpipe,&lnreadset,&lnwriteset,&lnexceptset,timeout); 
#endif

		/* Take us off the list */
		sys_sem_wait(selectsem);
		if (select_cb_list == &select_cb)
			select_cb_list = select_cb.next;
		else
			for (p_selcb = select_cb_list; p_selcb; p_selcb = p_selcb->next)
				if (p_selcb->next == &select_cb)
				{
					p_selcb->next = select_cb.next;
					break;
				}

		sys_sem_signal(selectsem);

#ifdef FAKE_SYSCALL
		native_close(select_cb.pipe[0]);
		native_close(select_cb.pipe[1]);
#else
		close(select_cb.pipe[0]);
		close(select_cb.pipe[1]);
#endif
		if (nready_native == 0)             /* Timeout */
		{
			if (readset)
				FD_ZERO(readset);
			if (writeset)
				FD_ZERO(writeset);
			if (exceptset)
				FD_ZERO(exceptset);

			LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_select: timeout expired\n"));
			set_errno(0);

			return 0;
		}

		if (FD_ISSET(select_cb.pipe[0], &lnreadset)) {
			nready_native--; 
			FD_CLR(select_cb.pipe[0], &lnreadset);
		}

		nready = lwip_selscan(maxfdp1, &lreadset, &lwriteset, &lexceptset);

	}
	else
		sys_sem_signal(selectsem);

	if (readset) 
		FD_ZERO(readset);
	if (writeset)
		FD_ZERO(writeset);
	if (exceptset)
		FD_ZERO(exceptset);
	for (i=0;i<maxfdp1;i++) {
		if (readset) {
			if (FD_ISSET(i,&lreadset)) FD_SET(i,readset);
			if (FD_ISSET(i,&lnreadset)) FD_SET(i,readset);
		}
		if (writeset) {
			if (FD_ISSET(i,&lwriteset)) FD_SET(i,writeset);
			if (FD_ISSET(i,&lnwriteset)) FD_SET(i,writeset);
		}
		if (exceptset) {
			if (FD_ISSET(i,&lexceptset)) FD_SET(i,exceptset);
			if (FD_ISSET(i,&lnexceptset)) FD_SET(i,exceptset);
		}
	}

	LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_select: nready = %d\n", nready+nready_native));
	if(writeset)
		set_errno(0);

	return nready+nready_native;
}

#ifdef FAKE_SYSCALL

int accept(int s, struct sockaddr *addr, socklen_t *addrlen)
{
	if (lwip_sockmap[s] < 0)
		return native_accept(s,addr,addrlen);
	else
		return lwip_accept(s,addr,addrlen);
}

int bind(int s, struct sockaddr *name, socklen_t namelen)
{
	if (lwip_sockmap[s] < 0)
		return native_bind(s,name, namelen) ;
	else
		return lwip_bind(s,name, namelen) ;
}

int connect(int s, struct sockaddr *name, socklen_t namelen)
{
	if (lwip_sockmap[s] < 0)
		return native_connect(s,name,namelen) ;
	else
		return lwip_connect(s,name,namelen) ;
}

int listen(int s, int backlog)
{
	if (lwip_sockmap[s] < 0)
		return native_listen(s,backlog) ;
	else
		return lwip_listen(s,backlog) ;
}

int recvfrom(int s, void *mem, int len, unsigned int flags,
		struct sockaddr *from, socklen_t *fromlen)
{
	if (lwip_sockmap[s] < 0)
		return native_recvfrom(s,mem,len,flags,from,fromlen) ;
	else
		return lwip_recvfrom(s,mem,len,flags,from,fromlen) ;
}

int read(int s, void *mem, size_t len)
{
	if (lwip_sockmap[s] < 0)
		return native_read(s,mem,len) ;
	else
		return lwip_read(s,mem,len) ;
}

int recv(int s, void *mem, int len, unsigned int flags)
{
	if (lwip_sockmap[s] < 0)
		return native_recv(s,mem,len,flags) ;
	else
		return lwip_recv(s,mem,len,flags) ;
}

int send(int s, void *data, ssize_t size, unsigned int flags)
{
	if (lwip_sockmap[s] < 0)
		return native_send(s,data,size,flags) ;
	else
		return lwip_send(s,data,size,flags) ;
}

int sendto(int s, void *data, int size, unsigned int flags,
		struct sockaddr *to, socklen_t tolen)
{
	if (lwip_sockmap[s] < 0)
		return native_sendto(s, data, size, flags, to, tolen) ;
	else
		return lwip_sendto(s, data, size, flags, to, tolen) ;
}

int socket(int domain, int type, int protocol)
{
	if (!initialized) {   /* not here! before! in _init! */
		register int i;
		for(i=0;i<OPEN_MAX;i++)
			lwip_sockmap[i] = -1;
		initialized = 1;
	}
	if (domain != PF_INET && domain != PF_INET6)
		return native_socket(domain,type,protocol) ;
	else
		return lwip_socket(domain,type,protocol) ;
}

int write(int s, const void *data, size_t size)
{
	if (lwip_sockmap[s] < 0)
		return native_write(s,data,size) ;
	else
		return lwip_write(s,data,size) ;
}

int shutdown(int s, int how)
{
	if (lwip_sockmap[s] < 0)
		return native_shutdown(s,how) ;
	else
		return lwip_shutdown(s,how) ;
}

int getpeername (int s, struct sockaddr *name, socklen_t *namelen)
{
	if (lwip_sockmap[s] < 0)
		return native_getpeername (s,name,namelen) ;
	else
		return lwip_getpeername (s,name,namelen) ;
}

int getsockname (int s, struct sockaddr *name, socklen_t *namelen)
{
	if (lwip_sockmap[s] < 0)
		return native_getsockname (s, name, namelen) ;
	else
		return lwip_getsockname (s, name, namelen) ;
}

int getsockopt (int s, int level, int optname, void *optval, socklen_t *optlen)
{
	if (lwip_sockmap[s] < 0)
		return native_getsockopt (s, level, optname, optval, optlen) ;
	else
		return lwip_getsockopt (s, level, optname, optval, optlen) ;
}

int setsockopt (int s, int level, int optname, void *optval, socklen_t optlen)
{
	if (lwip_sockmap[s] < 0)
		return native_setsockopt (s, level, optname, optval, optlen) ;
	else
		return lwip_setsockopt (s, level, optname, optval, optlen) ;
}

int ioctl(int s, long cmd, void *argp)
{
	if (lwip_sockmap[s] < 0)
		return native_ioctl(s,cmd,argp) ;
	else
		return lwip_ioctl(s,cmd,argp) ;
}

int select(int maxfdp1, fd_set *readset, fd_set *writeset, fd_set *exceptset,
		    struct timeval *timeout)
{
	lwip_select(maxfdp1,readset,writeset,exceptset,timeout);
}
#endif

