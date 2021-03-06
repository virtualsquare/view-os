/**
 * @file
 */
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
 *   51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */ 
#ifndef _LWIPV6_H
#define _LWIPV6_H
#include <stdio.h>
#include <stdlib.h>   /* timeval */ 
#include <stdint.h>   /* uint32_t */ 
#include <errno.h>   
#include <sys/poll.h>   
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#ifndef AF_UNSPEC
#define AF_UNSPEC       0
#endif
#ifndef PF_UNSPEC
#define PF_UNSPEC       AF_UNSPEC
#endif
#ifndef AF_INET
#define AF_INET         2
#endif
#ifndef PF_INET
#define PF_INET         AF_INET
#endif
#ifndef AF_INET6
#define AF_INET6        10
#endif
#ifndef PF_INET6
#define PF_INET6        AF_INET6
#endif
#ifndef AF_NETLINK
#define AF_NETLINK      16
#endif
#ifndef PF_NETLINK
#define PF_NETLINK      AF_NETLINK
#endif
#ifndef AF_PACKET
#define AF_PACKET       17
#endif
#ifndef PF_PACKET
#define PF_PACKET       AF_PACKET
#endif

struct ip_addr {
	  uint32_t addr[4];
};

#define IP4_ADDRX(ip4ax, a,b,c,d) \
	(ip4ax) = htonl(((uint32_t)((a) & 0xff) << 24) | ((uint32_t)((b) & 0xff) << 16) | \
									((uint32_t)((c) & 0xff) << 8) | (uint32_t)((d) & 0xff))

#define IP64_PREFIX (htonl(0xffff))

#define IP6_ADDR(ipaddr, a,b,c,d,e,f,g,h) ({  \
		(ipaddr)->addr[0] = htonl((uint32_t)(((a) & 0xffff) << 16) | ((b) & 0xffff)); \
		(ipaddr)->addr[1] = htonl((((c) & 0xffff) << 16) | ((d) & 0xffff)); \
		(ipaddr)->addr[2] = htonl((((e) & 0xffff) << 16) | ((f) & 0xffff)); \
		(ipaddr)->addr[3] = htonl((((g) & 0xffff) << 16) | ((h) & 0xffff)); } )

#define IP64_ADDR(ipaddr, a,b,c,d) ({ \
	  (ipaddr)->addr[0] = 0; \
	  (ipaddr)->addr[1] = 0; \
	  (ipaddr)->addr[2] = IP64_PREFIX; \
	  IP4_ADDRX(((ipaddr)->addr[3]),(a),(b),(c),(d)); })

#define IP64_MASKADDR(ipaddr, a,b,c,d) do { \
	  (ipaddr)->addr[0] = 0xffffffff; \
	  (ipaddr)->addr[1] = 0xffffffff; \
	  (ipaddr)->addr[2] = 0xffffffff; \
	  IP4_ADDRX(((ipaddr)->addr[3]),(a),(b),(c),(d)); } while (0)

#define IP_ADDR_IS_V4(ipaddr) \
	(((ipaddr)->addr[0] == 0) && \
	 ((ipaddr)->addr[1] == 0) && \
	 ((ipaddr)->addr[2] == IP64_PREFIX))

/* if set use IPv6 AUTOCONF */
#define NETIF_FLAG_AUTOCONF 0x800U
/* if set this interface supports Router Advertising */
#define NETIF_FLAG_RADV     0x2000U
#define NETIF_STD_FLAGS (NETIF_FLAG_AUTOCONF)
#define NETIF_ADD_FLAGS (NETIF_FLAG_AUTOCONF | NETIF_FLAG_RADV)

/** if set, the interface is configured using DHCP */
#define NETIF_FLAG_DHCP 0x4000U
#define NETIF_IFUP_FLAGS (NETIF_FLAG_DHCP)

/* netif creation with standard flags */
#define lwip_vdeif_add(S,A) lwip_add_vdeif((S),(A),NETIF_STD_FLAGS)
#define lwip_tapif_add(S,A) lwip_add_tapif((S),(A),NETIF_STD_FLAGS)
#define lwip_tunif_add(S,A) lwip_add_tunif((S),(A),NETIF_STD_FLAGS)
#define lwip_slirpif_add(S,A) lwip_add_slirpif((S),(A),0)
#define lwip_ifup(N) lwip_ifup_flags((N),0)
#define lwip_ifup_dhcp(N) lwip_ifup_flags((N),NETIF_FLAG_DHCP)

#ifndef LWIPV6DL
typedef void (*lwipvoidfun)();
extern const struct ip_addr ip_addr_any;
#define IP_ADDR_ANY ((struct ip_addr *)&ip_addr_any)
struct netif;
struct sockaddr;
struct stack;
struct msghdr;

/* constructor and destructors are automagically called when lwipv6
 * gets loaded/unloaded as a shared library.
 * lwip_init/lwip_fini are for static linking only */
void lwip_init(void);
void lwip_fini(void);

void lwip_thread_new(void (* thread)(void *arg), void *arg);
/* old interface */
struct stack *lwip_stack_new(void);
void lwip_stack_free(struct stack *stack);
#define LWIP_STACK_FLAG_FORWARDING 1
#define LWIP_STACK_FLAG_USERFILTER 0x2
#define LWIP_STACK_FLAG_UF_NAT     0x10000

typedef int (* lwip_capfun) (void);

/* new api */
struct stack *lwip_add_stack(unsigned long flags);
struct stack *lwip_add_stack_cap(unsigned long flags, lwip_capfun capfun);
void lwip_del_stack(struct stack *stack);

struct stack *lwip_stack_get(void);
void lwip_stack_set(struct stack *stack);

unsigned long lwip_stack_flags_get(struct stack *stackid);
void lwip_stack_flags_set(struct stack *stackid, unsigned long flags);

struct netif *lwip_add_vdeif(struct stack *stack, void *arg, int flags);
struct netif *lwip_add_tapif(struct stack *stack, void *arg, int flags);
struct netif *lwip_add_tunif(struct stack *stack, void *arg, int flags);
struct netif *lwip_add_slirpif(struct stack *stack, void *arg, int flags);

int lwip_add_addr(struct netif *netif,struct ip_addr *ipaddr, struct ip_addr *netmask);
int lwip_del_addr(struct netif *netif,struct ip_addr *ipaddr, struct ip_addr *netmask);
int lwip_add_route(struct stack *stack, struct ip_addr *addr, struct ip_addr *netmask, struct ip_addr *nexthop, struct netif *netif, int flags);
int lwip_del_route(struct stack *stack, struct ip_addr *addr, struct ip_addr *netmask, struct ip_addr *nexthop, struct netif *netif, int flags);
int lwip_ifup_flags(struct netif *netif, int flags);
int lwip_ifdown(struct netif *netif);

int lwip_accept(int s, struct sockaddr *addr, socklen_t *addrlen);
int lwip_bind(int s, const struct sockaddr *name, socklen_t namelen);
int lwip_shutdown(int s, int how);
int lwip_getpeername (int s, struct sockaddr *name, socklen_t *namelen);
int lwip_getsockname (int s, struct sockaddr *name, socklen_t *namelen);
int lwip_getsockopt (int s, int level, int optname, void *optval, socklen_t *optlen);
int lwip_setsockopt (int s, int level, int optname, const void *optval, socklen_t optlen);
int lwip_close(int s);
int lwip_connect(int s, const struct sockaddr *name, socklen_t namelen);
int lwip_listen(int s, int backlog);
ssize_t lwip_recv(int s, void *mem, int len, unsigned int flags);
ssize_t lwip_read(int s, void *mem, int len);
ssize_t lwip_recvfrom(int s, void *mem, int len, unsigned int flags,
		      struct sockaddr *from, socklen_t *fromlen);
ssize_t lwip_send(int s, const void *dataptr, int size, unsigned int flags);
ssize_t lwip_sendto(int s, const void *dataptr, int size, unsigned int flags,
		    const struct sockaddr *to, socklen_t tolen);
ssize_t lwip_recvmsg(int fd, struct msghdr *msg, int flags); 
ssize_t lwip_sendmsg(int fd, const struct msghdr *msg, int flags); 

int lwip_msocket(struct stack *stack, int domain, int type, int protocol);
int lwip_socket(int domain, int type, int protocol);
ssize_t lwip_write(int s, void *dataptr, int size);
int lwip_select(int maxfdp1, fd_set *readset, fd_set *writeset, fd_set *exceptset,
		struct timeval *timeout);
int lwip_pselect(int maxfdp1, fd_set *readset, fd_set *writeset, fd_set *exceptset,
		const struct timespec *timeout, const sigset_t *sigmask);
int lwip_poll(struct pollfd *fds, nfds_t nfds, int timeout);
int lwip_ppoll(struct pollfd *fds, nfds_t nfds,
		const struct timespec *timeout, const sigset_t *sigmask);

int lwip_ioctl(int s, long cmd, void *argp);
int lwip_fcntl64(int s, int cmd, long arg);
int lwip_fcntl(int s, int cmd, long arg);

struct iovec;
ssize_t lwip_writev(int s, struct iovec *vector, int count);
ssize_t lwip_readv(int s, struct iovec *vector, int count);

void lwip_radv_load_config(struct stack *stack,FILE *filein);
int lwip_radv_load_configfile(struct stack *stack,void *arg);

int lwip_event_subscribe(lwipvoidfun cb, void *arg, int fd, int how);

/* Allows binding to TCP/UDP sockets below 1024 */
#define LWIP_CAP_NET_BIND_SERVICE 1<<10
/* Allow broadcasting, listen to multicast */
#define LWIP_CAP_NET_BROADCAST    1<<11
/* Allow interface configuration */
#define LWIP_CAP_NET_ADMIN        1<<12
/* Allow use of RAW sockets */
/* Allow use of PACKET sockets */
#define LWIP_CAP_NET_RAW          1<<13

/* add/delete a slirp port forwarding rule.
	 src/srcport is the local address/port (in the native stack)
	 dest/destport is the virtual address/port where all the 
	 traffic to src/srcport must be forwarded */
#define SLIRP_LISTEN_UDP 0x1000
#define SLIRP_LISTEN_TCP 0x2000
#define SLIRP_LISTEN_UNIXSTREAM 0x3000
#define SLIRP_LISTEN_TYPEMASK 0x7000
#define SLIRP_LISTEN_ONCE 0x8000

int lwip_slirp_listen_add(struct netif *slirpif,
		struct ip_addr *dest,  int destport,
		const void *src,  int srcport, int flags);
int lwip_slirp_listen_del(struct netif *slirpif,
		struct ip_addr *dest,  int destport,
		const void *src,  int srcport, int flags);

#else   /* Dynamic Loading */
#include <dlfcn.h>

struct ip_addr *pip_addr_any;
#define IP_ADDR_ANY ((struct ip_addr *)pip_addr_any)

struct netif;
typedef struct netif *pnetif;
typedef struct stack *pstack;
typedef pnetif (*pnetiffun)();
typedef pstack (*pstackfun)();
typedef int (*lwiplongfun)();
typedef ssize_t (*lwipssizetfun)();
typedef void (*lwipvoidfun)();

pstackfun lwip_stack_new,lwip_stack_new_cap;
lwipvoidfun lwip_stack_free;
pstackfun lwip_stack_get;
lwipvoidfun lwip_stack_set;
lwipvoidfun lwip_thread_new;

pnetiffun lwip_add_vdeif, lwip_add_tapif, lwip_add_tunif, lwip_add_slirpif;

lwiplongfun lwip_add_addr,
			lwip_del_addr,
			lwip_add_route,
			lwip_del_route,
			lwip_ifup_flags,
			lwip_ifdown,
			lwip_accept,
			lwip_bind,
			lwip_shutdown,
			lwip_getpeername,
			lwip_getsockname,
			lwip_getsockopt,
			lwip_setsockopt,
			lwip_close,
			lwip_connect,
			lwip_listen,
			lwip_socket,
			lwip_select,
			lwip_pselect,
			lwip_poll,
			lwip_ppoll,
			lwip_ioctl,
			lwip_msocket,
			lwip_event_subscribe;

lwipssizetfun lwip_recv,
			  lwip_read,
			  lwip_recvfrom,
			  lwip_send,
			  lwip_sendto,
			  lwip_recvmsg,
			  lwip_sendmsg,
			  lwip_write,
			  lwip_writev,
			  lwip_readv;


/* Added by Diego Billi */
lwiplongfun lwip_radv_load_configfile;

static inline void *loadlwipv6dl()
{
	struct lwipname2fun {
		char *funcname;
		lwiplongfun *f;
	} lwiplibtab[] = {
		{"lwip_stack_new", (lwiplongfun*)&lwip_stack_new},
		{"lwip_stack_new_cap", (lwiplongfun*)&lwip_stack_new_cap},
		{"lwip_stack_free", (lwiplongfun*)&lwip_stack_free},
		{"lwip_stack_get", (lwiplongfun*)&lwip_stack_get},
		{"lwip_stack_set", (lwiplongfun*)&lwip_stack_set}, 
		{"lwip_add_addr", &lwip_add_addr},
		{"lwip_del_addr", &lwip_del_addr},
		{"lwip_add_route", &lwip_add_route},
		{"lwip_del_route", &lwip_del_route},
		{"lwip_ifup_flags", &lwip_ifup}, 
		{"lwip_ifdown", &lwip_ifdown},
		{"lwip_accept", &lwip_accept},
		{"lwip_bind", &lwip_bind}, 
		{"lwip_shutdown", &lwip_shutdown},
		{"lwip_getpeername", &lwip_getpeername},
		{"lwip_getsockname", &lwip_getsockname},
		{"lwip_getsockopt", &lwip_getsockopt},
		{"lwip_setsockopt", &lwip_setsockopt},
		{"lwip_close", &lwip_close},
		{"lwip_connect", &lwip_connect},
		{"lwip_listen", &lwip_listen},
		{"lwip_recv", &lwip_recv}, 
		{"lwip_read", &lwip_read}, 
		{"lwip_recvfrom", &lwip_recvfrom},
		{"lwip_send", &lwip_send}, 
		{"lwip_sendto", &lwip_sendto},
		{"lwip_recvmsg", &lwip_recvmsg},
		{"lwip_sendmsg", &lwip_sendmsg},
		{"lwip_socket", &lwip_socket},
		{"lwip_write", &lwip_write},
		{"lwip_select", &lwip_select},
		{"lwip_pselect", &lwip_pselect},
		{"lwip_poll", &lwip_poll},
		{"lwip_ppoll", &lwip_ppoll},
		{"lwip_ioctl", &lwip_ioctl},
		{"lwip_readv", &lwip_readv},
		{"lwip_writev", &lwip_writev},
		{"lwip_msocket", &lwip_msocket},
		{"lwip_add_vdeif", (lwiplongfun *)(&lwip_add_vdeif)},
		{"lwip_add_tapif", (lwiplongfun *)(&lwip_add_tapif)},
		{"lwip_add_tunif", (lwiplongfun *)(&lwip_add_tunif)}, 
		{"lwip_add_slirpif", (lwiplongfun *)(&lwip_add_slirpif)}, 
		{"lwip_radv_load_configfile", (lwiplongfun *)(&lwip_radv_load_configfile)},
		{"lwip_thread_new", (lwipvoidfun*) (&lwip_thread_new)},
		{"lwip_event_subscribe", (lwipvoidfun*) (&lwip_event_subscribe)}
	};
	int i;
	void *lwiphandle = dlopen("liblwipv6.so",RTLD_NOW); 
	if(lwiphandle == NULL) { 
		errno=ENOENT;
	} else {
		for (i=0; i<(sizeof(lwiplibtab)/sizeof(struct lwipname2fun)); i++) 
			*lwiplibtab[i].f = dlsym(lwiphandle,lwiplibtab[i].funcname);
		pip_addr_any = dlsym(lwiphandle,"ip_addr_any");
	}
	return lwiphandle;
}

#endif
#endif
