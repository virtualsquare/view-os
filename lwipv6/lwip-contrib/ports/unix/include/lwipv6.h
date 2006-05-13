#ifndef _LWIPV6_H
#define _LWIPV6_H
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

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
		(ipaddr)->addr[0] = htonl((uint32_t)((a & 0xffff) << 16) | (b & 0xffff)); \
		(ipaddr)->addr[1] = htonl(((c & 0xffff) << 16) | (d & 0xffff)); \
		(ipaddr)->addr[2] = htonl(((e & 0xffff) << 16) | (f & 0xffff)); \
		(ipaddr)->addr[3] = htonl(((g & 0xffff) << 16) | (h & 0xffff)); } )

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


#ifndef LWIPV6DL
extern const struct ip_addr ip_addr_any;
#define IP_ADDR_ANY ((struct ip_addr *)&ip_addr_any)

struct netif;
struct sockaddr;
struct netif *lwip_vdeif_add(void *arg);
struct netif *lwip_tapif_add(void *arg);
struct netif *lwip_tunif_add(void *arg);

int lwip_add_addr(struct netif *netif,struct ip_addr *ipaddr, struct ip_addr *netmask);
int lwip_del_addr(struct netif *netif,struct ip_addr *ipaddr, struct ip_addr *netmask);
int lwip_add_route(struct ip_addr *addr, struct ip_addr *netmask, struct ip_addr *nexthop, struct netif *netif, int flags);
int lwip_del_route(struct ip_addr *addr, struct ip_addr *netmask, struct ip_addr *nexthop, struct netif *netif, int flags);
int lwip_ifup(struct netif *netif);
int lwip_ifdown(struct netif *netif);

int lwip_accept(int s, struct sockaddr *addr, socklen_t *addrlen);
int lwip_bind(int s, struct sockaddr *name, socklen_t namelen);
int lwip_shutdown(int s, int how);
int lwip_getpeername (int s, struct sockaddr *name, socklen_t *namelen);
int lwip_getsockname (int s, struct sockaddr *name, socklen_t *namelen);
int lwip_getsockopt (int s, int level, int optname, void *optval, socklen_t *optlen);
int lwip_setsockopt (int s, int level, int optname, const void *optval, socklen_t optlen);
int lwip_close(int s);
int lwip_connect(int s, struct sockaddr *name, socklen_t namelen);
int lwip_listen(int s, int backlog);
int lwip_recv(int s, void *mem, int len, unsigned int flags);
int lwip_read(int s, void *mem, int len);
int lwip_recvfrom(int s, void *mem, int len, unsigned int flags,
		      struct sockaddr *from, socklen_t *fromlen);
int lwip_send(int s, void *dataptr, int size, unsigned int flags);
int lwip_sendto(int s, void *dataptr, int size, unsigned int flags,
		    struct sockaddr *to, socklen_t tolen);
int lwip_socket(int domain, int type, int protocol);
int lwip_write(int s, void *dataptr, int size);
int lwip_select(int maxfdp1, fd_set *readset, fd_set *writeset, fd_set *exceptset,
		                struct timeval *timeout);
int lwip_ioctl(int s, long cmd, void *argp);
#else   /* Dynamic Loading */
#include <dlfcn.h>

struct ip_addr *pip_addr_any;
#define IP_ADDR_ANY ((struct ip_addr *)pip_addr_any)

struct netif;
typedef struct netif *pnetif;
typedef pnetif (*pnetiffun)();
typedef int (*lwipintfun)();

pnetiffun lwip_vdeif_add, lwip_tapif_add, lwip_tunif_add;

lwipintfun lwip_add_addr,
lwip_del_addr,
lwip_add_route,
lwip_del_route,
lwip_ifup,
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
lwip_recv,
lwip_read,
lwip_recvfrom,
lwip_send,
lwip_sendto,
lwip_socket,
lwip_write,
lwip_select,
lwip_ioctl;

#define LOADLWIPV6DL ({ \
struct lwipname2fun {\
	char *funcname;\
	lwipintfun *f;\
} lwiplibtab[] = {\
	{"lwip_add_addr", &lwip_add_addr},\
	{"lwip_del_addr", &lwip_del_addr},\
	{"lwip_add_route", &lwip_add_route},\
	{"lwip_del_route", &lwip_del_route},\
	{"lwip_ifup", &lwip_ifup}, \
	{"lwip_ifdown", &lwip_ifdown},\
	{"lwip_accept", &lwip_accept},\
	{"lwip_bind", &lwip_bind}, \
	{"lwip_shutdown", &lwip_shutdown},\
	{"lwip_getpeername", &lwip_getpeername},\
	{"lwip_getsockname", &lwip_getsockname},\
	{"lwip_getsockopt", &lwip_getsockopt},\
	{"lwip_setsockopt", &lwip_setsockopt},\
	{"lwip_close", &lwip_close},\
	{"lwip_connect", &lwip_connect},\
	{"lwip_listen", &lwip_listen},\
	{"lwip_recv", &lwip_recv}, \
	{"lwip_read", &lwip_read}, \
	{"lwip_recvfrom", &lwip_recvfrom},\
	{"lwip_send", &lwip_send}, \
	{"lwip_sendto", &lwip_sendto},\
	{"lwip_socket", &lwip_socket},\
	{"lwip_write", &lwip_write},\
	{"lwip_select", &lwip_select},\
	{"lwip_ioctl", &lwip_ioctl},\
  {"lwip_vdeif_add", (lwipintfun *)(&lwip_vdeif_add)},\
	{"lwip_tapif_add", (lwipintfun *)(&lwip_tapif_add)},\
	{"lwip_tunif_add", (lwipintfun *)(&lwip_tunif_add)}};\
		int i;\
		void *lwiphandle=dlopen("liblwip.so",RTLD_NOW); \
		if(lwiphandle==NULL) { \
		fprintf(stderr,"lwiplib not found %s\n",dlerror());\
		exit(-1);\
		}\
		for (i=0;i<28;i++) \
		*lwiplibtab[i].f=dlsym(lwiphandle,lwiplibtab[i].funcname);\
		pip_addr_any=dlsym(lwiphandle,"ip_addr_any");\
		})

#endif
#endif
