/*   This is part of uNAT
 *   Developed for the uNAT project
 *   Universal NAT
 *   
 *   Copyright 2004 Diego Billi - Italy
 *   Modified 2010 Renzo Davoli - Italy
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>    // getopt() 
#ifdef notdef
#include <stddef.h>
#endif
#include <stdarg.h>

//
// Lwip headers
//
#include "lwip/debug.h"
#include "lwip/mem.h"
#include "lwip/memp.h"
#include "lwip/sys.h"
#include "lwip/stats.h"
#include "lwip/stack.h"

#include "lwip/ip.h"
#include "lwip/udp.h"
#include "lwip/tcp.h"

#include "lwip/tcpip.h"
#include "netif/etharp.h"

#include "netif/vdeif.h"
#include "netif/tunif.h"
#include "netif/tapif.h"

#include "lwip/sockets.h"
#include "lwip/if.h"
#include "lwip/netlinkdefs.h"

//
// UserFilter
//
#include "lwip/nat/nat.h"
//#include "lwip/nat/nat_socket.h"

//
// uNAT headers
//
#include "main.h"
#include "commands.h"

struct stack *stack;
//============================================================================

#if 1
char ip_tmp[40];

#define print_ip(ipv, ip) \
	do { \
		bzero(ip_tmp, 40); \
		sprintf_ip((ipv), ip_tmp, (ip)); \
		printf("%s", ip_tmp); \
	} while(0);

void sprintf_ip(int ipv, char *str, struct ip_addr *addr)
{
	if (addr != NULL) {

		sprintf(str, "%x:%x:%x:%x:%x:%x:",
			ntohl(addr->addr[0]) >> 16 & 0xffff,
			ntohl(addr->addr[0]) & 0xffff,
			ntohl(addr->addr[1]) >> 16 & 0xffff,
			ntohl(addr->addr[1]) & 0xffff,
			ntohl(addr->addr[2]) >> 16 & 0xffff,
			ntohl(addr->addr[2]) & 0xffff);

		str += strlen(str);
		
		if (ipv == 0) {
			if (ip_addr_is_v4comp(addr)) 
				ipv = 4;
			else 
				ipv = 6;
		}

		if (ipv == 4)
			sprintf(str, "%d.%d.%d.%d",
				ntohl(addr->addr[3]) >> 24 & 0xff,
				ntohl(addr->addr[3]) >> 16 & 0xff,
				ntohl(addr->addr[3]) >> 8 & 0xff,
				ntohl(addr->addr[3]) & 0xff);
		else {
			sprintf(str, "%x:%x",
				ntohl(addr->addr[3]) >> 16 & 0xffff,
				ntohl(addr->addr[3]) & 0xffff);
		}
	}
}
#endif
#if 0
#define NAMEINFO_LEN 255

#define print_ip(ipv, ip) \
	do { \
		char hostbuf[NAMEINFO_LEN]; \
		printf("%s",lwip_inet_ntoa((ip),hostbuf,NAMEINFO_LEN)); \
	} while (0);

static int lwip_inet_aton(const char *cp, struct ip_addr *inp)
{
	struct addrinfo *res;
	struct addrinfo hints;
	int rv;
	memset(&hints,0,sizeof(hints));
	hints.ai_family = AF_INET6;
	hints.ai_flags = AI_V4MAPPED;
	rv=getaddrinfo(cp,NULL,&hints,&res);
	if (rv >= 0) {
		struct sockaddr_in6 *s6=(struct sockaddr_in6 *)(res->ai_addr);
		memcpy(inp,&(s6->sin6_addr), sizeof(struct ip_addr));
		freeaddrinfo(res);
		return 1;
	} else
		return 0;
}

static char *lwip_inet_ntoa(struct ip_addr *inp, char *host, size_t hostlen)
{
	struct sockaddr_in6 s6;
	s6.sin6_family=AF_INET6;
	memcpy(&(s6.sin6_addr), inp, sizeof(struct ip_addr));
	if (getnameinfo((struct sockaddr *)&s6, sizeof(s6),
				host, hostlen, NULL, 0, NI_NUMERICHOST) == 0) {
		char *percent;
		if ((percent=strchr(host,'%')) != NULL)
			*percent=0;
		if (strncmp(host,"::ffff:",7)==0 && strchr(host,'.') != NULL)
			return host+7;
		else
			return host;
	}
	else
		return NULL;
}

static void lwip_inet_mask(int bits, struct ip_addr *addr, struct ip_addr *mask)
{
	int i;
	struct ip_addr hostmask={.addr={0,0,0,0}};
	if (addr->addr[0] == 0 &&
			addr->addr[1] == 0 &&
			addr->addr[2] == IP64_PREFIX)
		bits += 96;
	for (i=0;i<bits;i++)
		hostmask.addr[i >> 5] |= 1 << (31-(i & 31));
	mask->addr[0]=htonl(hostmask.addr[0]);
	mask->addr[1]=htonl(hostmask.addr[1]);
	mask->addr[2]=htonl(hostmask.addr[2]);
	mask->addr[3]=htonl(hostmask.addr[3]);
}

static int lwip_mask2bits(struct ip_addr *addr, struct ip_addr *mask)
{
	int i,j;
	int rv;
	if (addr->addr[0] == 0 &&
			addr->addr[1] == 0 &&
			addr->addr[2] == IP64_PREFIX) {
		i=3;
		rv=0;
	} else {
		for (i=rv=0;i<4 && mask->addr[i] ==  ~0;i++) 
			rv+=32;
	}
	for (j=0;i<4 && j<32 && (mask->addr[i] & (1 << (31-j)));j++)
		rv++;
	return rv;
}
#endif


//============================================================================
// Programs options 
//============================================================================

int verbose = 0;

static int daemon_mode = 0;

static char *config_file = NULL;

#define IS_IP4_ADDR(str)  (strchr((str), '.') != NULL)
#define IS_IP6_ADDR(str)  (strchr((str), ':') != NULL)

//============================================================================
// Output functions 
//============================================================================

// Prints on standard output is verbose mode is ON
void verbose_printf(const char *format, ...)
{
	if (verbose)
	{
		va_list arg;
		va_start (arg, format);
		vfprintf(stderr, format, arg);
		va_end (arg);
	}
}

// Prints on standard error and exits!
void error_printf(const char *format, ...)
{
	va_list arg;
	va_start (arg, format);
	vfprintf(stderr,format,arg);
	va_end (arg);
}

// Prints on standard error and exits!
void exit_printf(const char *format, ...)
{
	va_list arg;
	va_start (arg, format);
	vfprintf(stderr,format,arg);
	va_end (arg);

	/* TODO  close file descriptors? ecc... */
	exit(1);
}

//============================================================================
// Drivers
//============================================================================

#define DRV_NAME_LEN 10
#define DRV_DESC_LEN 50
struct driver {
	err_t (* drv_init)(struct netif *netif);  // interface init function
	char name[DRV_NAME_LEN];                  // driver name
	char desc[DRV_DESC_LEN];                  // simple description  
};

#define SUPPORTED_DRIVERS 4
struct driver drivers_list[SUPPORTED_DRIVERS] = {

	{ tapif_init, "tap" , "Tuntap TAP. No params."},
	{ tunif_init, "tun" , "Tuntap TUN. No params"},
	{ vdeif_init, "vde" , "Vde switch. Param string: <vde_socket file>" },
};

struct driver * driver_find(char *name)
{
	int i;

	for (i=0; i < SUPPORTED_DRIVERS; i++) 
    	if (strcmp(name, drivers_list[i].name) == 0)
		return &drivers_list[i];

	return NULL;
};

//============================================================================
// Interfaces 
//============================================================================

#define INTERFACE_NAME_LEN 10
struct interface {
	struct interface    *next;

	struct driver *driver;                    
	struct netif  iface;             // Lwip interface descriptor 
	char name[INTERFACE_NAME_LEN+1]; // interface name give by the user
};

#define NUM_INTERFACES 4
struct interface interfaces_table[NUM_INTERFACES];

int num_created_interfaces = 0;
struct interface *created_interfaces = NULL; // Linked list of active interfaces

struct interface *interface_tmp;


#define INTERFACES_ADD(list, iface) \
	do { \
		(iface)->next = *(list); \
		*(list) = (iface); \
		num_created_interfaces++; \
	} while(0)

#define INTERFACES_RMV(list, iface) \
	do { \
		num_created_interfaces--; \
		if(*list == iface) { \
			*list = (*list)->next; \
		} else \
			for(interface_tmp = *list; interface_tmp != NULL; interface_tmp = interface_tmp->next) { \
				if (interface_tmp->next != NULL && interface_tmp->next == iface) { \
				    interface_tmp->next = iface->next; \
					break; \
				} \
			} \
		bzero((iface)->name, INTERFACE_NAME_LEN); \
		(iface)->next = NULL; \
	} while(0)

void interfaces_init(void)
{
	bzero(interfaces_table, sizeof(struct interface) * NUM_INTERFACES); 	

	created_interfaces = NULL;
	num_created_interfaces = 0;
}

struct interface * get_new_interface(void)
{
	int i;
	for (i=0; i <NUM_INTERFACES; i++)
	{
		if (strlen(interfaces_table[i].name) == 0)
			return &interfaces_table[i];
	}

	return NULL;
}

int interface_add(struct interface *inter)
{
	INTERFACES_ADD(&created_interfaces, inter);
	return 1;
}

int interface_remove(struct interface *inter)
{
	INTERFACES_RMV(&created_interfaces, inter);
	return 1;
}

struct interface * interface_find_by_name(char *name)
{
	struct interface *p = NULL;

	p = created_interfaces;
	while (p != NULL) {
		if (strcmp(name, p->name) == 0)
			break;
		p = p->next;
	}

	return p;
}

struct interface * interface_find_by_id(int id)
{
	struct interface *p = NULL;

	p = created_interfaces;
	while (p != NULL) {
		if (p->iface.id == id)
			break;
		p = p->next;
	}

	return p;
}

//============================================================================
// Functions called by commands.c module
//============================================================================

void stack_shutdown_done(void *param)
{
	sys_sem_t *mutex = (sys_sem_t *) param;

	printf("TCP/IP stack shutdown: done\n");
	sys_sem_signal(*mutex);  
}


void app_quit(void)
{
	sys_sem_t mutex = sys_sem_new(0);

	verbose_printf("Shutdown started...\n");

	tcpip_shutdown(stack, stack_shutdown_done, &mutex);
	sys_sem_wait_timeout(mutex, 0); 
	sys_sem_free(mutex);

	verbose_printf("Exit!\n");

	exit(0);
}

void app_set_verbose(int mode)
{
	verbose = mode;
	verbose_printf("set verbose mode on.\n");
}

void app_syscmd(char *sysline)
{
	verbose_printf("*** launching external command...\n");
	// FIX: dont' use system()
	system(sysline);
	verbose_printf("\n*** return to shell.\n");
}

void app_syscmd2(char **argv)
{
	char *path;
	int i;
	
	verbose_printf("*** launching external command...\n");
	for (i=0; argv[i] != NULL; i++) 
		printf("'%s' ", argv[i]);

	// FIX: check path==NULL?
	path = getenv("PATH");
	printf("%s\n", path);
	//execv(path, argv);
	printf("\n");

	verbose_printf("\n*** return to shell.\n");
}

void app_drivers_list(void)
{
	int i;

	printf("Name\tDescription\n");

	for (i=0; i < SUPPORTED_DRIVERS; i++) 
		printf("%s\t%s\n", drivers_list[i].name, drivers_list[i].desc);
}

//============================================================================

void app_iface_create(char *name, char *driver, char *param)
{
	struct driver *drv;
	struct interface *newif;
		
	void *state=NULL;
		
	if (interface_find_by_name(name) != NULL) {
		error_printf("*** interface '%s' already exists!\n", name);
		return;
	}

	if ((drv = driver_find(driver)) == NULL) {
		verbose_printf("*** driver '%s' not supported!.\n", driver);
		return;
	}

	if (num_created_interfaces >= NUM_INTERFACES) {
		verbose_printf("*** you can create at most %d interfaces.\n", NUM_INTERFACES);
		return;
	}

	if ((newif = get_new_interface()) == NULL) {
		verbose_printf("*** you can create at most %d interfaces.\n", NUM_INTERFACES);
		return;
	}

	// Some drivers use parameters given by the user. 
	if (param != NULL) {
		state = strdup(param);
		verbose_printf("Using param: %s\n", param);
	} 

	verbose_printf("creating interface with driver '%s'...\n", driver);

	newif->driver = drv;
	strncpy(newif->name, name, INTERFACE_NAME_LEN);

	if (tcpip_netif_add(stack, &newif->iface, state, drv->drv_init, tcpip_input, tcpip_notify) == NULL) {
		verbose_printf("*** unable to create interface '%s'.\n", name);
		return;
	}

	interface_add(newif);

	verbose_printf("interface '%s' created!.\n",  newif->name);
}

void app_iface_remove(char *name)
{
	struct interface *i;

	verbose_printf("removing interface '%s'...\n", name);

	i = interface_find_by_name(name);
	if (i != NULL) {
		netif_remove(&i->iface);

		interface_remove(i);
		verbose_printf("%s removed.\n", name);
	} 
	else
		verbose_printf("*** interface %s doesn't exist.\n", name);
}


void app_iface_updown(int up, char *name)
{
	struct interface *i;

	i = interface_find_by_name(name);
	if (i != NULL) {

		if (up) {
			i->iface.flags |= NETIF_FLAG_UP;
			verbose_printf("interface '%s' up\n", name);
		}
		else {
			i->iface.flags &= ~NETIF_FLAG_UP;
			verbose_printf("interface '%s' down\n", name);
		}
	} 
	else
		verbose_printf("*** interface %s doesn't exist.\n", name);
}


#if 0
#define  SO_IN_ADDR2IP_ADDR(from, to) IP64_ADDR((to), \
      (((from)->s_addr) & 0x000000ff), \
      ((((from)->s_addr) >> 8) & 0x000000ff), \
      ((((from)->s_addr) >> 16) & 0x000000ff), \
      ((((from)->s_addr) >> 24) & 0x000000ff))
#endif
#define  SO_IN_ADDR2IP_ADDR(from, to) do { \
	  (to)->addr[0] = 0; \
	  (to)->addr[1] = 0; \
	  (to)->addr[2] = IP64_PREFIX; \
	  (to)->addr[3] = (from)->s_addr; } while (0)


#define SO_IN_ADDR2IP_MASK(from, to) do { \
	  (to)->addr[0] = 0xffffffff; \
	  (to)->addr[1] = 0xffffffff; \
	  (to)->addr[2] = 0xffffffff; \
	  (to)->addr[3] = (from)->s_addr; } while (0)

//
// Converts 'str_ip' in the right ip_addr structure.
// If 'ipv' == 0 the function try to guess the IP version of 'str_ip' string. If the conversion
// is successful the function stores the guessed IP version in 'ipv'
// If 'ipv' == 4|6 and 'str_ip' is not an ip of the specified version the conversion fails.
int my_inet_pton (int * ipv, char *str_ip, struct ip_addr * address, int isnetmask)
{
	struct in_addr in_addr4;
	struct in6_addr in_addr6;
		
	if (IS_IP4_ADDR(str_ip)) {
		if (*ipv == 0 || *ipv == 4) {
			if (inet_pton(AF_INET, str_ip, &in_addr4) > 0)  {
				if (isnetmask) 
					SO_IN_ADDR2IP_MASK(&in_addr4, address);
				else 
					SO_IN_ADDR2IP_ADDR(&in_addr4, address);

				//printf("%s -> %ux\n",str_ip,address->addr[3]);
				if (*ipv == 0) *ipv = 4;
				return 4;
			}
		}
		else 
			return 0;
	}
	
	if (IS_IP6_ADDR(str_ip)) {
		if (*ipv == 0 || *ipv == 6) {
			if (inet_pton(AF_INET6, str_ip, &in_addr6) > 0) {
//				IP6_ADDR_LINKSCOPE(&iptmp->ipaddr, netif->hwaddr);
				ip_addr_set(address, (struct ip_addr *) &in_addr6.s6_addr);
//				memcpy(&addre->ipaddr, &iptmp, oprefix->preflen / 8);
				if (*ipv == 0) *ipv = 6;
				return 6;
			}
		}
		else 
			return 0;
	}
	
	return 0;
}


int get_mask_len (struct ip_addr *netmask)
{
	int result=0;
	register int i,j;
	for (i=0; i<4; i++)
		if (~netmask->addr[i]==0)
			result+=32;
		else
			break;
	if (i<4 && netmask->addr[i] != 0) 
		for (j=0; j<32; j++)
			if (ntohl(netmask->addr[i]) & 1 << (31 - j))
				result++;
	return result;
}


void get_prefix_mask(int prefix,struct ip_addr *netmask)
{
	register int i,j;
	register int tmp;
	for (i=0; i<4; i++, prefix -= 32) {
		if (prefix > 32)
			netmask->addr[i]=0xffffffff;
		else if (prefix > 0) {
			tmp=0;
			for (j=0;j<prefix;j++)
				tmp |= (1 << (31 - j));
			netmask->addr[i]=htonl(tmp);
		} else
			netmask->addr[i]=0;
	}
}

int create_ip_and_netmask(struct ip_addr *ip, struct ip_addr *netmask, char *str_ip, char *str_net, struct netif *netif)
{
	struct in_addr in_addr4;
	struct in_addr in_net4;
	struct in6_addr in_addr6;
	struct in6_addr in_net6;
	struct ip_addr iptmp;
	int n;

	if (IS_IP4_ADDR(str_ip)) {
		if (inet_pton(AF_INET, str_ip , &in_addr4) == 0) 
			return -1;
		if (inet_pton(AF_INET, str_net, &in_net4) == 0) 
			return -1;

		SO_IN_ADDR2IP_ADDR(&in_addr4, ip);
		SO_IN_ADDR2IP_MASK(&in_net4, netmask);

		return 1;
	}

	if (IS_IP6_ADDR(str_ip)) {

		IP6_ADDR_LINKSCOPE(ip, netif->hwaddr);

		/* Set IP */
		if (inet_pton(AF_INET6, str_ip, &in_addr6) == 0) 
			return -1;
		ip_addr_set(&iptmp, (struct ip_addr *) &in_addr6.s6_addr);


		/* Set Netmask */
		if (inet_pton(AF_INET6, str_net, &in_net6) > 0) {
			ip_addr_set(netmask, (struct ip_addr *) &in_net6.s6_addr);
		}
		else {
			n = strtol(str_net, (char **)NULL, 10);
			if ((errno != ERANGE) && (n >= 0)) {
				get_prefix_mask(n, netmask);
			}
			else
				return -1;
		}

		n = get_mask_len(netmask);

		memcpy(ip, &iptmp, n / 8);

		return 1;
	}

	return 0;
}


void app_ip_adddel(int cmd, char *ifname, char *ip, char *net)
{
	struct interface *i;

	struct ip_addr ipaddr;
	struct ip_addr netmask;	
	
	i = interface_find_by_name(ifname);
	if (i != NULL) {

		if (create_ip_and_netmask(&ipaddr, &netmask, ip, net, &i->iface) < 0) {
			error_printf("*** invalid value\n");
			return;
		}
		
		if (cmd == 1)
			netif_add_addr(&i->iface, &ipaddr, &netmask);
		else
		if (cmd == 0)
			netif_del_addr(&i->iface, &ipaddr, &netmask);
	} 
	else
		verbose_printf("*** interface %s doesn't exist.\n", ifname);
}


void print_interface(struct interface *inter)
{
	int i;
	int ipv;
	struct ip_addr_list *addr;

	printf("%s\t", inter->name);
	printf("Drv: %s [Id: %d (%c%c%d)]  ", inter->driver->name, inter->iface.id, inter->iface.name[0], inter->iface.name[1], inter->iface.num );
	printf("HWaddr: ");
	if (inter->iface.hwaddr_len > 0)
		for (i=0; i < inter->iface.hwaddr_len; i++) {
			printf("%02X", inter->iface.hwaddr[i]);
			if (i < (inter->iface.hwaddr_len-1))
				printf(":");
		}
	else
		printf("none");
	printf("\n");

	if (inter->iface.addrs != NULL) {
		addr = inter->iface.addrs;
		do {

			if(ip_addr_is_v4comp(&addr->ipaddr)) {
				ipv = 4; 
				printf("\tinet4 ");
			} else {
				ipv = 6;
				printf("\tinet6 ");
			}

			printf("addr: ");  print_ip(ipv, &addr->ipaddr);
			printf(" Mask: "); print_ip(ipv, &addr->netmask);
			printf(" ");
			if (addr->flags & IFA_F_PERMANENT ) printf("Permanent ");
			if (addr->flags & IFA_F_SECONDARY ) printf("Secondary ");
			if (addr->flags & IFA_F_TEMPORARY ) printf("Temporary ");
			if (addr->flags & IFA_F_DEPRECATED) printf("Deprecated ");
			if (addr->flags & IFA_F_TENTATIVE ) printf("Tentative ");
			printf("\n");
			addr = addr->next;
		} while (addr != inter->iface.addrs) ;
	}

	printf("\t");
	if (inter->iface.flags & NETIF_FLAG_UP)           printf("UP ");
	if (inter->iface.flags & NETIF_FLAG_BROADCAST)    printf("BROADCAST ");
	if (inter->iface.flags & NETIF_FLAG_LOOPBACK)     printf("LOOPBACK ");
	if (inter->iface.flags & NETIF_FLAG_POINTTOPOINT) printf("POINT-TO-POINT ");
	if (inter->iface.flags & NETIF_FLAG_LINK_UP)      printf("LINKUP ");
	if (inter->iface.flags & NETIF_PROMISC)           printf("PROMISC ");

	printf("MTU: %d\n", inter->iface.mtu);
}

void app_iface_list(void)
{
	struct interface *p;

	if (created_interfaces == NULL) {
		verbose_printf("no interfaces.\n");
		return;
	}

	verbose_printf("%d interfaces:\n", num_created_interfaces);
	p = created_interfaces;
	while (p != NULL) {
		print_interface(p);
		if (p->next) printf("\n");
		p = p->next;
	}
}

//============================================================================

void app_route_list()
{
	int ipv;
	struct interface *i;
	struct ip_route_list *r = stack->ip_route_head;

	if (r != NULL)
		printf("%-45s %-45s %-45s %s\n", "Destination",  "Gateway", "Genmask", "Iface");

	while (r != NULL)	{
#if 1
		if (ip_addr_is_v4comp(&r->addr))  ipv = 4;
		else                              ipv = 6;
		sprintf_ip(ipv, ip_tmp, &r->addr);
		printf("%-45s ", ip_tmp);
		sprintf_ip(ipv, ip_tmp, &r->nexthop);
		printf("%-45s ", ip_tmp);
		sprintf_ip(ipv, ip_tmp, &r->netmask);
		printf("%-45s ", ip_tmp);
#endif
#if 0
		char hostbuf[NAMEINFO_LEN]; 
		printf("%s/%d",lwip_inet_ntoa(&r->addr,hostbuf,NAMEINFO_LEN),lwip_mask2bits(&r->addr,&r->netmask)); 
		printf(" via %s dev",lwip_inet_ntoa(&r->nexthop,hostbuf,NAMEINFO_LEN));
#endif
		i = interface_find_by_id(r->netif->id);
		printf("%s", i->name);
		printf("\n");
		r = r->next;	
	}	
}

void app_route_adddel(int cmd, char *ip, char *net, char *next, char *ifname )
{
	struct interface *i;

	int ipv;
	
	struct ip_addr ipaddr;
	struct ip_addr netmask;
	struct ip_addr nexthop;

	ipv = 0;
	if (my_inet_pton(&ipv, ip, &ipaddr, 0) == 0) {
		error_printf("*** invalid IP address '%s'!\n", ip);
		return;
	}
	if (my_inet_pton(&ipv, net, &netmask, 1) == 0) {
		error_printf("*** invalid netmask '%s'!\n", net);
		return;
	}
	if (my_inet_pton(&ipv, next, &nexthop, 0) == 0) {
		error_printf("*** invalid IP address '%s'!\n", next);
		return;
	}

	i = interface_find_by_name(ifname);
	if (i != NULL) {
		
		if (cmd == 1)
			ip_route_list_add(stack, &ipaddr, &netmask, &nexthop, & i->iface, 0); 
		else
		if (cmd == 0)
			ip_route_list_del(stack, &ipaddr, &netmask, &nexthop, & i->iface, 0); 
	} 
	else
		verbose_printf("*** interface %s doesn't exist.\n", ifname);
}

void app_route_delif(char *ifname)
{
	struct interface *i;

	i = interface_find_by_name(ifname);
	if (i != NULL) 
		ip_route_list_delnetif(stack, & i->iface);
	else
		verbose_printf("*** interface %s doesn't exist.\n", ifname);
}

//============================================================================

#ifdef LWIP_NAT


#define STR_ALL  "*"
void print_nat_table(struct nat_rule *table, char *title)
{
	struct interface *inter;

	struct nat_rule *p;

	p = table;
	while (p != NULL)
	{
		printf("%s   ", title);

		//
		// Print options
		//
		if (p->matches.iface != NULL) {
			inter = interface_find_by_id(p->matches.iface->id);
			if (inter == NULL) 
				return;         // should never be true.
			printf("%s\t\t", inter->name);
		}
		else
			printf("*\t\t");		

		printf("ipv: %d", p->matches.ipv);
		printf(" ");

		printf("sip: ");
		if (IS_IGNORE_IP(&p->matches.src_ip)) printf("*");
		else { print_ip (p->matches.ipv, &p->matches.src_ip); }
		printf("  ");
			
		printf("dip: ");
		if (IS_IGNORE_IP(&p->matches.dst_ip)) printf("*");
		else { print_ip (p->matches.ipv, &p->matches.dst_ip); }
		printf("  ");


		printf("proto: ");
		if (IS_IGNORE_PROTO(p->matches.protocol)) printf("*\t\t");			
		else if (p->matches.protocol == IP_PROTO_TCP) printf("tcp\t\t");
		else if (p->matches.protocol == IP_PROTO_UDP) printf("udp\t\t");
		else printf("unknown");
		printf("  ");
		
		printf("dport: ");
		if (IS_IGNORE_PORT(p->matches.dst_port)) printf("*");
		else printf("%d", ntohs(p->matches.dst_port));
		printf("  ");
		
		printf("sport: ");
		if (IS_IGNORE_PORT(p->matches.src_port)) printf("*");
		else printf("%d", ntohs(p->matches.src_port));
		printf("  ");
		
		// Print target
		printf("--> %s", STR_NATNAME(p->type));
		if (p->type != NAT_MASQUERADE) {
			printf("  "); 
			print_ip (p->matches.ipv, &p->manip.ipmin);

			if (p->manip.flag & MANIP_RANGE_PROTO) {
				printf(":%d", ntohs(p->manip.protomin.value));
			}
		}

		printf("\n");
		p = p->next;
	}
}

void app_nat_list(int ipv)
{
	printf("Position   Interface\tOptions\n");

	if (stack->stack_nat) {
		print_nat_table(stack->stack_nat->nat_in_rules, "PREROUTING");
		print_nat_table(stack->stack_nat->nat_out_rules, "POSTROUTING");
	}
}

int my_strtol(long int *val, char *str)
{
	char *ptr = NULL;
	
	*val = strtol(str, &ptr, 10);
	if (errno == ERANGE || *ptr != '\0') 
		return -1;
	else 
		return 1;
}

void app_nat_add(int ipv, nat_table_t pos, nat_type_t type, char *ifname, char *proto, 
		char *sip, char *dip, 
		char *dport, char *sport, 
		char *ip_min, char *ip_max, 
		char *port_min, char *port_max)
{
   	struct nat_rule *rule;
	struct interface *i;
		
	int address_ipv = 0;

	long int n;
	
	rule = nat_new_rule();
	if (rule == NULL) {
		verbose_printf("*** unable to create new NAT rule.");
		return;
	}

	do {
		rule->matches.ipv = ipv;

		//
		// Set rule options
		//
		if (ifname != NULL) {
			i = interface_find_by_name(ifname);
			if (i == NULL) {
				verbose_printf("*** interface %s doesn't exist.\n", ifname);
				break;
			} 
			rule->matches.iface = &i->iface;
		}
	
		// source ip  & dest ip options
		if (sip != NULL) {
			
			if (my_inet_pton(&address_ipv, sip, &rule->matches.src_ip, 0) <= 0) {
				error_printf("*** invalid IP address '%s'!\n", sip);
				break;
			}
		}
		else
			SET_IGNORE_IP(&rule->matches.src_ip);
	
		if (dip != NULL) {
			if (my_inet_pton(&address_ipv,dip,  &rule->matches.dst_ip, 0) <= 0) {
				error_printf("*** invalid IP address '%s'!\n", dip);
				break;
			}
		} 
		else
			SET_IGNORE_IP(&rule->matches.dst_ip);
		

		if (proto != NULL) {
			if (strcmp(proto, "tcp") == 0) rule->matches.protocol = IP_PROTO_TCP;
			else if (strcmp(proto, "udp") == 0) rule->matches.protocol = IP_PROTO_UDP;
			else {
				error_printf("*** invalid protocol '%s'!\n", proto);
				break;
			}
		}
		else rule->matches.protocol = IGNORE_PROTO;


		// source port & dest port
		if (sport == NULL)
			rule->matches.src_port = IGNORE_PORT;
		else {
			if (my_strtol(&n, sport) < 0) {
			//n = strtol(sport, (char **)NULL, 10);
			//if (errno == ERANGE) {
				error_printf("*** invalid value '%s'!\n", sport);
				break;
			}
			rule->matches.src_port = htons(n);
		}
		
		if (dport == NULL) 
			rule->matches.dst_port = IGNORE_PORT;
		else {
			if (my_strtol(&n, dport) < 0) {
			//n = strtol(dport, (char **)NULL, 10);
			//if (errno == ERANGE) {
				error_printf("*** invalid value '%s'!\n", dport);
				break;
			}
			rule->matches.dst_port = htons(n);
		}
		
		//
		// Set rule target
		//
		rule->type = type;
		
		if ((type == NAT_SNAT) || (type == NAT_DNAT)){

			rule->manip.flag |= MANIP_RANGE_IP;

			verbose_printf("NAT '%s':'%s'\n", ip_min, port_min);
			
			if (my_inet_pton(&address_ipv,  ip_min, & rule->manip.ipmin, 0) <= 0) {
				error_printf("*** invalid IP address '%s'!\n", ip_min);
				break;
			}
			
			if (port_min != NULL) {
				if (my_strtol(&n, port_min) < 0) {
					error_printf("*** invalid value '%s'!\n", port_min);
					break;
				}
				rule->manip.protomin.value = htons(n);
			}

			if (port_max != NULL) {
				if (my_strtol(&n, port_max) < 0) {
					error_printf("*** invalid value '%s'!\n", port_max);
					break;
				}
				rule->manip.protomax.value = htons(n);
			}

		}
		else if (type == NAT_MASQUERADE) {
			verbose_printf("MASQUERADE\n");
			rule->manip.flag = 0;
		}
		else
			break;
	
		nat_add_rule(stack, ipv, pos, rule);
	
	} while (0);
}

void app_nat_del(int ipv, nat_table_t pos, int num)
{
	struct nat_rule *removed;

	if ((removed = nat_del_rule(stack, pos, num)) != NULL)
		nat_free_rule(removed);
}

#endif 

//============================================================================
// Programs options 
//============================================================================

static char const short_options[] = "+vdc:";

//long opt syntax: opt, has arg, flag, value
static struct option long_options[] = {    
	{"verbose" , 0, 0, 'v'},       // set verbose mode on
	{"daemon"  , 0, 0, 'd'},       // set Input interface options
	{"config"  , 1, 0, 'c'},       // set Input interface options
	{0, 0, 0, 0}
};

// Needed for getopt() 
extern char *optarg;
extern int   optind, opterr, optopt;

// Prints help message and exits!
void print_help(void)
{
	printf("Usage: unat [options]' \n"
		"   -v | --verbose         Verbose mode on.\n"
		"   -d | --daemon          Set daemon mode. -i is required\n"
		"   -c | --config <file>   Read configuration from file.\n"
	);
	exit(1);
}

//============================================================================
// Main
//============================================================================

//
// Commands parser and user input run in separated thread.
//
// We set up a a producer/consumer scenario with a thread that produce 
// user input and store it in the "command_line" global variabile.
//      
//    uNAT/Lwip Thread  <------ command_line ------> User Input Thread
//

sys_sem_t app_init_mutex;

static sys_sem_t user_input_empty_mutex;
static sys_sem_t user_input_full_mutex;

static char command_line[CMD_MAX_LEN+1];

void stack_init_done(void *param)
{
	sys_sem_t *mutex = (sys_sem_t *) param;

	verbose_printf("LWIPV6a stack now running.\n");

	sys_sem_signal(*mutex);  
}


void stack_thread(void *arg)
{
	sys_sem_t stack_init_mutex;

	verbose_printf("Init stack data: ");

#if LWIP_STATS
	stats_init();	
#endif
	sys_init();	
	mem_init();	
	memp_init();	
	pbuf_init();	
	tcpip_init();	

	verbose_printf("done");

	/* Start stack */
	stack_init_mutex = sys_sem_new(0);
	stack=tcpip_start(stack_init_done, &stack_init_mutex,
			LWIP_STACK_FLAG_FORWARDING|
			LWIP_STACK_FLAG_USERFILTER|
			LWIP_STACK_FLAG_UF_NAT
#if LWIP_CAPABILITIES
			,NULL
#endif
			);
	/* Wait for stack initialization */
	sys_sem_wait_timeout(stack_init_mutex, 0); 

	/* Unblock user input */
	sys_sem_signal(app_init_mutex);  

	// Wait for user commands and parse them
	while (1) {
		// P (full)
		sys_sem_wait_timeout(user_input_full_mutex, 0); 

		// Parse user command in this thread
		parse_command_line(command_line);

		// V (empty)
		sys_sem_signal(user_input_empty_mutex);  
	}
}


// Initialize uNAT data and lwip stack 
int app_init(void)
{
	verbose_printf("Init uNAT...\n");

	app_init_mutex   = sys_sem_new(0);

	// unbuffered output only for debug
	setvbuf(stdout, (char *)NULL, _IONBF, 0); 

	if (commands_init() == 0) {
		error_printf("Unable to setup shell commands!\n");
		exit(1);
	}
		
	interfaces_init();

	user_input_empty_mutex = sys_sem_new(1);
	user_input_full_mutex = sys_sem_new(0);

	/* Launch LWIP STACK */
	sys_thread_new(stack_thread, NULL, DEFAULT_THREAD_PRIO);

	sys_sem_wait_timeout(app_init_mutex, 0); 

	verbose_printf("Initialization successfull!\n");

	return 1;
}

// Reads commands from a configuration file.
void read_commands(int prompt, FILE *file)
{
	int stop = 0;

	while (!stop) {

		// P (empty)
		sys_sem_wait_timeout(user_input_empty_mutex, 0); 

		if (prompt) 
			printf(SHELL_PROMPT);

		bzero(command_line, CMD_MAX_LEN + 1);
		if (fgets(command_line, CMD_MAX_LEN, file) == NULL) 
			stop = 1;

		// V (full)
		sys_sem_signal(user_input_full_mutex); 
	}
}


int main(int argc, char *argv[])
{
	FILE *config;
	int c;

	// Parse programs options and set global variabiles.
	while (1) {
		
		int option_index = 0;
	
		c = getopt_long (argc, argv, short_options, long_options, &option_index);
		if (c == -1)
			break; // no parameters 
	
		switch (c)  {
			case 'v':
				app_set_verbose(1);
				break;
			case 'd':
				daemon_mode = 1;
				break;
			case 'c':
				if (!optarg) 
					print_help();
				config_file = strdup(optarg); /* FIX: check NULL */
				break;
			default:
				print_help();
		}
	}
	
	// Strange options on command line. Show them 
	if (optind < argc) {
		
		verbose_printf ("***Warning: unrecognized params: ");
		while (optind < argc)
			verbose_printf ("%s ", argv[optind++]);
		verbose_printf ("\n");
	}

	if ((daemon_mode == 1) && (config_file == NULL) )
	    	print_help();

	// Initialize Lwip stack & programs structures.
	app_init();

	// Read config file
	if (config_file != NULL) {
		verbose_printf("Reading config file '%s'\n", config_file);
		
		if ((config = fopen(config_file, "r")) != NULL) {

			read_commands(0, config);

			fclose(config);
			verbose_printf("Closed config file '%s'\n", config_file);
		} 
		else {
			error_printf("*** unable to open '%s'!\n", config_file);
			return 0;
		}
	}

	// The main thread will read commands from standard input if
	// the NAT is not in daemon  mode.
	if (daemon_mode == 1)
	{
		// FIX: see daemon() function
		verbose_printf("Starting in daemon mode: main thread sleep\n");

		select(0, NULL, NULL, NULL, NULL);
	}
	else
	{
		verbose_printf("Starting in interactive mode.\n");

		read_commands(1, stdin);
	}

	// FIX: remove this
	// The stack is running in a separete thread.
	// We reach this line if the user exit or some strange
	// error. 
	app_quit();	
	
	return 0;
}



#if 0
int fill_netmask(struct ip_addr *netmask, int *ipv, char *net)
{
	int n;

	/* "net" stirng can be a interger value or a IP netmask */

	if (*ipv == 6) {

		n = strtol(net, (char **)NULL, 10);
		if ((errno != ERANGE) && (n >= 0)) {
			get_prefix_mask(n, netmask);
			return 1;
		}
		else
			return -1;
	}
	else
	if (*ipv == 4) {

		if (my_inet_pton(ipv, net,  netmask, 1) == 0) {
			return -1;
		}
		return 1;
	}

	return -1;
}
#endif

