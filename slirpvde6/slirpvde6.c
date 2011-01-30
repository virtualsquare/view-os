/* Copyright 2003-2010 Renzo Davoli 
 * Licensed under the GPL
 * Modified by Ludovico Gardenghi 2005
 * 
 * This file is part of SlirpVde6.
 *   
 * SlirpVde6 is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by 
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *        
 * SlirpVde6 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *           
 * You should have received a copy of the GNU General Public License
 * along with SlirpVde6.  If not, see <http://www.gnu.org/licenses/>.
 */            


#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <stdarg.h>
#include <getopt.h>
#include <libgen.h>
#include <lwipv6.h>
#include <limits.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include "bootp.h"
#include "tftp.h"
#include "dnsforward.h"
#include "xlocal.h"
#include "slirpvde6.h"
#include "config.h"

#define RADV

#ifdef HAVE_GETOPT_LONG_ONLY
#define GETOPT_LONG getopt_long_only
#else
#define GETOPT_LONG getopt_long
#endif

#if defined(VDE_DARWIN) || defined(VDE_FREEBSD)
# if defined HAVE_SYSLIMITS_H
#   include <syslimits.h>
# elif defined HAVE_SYS_SYSLIMITS_H
#   include <sys/syslimits.h>
# else
#   error "No syslimits.h found"
# endif
#endif

#define DEFAULT_IP_ADDR "10.0.2.1"
#define DEFAULT_MASK_BITS
#define NAMEINFO_LEN 255

int logok=0;
char *prog;

struct ip_addr *vhosts=NULL;
int *maskbits=NULL;
int nvhosts=0;
char *tftp_prefix=NULL;
struct ip_addr vnetwork;
struct ip_addr vdhcp_start;
int vdhcp_naddr;
struct ip_addr *dhcphost;
int dhcpmask;
struct ip_addr *dhcpnameserver;
struct ip_addr *vnameserver;

static char *pidfile = NULL;
static char pidfile_path[PATH_MAX];
int dhcpmgmt=0;
int dnsforward=0;
#ifdef RADV
static char *radvd = NULL;
static char *radvdfile = NULL;
#endif

struct slirpoll_args {
	void (*fun)(int fd, void *arg);
	void *funarg;
};

struct pollfd *slirpoll_pfd;
struct slirpoll_args *slirpoll_pfd_args;
int slirpoll_npfd;
int slirpoll_npfd_max;

#define NETIF_MAX_STEP 8

int slirpoll_addfd(int fd,
		void (*fun)(int fd, void *arg),
		void *funarg)
{
	int n;

	for (n=0; n < slirpoll_npfd && slirpoll_pfd[n].fd >= 0; n++)
		;
	if (n == slirpoll_npfd) {
		if (n >= slirpoll_npfd_max) {
			int newmax=slirpoll_npfd_max + NETIF_MAX_STEP;
			void *newpfd=realloc(slirpoll_pfd,(newmax * sizeof(struct pollfd)));
			void *newpfdargs=realloc(slirpoll_pfd_args,
					(newmax * sizeof (struct slirpoll_args)));
			if (newpfd && newpfdargs) {
				slirpoll_pfd=newpfd;
				slirpoll_pfd_args=newpfdargs;
				slirpoll_npfd_max=newmax;
			} else {
				if (newpfd) mem_free(newpfd);
				if (newpfdargs) mem_free(newpfdargs);
				return -1;
			}
		}
		slirpoll_npfd++;
	}
	slirpoll_pfd[n].fd = fd;
	slirpoll_pfd[n].events = POLLIN;
	slirpoll_pfd[n].revents = 0;
	slirpoll_pfd_args[n].fun = fun;
	slirpoll_pfd_args[n].funarg = funarg;
	//printf("slirpoll_addfd %d (%d)\n",fd,n);
	return n;
}

void slirpoll_delfd(int fd)
{
	int n;

	for (n=0; n < slirpoll_npfd && slirpoll_pfd[n].fd != fd; n++)
		;

	if (n < slirpoll_npfd) {
		slirpoll_pfd[n].fd = -1;
		slirpoll_pfd[n].events = 0;
		slirpoll_pfd[n].revents = 0;
		slirpoll_pfd_args[n].fun = NULL;
		slirpoll_pfd_args[n].funarg = NULL;
		while (slirpoll_npfd > 0 && slirpoll_pfd[slirpoll_npfd-1].fd < 0)
			slirpoll_npfd--;
	}
	//printf("slirpoll_delfd %d (%d)\n",fd,n);
}


void lprint(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
}

void printlog(int priority, const char *format, ...)
{
	va_list arg;

	va_start (arg, format);

	if (logok)
		vsyslog(priority,format,arg);
	else {
		fprintf(stderr,"%s: ",prog);
		vfprintf(stderr,format,arg);
		fprintf(stderr,"\n");
	}
	va_end (arg);
}

static void save_pidfile()
{
	if(pidfile[0] != '/')
		strncat(pidfile_path, pidfile, sizeof(pidfile_path) - strlen(pidfile_path) -1);
	else {
		pidfile_path[0] = 0;
		strncat(pidfile_path, pidfile, sizeof(pidfile_path)-1);
	}

	int fd = open(pidfile_path,
			O_WRONLY | O_CREAT | O_EXCL,
			S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	FILE *f;

	if(fd == -1) {
		printlog(LOG_ERR, "Error in pidfile creation: %s", strerror(errno));
		exit(1);
	}

	if((f = fdopen(fd, "w")) == NULL) {
		printlog(LOG_ERR, "Error in FILE* construction: %s", strerror(errno));
		exit(1);
	}

	if(fprintf(f, "%ld\n", (long int)getpid()) <= 0) {
		printlog(LOG_ERR, "Error in writing pidfile");
		exit(1);
	}

	fclose(f);
}

static void cleanup(void)
{
}

int lwip_inet_aton(const char *cp, struct ip_addr *inp)
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

char *lwip_inet_ntoa(struct ip_addr *inp, char *host, size_t hostlen)
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

void lwip_inet_mask(int bits, struct ip_addr *addr, struct ip_addr *mask)
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

#define IS_TCP 0
#define IS_UDP 1
static char *tcpudp[]={"TCP","UDP"};

struct redir_tcp_udp {
	struct ip_addr inaddr;
	int is_udp;
	int port;
	int lport;
	struct redir_tcp_udp *next;
};

struct redirx {
	struct ip_addr inaddr;
	int start_port;
	int display;
	int screen;
	struct redirx *next;
};

struct redirlocx {
	int port;
	char *path;
	struct redirlocx *next;
};

static struct redir_tcp_udp *parse_redir_tcp(struct redir_tcp_udp *head, char *buff,int is_udp)
{
	u_int32_t inaddr=0;
	int port=0;
	int lport=0;
	char *ipaddrstr=NULL;
	char *portstr=NULL;
	struct redir_tcp_udp *new;

	if ((ipaddrstr = strchr(buff, ':'))==NULL || *(ipaddrstr+1)==0) {
		lprint("redir %s syntax error\n",tcpudp[is_udp]);
		return head;
	}
	*ipaddrstr++ = 0;

	if ((portstr = strchr(ipaddrstr, ':'))==NULL || *(portstr+1)==0) {
		lprint("redir %s syntax error\n",tcpudp[is_udp]);
		return head;
	}
	*portstr++ = 0;

	sscanf(buff,"%d",&lport);
	sscanf(portstr,"%d",&port);
	if (ipaddrstr) 
		inaddr = inet_addr(ipaddrstr);

	if (!inaddr) {
		lprint("%s redirection error: an IP address must be specified\n",tcpudp[is_udp]);
		return head;
	}

	if ((new=malloc(sizeof(struct redir_tcp_udp)))==NULL)
		return head;
	else {
		lwip_inet_aton(ipaddrstr,&new->inaddr);
		new->is_udp=is_udp;
		new->port=port;
		new->lport=lport;
		new->next=head;
		return new;
	}
}

static struct redirx *parse_redir_x(struct redirx *head, char *buff)
{
	char *ptr=NULL;
	u_int32_t inaddr = 0;
	int display=0;
	int screen=0;
	int start_port = 0;
	struct redirx *new;
	if ((ptr = strchr(buff, ':'))) {
		*ptr++ = 0;
		if (*ptr == 0) {
			lprint("X-redirection syntax error\n");
			return head;
		}
	}
	if (buff[0]) {
		inaddr = inet_addr(buff);
		if (inaddr == 0xffffffff) {
			lprint("Error: X-redirection bad address\r\n");
			return head;
		}
	}
	if (ptr) {
		if (strchr(ptr, '.')) {
			if (sscanf(ptr, "%d.%d", &display, &screen) != 2)
				return head;
		} else {
			if (sscanf(ptr, "%d", &display) != 1)
				return head;
		}
	}

	if (!inaddr) {
		lprint("Error: X-redirection an IP address must be specified\r\n");
		return head;
	}

	if ((new=malloc(sizeof(struct redirx)))==NULL)
		return head;
	else {
		lwip_inet_aton(buff,&new->inaddr);
		new->display=display;
		new->screen=screen;
		new->start_port=start_port;
		new->next=head;
		return new;
	}
}

static struct redirlocx *parse_redir_locx(struct redirlocx *head, char *buff)
{
	char *path;
	int port=atoi(buff);
	struct redirlocx *new;
	if ((path = strchr(buff, ':'))) {
		*path++=0;
		if ((new=malloc(sizeof(struct redirlocx)))==NULL)
			return head;
		else {
			new->port=port;
			new->path=strdup(path);
			new->next=head;
			return new;
		}
	} else {
		lprint("Error: tcp2unix redirection sytax error -x port:path e.g. -x 6000:/tmp/.X11-unix/X0\r\n");
		return head;
	}
}

static void do_redir_tcp(struct netif *slirpnif,
		struct redir_tcp_udp *head, int quiet)
{
	struct ip_addr host_addr=ip_addr_any;
	if (head) {
		do_redir_tcp(slirpnif,head->next,quiet);

		if (lwip_slirp_listen_add(slirpnif,
					&head->inaddr, head->port, IP_ADDR_ANY, head->lport,
					head->is_udp?SLIRP_LISTEN_UDP:SLIRP_LISTEN_TCP) >= 0) {
			if (!quiet) {
				char hostbuf[NAMEINFO_LEN];
				lprint("                    redir %s   =%d:%s:%d\n", 
						tcpudp[head->is_udp],head->lport,
						lwip_inet_ntoa(&head->inaddr,hostbuf,NAMEINFO_LEN),head->port);
			}
		}
		free(head);
	}
}

static void do_redir_x(struct netif *slirpnif,
		struct redirx *head, int quiet)
{
	if (head) {
		do_redir_x(slirpnif,head->next,quiet);
		int i;

		for (i = 6000 + head->start_port; i <= 6100; i++) {
			if (lwip_slirp_listen_add(slirpnif,
						&head->inaddr, 6000 + head->display, IP_ADDR_ANY, i,
						SLIRP_LISTEN_TCP) == 0) {
				if (!quiet) {
					char hostbuf[NAMEINFO_LEN];
					lprint("                    redir X     =%s:%d.%d\n", 
							lwip_inet_ntoa(&head->inaddr,hostbuf,NAMEINFO_LEN),head->display,head->screen);
				}
				break;
			}
		}
		free(head);
	}
}

static void do_redir_locx(struct stack *stack,
		    struct redirlocx *head, int quiet)
{
	if (head) {
		do_redir_locx(stack,head->next,quiet);

		if (xlocal_add(stack,
					head->port, head->path) >= 0) {
			if (!quiet) {
				char hostbuf[NAMEINFO_LEN];
				lprint("                    redir locX  =%d:%s\n",
						head->port, head->path);
			}
		}
		free(head);
	}
}

void usage(char *name) {
	fprintf(stderr,
			"Usage:\n"
			" %s [-socket vdesock] [-dhcp] [-daemon] [-network netaddr] \n"
			"\t [-L host_port:guest_addr:guest_port] [-X guest_addr[:display[.screen]]] \n"
			"\t [-x portno:unix_socket_path]\n"
			" %s [-s vdesock] [-D] [-d] [-n netaddr]\n"
			"\t [-L host_port:guest_addr:guest_port] [-X guest_addr[:display[.screen]]] \n" 
			"\t [-x portno:unix_socket_path]\n"
			,name,name);
	exit(-1);
}

int main(int argc, char **argv)
{
	struct stack *stack;
	struct netif *vdenif;
	struct netif *slirpnif;
	char *sockname=NULL;
	int result,nfds;
	register ssize_t nx;
	fd_set rs,ws,xs;
	int opt,longindx;
	int daemonize=0;
	struct redir_tcp_udp *rtcp=NULL;
	struct redirx *rx=NULL;
	struct redirlocx *rlocx=NULL;
	//struct vde_open_args open_args={.port=0,.group=NULL,.mode=0700};
	int quiet=0;
	int dhcpfd;
	struct ip_addr nameserver;

	int i;

	static struct option slirpvdeopts[] = {
		{"socket",required_argument,NULL,'s'},
		{"sock",required_argument,NULL,'s'},
		{"vdesock",required_argument,NULL,'s'},
		{"unix",required_argument,NULL,'s'},
		{"pidfile", required_argument, NULL, 'p'},
		{"dhcp",optional_argument,NULL,'D'},
		{"daemon",no_argument,NULL,'d'},
		{"network",required_argument,NULL,'n'},
		{"nameserver",optional_argument,NULL,'N'},
		{"dns",optional_argument,NULL,'N'},
		{"host",required_argument,NULL,'H'},
		{"mod",required_argument,NULL,'m'},
		{"group",required_argument,NULL,'g'},
		{"port",required_argument,NULL,'P'},
		{"tftp",required_argument,NULL,'t'},
		{"quiet",no_argument,NULL,'q'},
		{"help",no_argument,NULL,'h'},
#ifdef RADV
		{"radvd",optional_argument,NULL,'r'},
		{"radvdrc",optional_argument,NULL,'R'},
#endif
		{NULL,no_argument,NULL,0}};

	vhosts=malloc(sizeof(struct ip_addr));
	lwip_inet_aton(DEFAULT_IP_ADDR,vhosts);
	maskbits=malloc(sizeof(int));
	maskbits[0]=24;

	prog=basename(argv[0]);

	while ((opt=GETOPT_LONG(argc,argv,
					"D::s:n:H:p:g:m:L:U:X:x:t:N::dqh"
#ifdef RADV
					"r::R:"
#endif
					,slirpvdeopts,&longindx)) > 0) {
		switch (opt) {
			case 's' : sockname=optarg;
								 break;
			case 'D' : dhcpmgmt = 1;
								 if (optarg != NULL) {
									 char *slash=strchr(optarg,'/');
									 if (slash) {
										 vdhcp_naddr=atoi(slash+1);
										 *slash=0;
									 }
									 lwip_inet_aton(optarg,&vdhcp_start);
								 }
								 break;
			case 'd' : daemonize = 1;
								 break;
			case 'H' :
			case 'n' : {
									 char *slash=strchr(optarg,'/');
									 vhosts=realloc(vhosts,(nvhosts+1)*sizeof(struct ip_addr));
									 maskbits=realloc(maskbits,(nvhosts+1)*sizeof(int));
									 if (slash) {
										 maskbits[nvhosts]=atoi(slash+1);
										 *slash=0;
									 }
									 lwip_inet_aton(optarg,&vhosts[nvhosts]);
									 nvhosts++;
								 }
								 break;
			case 'N' : dnsforward=1;
								 if (optarg != NULL) {
									 lwip_inet_aton(optarg,&nameserver);
									 vnameserver=&nameserver;
								 }
								 break;
#ifdef RADV
			case 'r' : if (optarg == NULL) 
									 radvd = "";
								 else 
									 radvd = strdup(optarg);
								 break;
			case 'R' : radvdfile = strdup(optarg);
								 break;
#endif
								 /*case 'm' : sscanf(optarg,"%o",(unsigned int *)&(open_args.mode));
									 break;*/
								 /*case 'g' : open_args.group=strdup(optarg);
									 break;*/
			case 'p':  pidfile=strdup(optarg);
								 break;
								 /*case 'P' : open_args.port=atoi(optarg);
									 break;*/
			case 'L': rtcp=parse_redir_tcp(rtcp,optarg,IS_TCP);
								break;
			case 'U': rtcp=parse_redir_tcp(rtcp,optarg,IS_UDP);
								break;
			case 'X': rx=parse_redir_x(rx,optarg);
								break;
			case 'x': rlocx=parse_redir_locx(rlocx,optarg);
								break;
			case 't': tftp_prefix=strdup(optarg);
								break;
			case 'q': quiet=1;
								break;
			default  : usage(prog);
								 break;
		}
	}

	if (nvhosts==0)
		nvhosts=1;

	if (optind < argc && sockname==NULL)
		sockname=argv[optind++];

	if (optind < argc)
		usage(prog);

#ifdef RADV
	if (radvd != NULL && *radvd == 0 && radvdfile == NULL) {
		for (i=0; (i<nvhosts) && (IP_ADDR_IS_V4(&vhosts[i])); i++) 
			;
		if (i<nvhosts) {
			char hostbuf[NAMEINFO_LEN];
			struct ip_addr tmpmask;
			struct ip_addr tmpaddr=vhosts[i];
			lwip_inet_mask(maskbits[i], &tmpaddr, &tmpmask);
			tmpaddr.addr[0] &= tmpmask.addr[0];
			tmpaddr.addr[1] &= tmpmask.addr[1];
			tmpaddr.addr[2] &= tmpmask.addr[2];
			tmpaddr.addr[3] &= tmpmask.addr[3];
			asprintf(&radvd,"%s/%d",lwip_inet_ntoa(&tmpaddr, hostbuf, NAMEINFO_LEN), maskbits[i]);
		} else {
			lprint("router advertisement arg error no IPv6 addr\n");
			exit(-1);
		}
	}
#endif
	if(sockname && sockname[0]=='-' && sockname[1]==0) {
		/* if vdestream on stdin-stdout be quiet and do not
			 daemonize */
		daemonize = 0;
		quiet = 1;
	}
	atexit(cleanup);
	if (daemonize) {
		openlog(basename(prog), LOG_PID, 0);
		logok=1;
		syslog(LOG_INFO,"slirpvde started");
	}
	if(getcwd(pidfile_path, PATH_MAX-1) == NULL) {
		printlog(LOG_ERR, "getcwd: %s", strerror(errno));
		exit(1);
	}

	if(pidfile) save_pidfile();
	if(dhcpmgmt) {
		int i;
		for (i=0; i<nvhosts; i++) {
			if (IP_ADDR_IS_V4(&vhosts[i])) {
				if(memcmp(&vdhcp_start, IP_ADDR_ANY, sizeof(vdhcp_start))==0)
					break;
				else {
					int tmpmask=~((1<<(32-maskbits[i]))-1);
					if ((ntohl(vhosts[i].addr[3]) & tmpmask) == 
							(ntohl(vdhcp_start.addr[3]) & tmpmask))
						break;
				}
			}
		}
		if (i == nvhosts) {
			printlog(LOG_ERR,"DHCP management disabled, incompatible addresses\n");
			dhcpmgmt=0;
		} else {
			dhcphost=&(vhosts[i]);
			dhcpmask=maskbits[i];
			if (dnsforward)
				dhcpnameserver=dhcphost;
			if(memcmp(&vdhcp_start, IP_ADDR_ANY, sizeof(vdhcp_start))==0) {
				memcpy(&vdhcp_start, dhcphost, sizeof(vdhcp_start));
				vdhcp_start.addr[3]=htonl(ntohl(vdhcp_start.addr[3])+14);
			}
		}
	}
	if(dhcpmgmt && vdhcp_naddr==0)
		vdhcp_naddr=10;

	if (daemonize && daemon(0, 0)) {
		printlog(LOG_ERR,"daemon: %s",strerror(errno));
		exit(1);
	}

	if (!quiet) {
		char hostbuf[NAMEINFO_LEN];
		lprint("Starting slirpvde6: virtual_host=%s/%d\n", 
				lwip_inet_ntoa(&vhosts[0], hostbuf, NAMEINFO_LEN), maskbits[0]);
		for (i=1;i<nvhosts;i++)
			lprint("                    virtual_host=%s/%d\n", 
					lwip_inet_ntoa(&vhosts[i], hostbuf, NAMEINFO_LEN), maskbits[i]);
		if (dnsforward) {
			if (vnameserver!=NULL) 
				lprint("                    DNS         =%s\n", 
						lwip_inet_ntoa(vnameserver, hostbuf, NAMEINFO_LEN));
			else {
				struct ip_addr tmpdns;
				get_dns_addr(&tmpdns);
				lprint("                    DNS (host)  =%s\n", 
						lwip_inet_ntoa(&tmpdns, hostbuf, NAMEINFO_LEN));
			}
		}
		if (dhcpmgmt) {
			lprint("                    dhcp_start  =%s nclients %d\n", 
					lwip_inet_ntoa(&vdhcp_start,hostbuf, NAMEINFO_LEN),vdhcp_naddr);
			lprint("                    dhcp_host   =%s\n", 
					lwip_inet_ntoa(dhcphost,hostbuf, NAMEINFO_LEN));
			if (dhcpnameserver!=NULL) 
				lprint("                    dhcp DNS    =%s\n", 
						lwip_inet_ntoa(dhcpnameserver, hostbuf, NAMEINFO_LEN));
			else {
				struct ip_addr tmpdns;
				get_dns_addr(&tmpdns);
				lprint("                    dhcpDNS host=%s\n", 
						lwip_inet_ntoa(&tmpdns, hostbuf, NAMEINFO_LEN));
			}
		}
#ifdef RADV
		if (radvdfile != NULL)
			lprint("                    router adv  = file %s\n", radvdfile);
		else if (radvd != NULL)
			lprint("                    router adv  =%s\n", radvd);
#endif
		if (tftp_prefix != NULL)
			lprint("                    tftp prefix =%s\n", tftp_prefix);
		lprint("                    vde switch  =%s\n", 
				(sockname == NULL)?"*DEFAULT*":sockname);
	}

	if((stack=lwip_stack_new())==NULL){
		lprint("lwipstack not created\n");
		exit(-1);
	}

	lwip_stack_flags_set(stack,LWIP_STACK_FLAG_FORWARDING);

	/* add a vde interface */
#ifdef RADV
	if(radvd != NULL || radvdfile != NULL) {
		if((vdenif=lwip_add_vdeif(stack,sockname,NETIF_FLAG_RADV))==NULL){
			lprint("VDE Interface not loaded\n");
			exit(-1);
		}
	} else
#endif
		if((vdenif=lwip_vdeif_add(stack,sockname))==NULL){
			lprint("VDE Interface not loaded\n");
			exit(-1);
		}

	/* add a slirp interface */
	if((slirpnif=lwip_slirpif_add(stack,NULL))==NULL){
		lprint("SLIRP Interface not loaded\n");
		exit(-1);
	}

	for (i=0; i<nvhosts; i++) {
		struct ip_addr tmpmask;
		lwip_inet_mask(maskbits[i], &vhosts[i], &tmpmask);
		lwip_add_addr(vdenif,&vhosts[i],&tmpmask);
	}

	if(lwip_add_route(stack,IP_ADDR_ANY, IP_ADDR_ANY, IP_ADDR_ANY, slirpnif,0)<0){
		lprint("lwip_add_route err\n");
		exit(-1);
	}

	do_redir_tcp(slirpnif,rtcp,quiet);
	do_redir_x(slirpnif,rx,quiet);
	do_redir_locx(stack,rlocx,quiet);

#ifdef RADV
	if(radvdfile != NULL)
		lwip_radv_load_configfile(stack, radvd+5);
	else if(radvd != NULL) { 
		FILE *memfile;
		char *buf;
		int buflen;
		memfile=open_memstream(&buf, &buflen);
		if (memfile) {
			char *oneprefix,*saveptr;
			char *prefixes=radvd;
			fprintf(memfile,"[vd0]\nAdvSendAdvert = ON\n");
			while((oneprefix=strtok_r(prefixes,",",&saveptr))!= NULL) {
				fprintf(memfile,"AddPrefix = %s\n",oneprefix);
				prefixes=NULL;
			}
		}
		fclose(memfile);
		//printf("=====================\n%s=====================\n",buf);
		memfile=fmemopen(buf,buflen,"r");
		if (memfile)
			lwip_radv_load_config(stack,memfile);
		fclose(memfile);
		free(buf);
	}
#endif

	lwip_ifup(vdenif);
	lwip_ifup(slirpnif);

	if (dhcpmgmt) 
		bootp_init(stack, vdhcp_naddr);
	tftp_init(stack, tftp_prefix);
	if (dnsforward) 
		dns_init(stack, vnameserver);

	while (1) {
		int n,i;
		n=lwip_poll(slirpoll_pfd,slirpoll_npfd,-1);
		for (i=0; n > 0 && i < slirpoll_npfd; i++) {
			if (slirpoll_pfd[i].revents) {
				n--;
				slirpoll_pfd_args[i].fun(slirpoll_pfd[i].fd,slirpoll_pfd_args[i].funarg);
			}
		}
	}
	return(0);
}
