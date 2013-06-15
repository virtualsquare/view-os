/*   
 *   otipweb.c: One Time IP Virtual Web appliance
 *   
 *   Copyright 2012 Renzo Davoli - Virtual Square Team 
 *   University of Bologna - Italy
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
 *
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stddef.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <lwipv6.h>
#include <time.h>
#include <dirent.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <mhash.h>
#include <syslog.h>
#include <getopt.h>
#include <stdarg.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <net/if.h>

#ifndef LWIP_STACK_FLAG_NO_ECHO
#define LWIP_STACK_FLAG_NO_ECHO 0
#endif

#define BUFSIZE 10240

static int logok=0;
static int daemonize; // daemon mode
static int verbose;
static int noecho;
static char *pidfile;
static char pidfile_path[PATH_MAX];
static char *switch_path;
static char *progname;
void printlog(int priority, const char *format, ...);

volatile int exclusion = 0;

void lock() {
	while (__sync_lock_test_and_set(&exclusion, 1)) {
		// Do nothing. This GCC builtin instruction
		// ensures memory barrier.
		sched_yield();
	}
}

void unlock() {
	__sync_synchronize(); // Memory barrier.
	exclusion = 0;
}

static char *html="Content-Type: text/html\r\n";

static char *okmsg= 
"HTTP/1.1 200 OK\r\n"
"%s"
"Content-Length: %d\r\n\r\n";

static char *messagein= "<HTML>\n<HEAD>\n<TITLE>APPLIANCE</TITLE>\n</HEAD>\n<BODY>\n<H1>%s</H1>\n";
static char *messageout= "</BODY>\n</HTML>\n\n";

void webnas_sendfile(int fd, char *path)
{
	char buf[BUFSIZE];
	int infd=open(path,O_RDONLY);
	if (infd > 0) {
		int n;
		char *header;
		struct stat statbuf;
		fstat(infd,&statbuf);
		if (strlen(path)>5 && strcmp(&path[strlen(path)-5],".html") == 0)
			asprintf(&header,okmsg,html,statbuf.st_size);
		else
			asprintf(&header,okmsg,"",statbuf.st_size);
		lwip_write(fd,header,strlen(header));
		free(header);
		while ((n=read(infd,buf,BUFSIZE))>0) {
			lwip_write(fd,buf,n);
		}
		close(infd);
	}
}

void webnas_senddir(int fd, char *path, char *webpath, struct ip_addr *addr)
{ 
	int i,n;
	char *msg,*header,*lastslash;
	struct dirent **namelist;
	size_t size;
	FILE *f=open_memstream(&msg,&size);
	fprintf(f,messagein,(*webpath)?webpath:"/ (root)");
	fprintf(f,"<h3>current address %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x</h3>\r\n",
			addr->addr[0]&0xff, (addr->addr[0]>>8)&0xff, (addr->addr[0]>>16)&0xff, (addr->addr[0])>>24, 
			addr->addr[1]&0xff, (addr->addr[1]>>8)&0xff, (addr->addr[1]>>16)&0xff, (addr->addr[1])>>24, 
			addr->addr[2]&0xff, (addr->addr[2]>>8)&0xff, (addr->addr[2]>>16)&0xff, (addr->addr[2])>>24, 
			addr->addr[3]&0xff, (addr->addr[3]>>8)&0xff, (addr->addr[3]>>16)&0xff, (addr->addr[3])>>24);

	if (path == webpath) {
		lastslash=strrchr(webpath,'/');
		if (lastslash) {
			*lastslash=0;
			fprintf(f,"<p><a href=\"/%s\"> .. </a></p>\n",webpath);
			*lastslash='/';
		} else
			fprintf(f,"<p><a href=\"/\"> .. </a></p>\n");
	}
	n=scandir(path, &namelist, NULL, alphasort);
	for (i=0; i<n;i++) {
		if (namelist[i]->d_name[0] != '.') 
			fprintf(f,"<p><a href=\"%s/%s\"> %s </a></p>\n",
					webpath,namelist[i]->d_name,namelist[i]->d_name);
	}
	fprintf(f,"%s",messageout);
	fclose(f);
	asprintf(&header,okmsg,html,size);
	lwip_write(fd,header,strlen(header));
	lwip_write(fd,msg,size);
	free(header);
	free(msg);
	free(namelist);
}

struct handlearg {
	int fd;
	int *counter;
	struct ip_addr *addr;
};

void handle(void *arg)
{
	char buf[BUFSIZE];
	struct handlearg *ha = arg;
	int fd = ha->fd;
	char *end;
	int n;
	if (verbose)
		printlog(LOG_DEBUG,"NEW CONN");
	n=lwip_read(fd,buf,BUFSIZE);
	if (n==0) goto close;
	if (strncmp(buf,"GET /",5)==0 && (end=strchr(buf+4,' ')) != NULL){
		struct stat sbuf;
		*end=0;
		if (buf[5]==0)
			webnas_senddir(fd,".",buf+5,ha->addr);
		else if (strstr(buf+4,"/../") == NULL && stat(buf+5,&sbuf)==0) {
			if (S_ISREG(sbuf.st_mode))
				webnas_sendfile(fd,buf+5);
			if (S_ISDIR(sbuf.st_mode))
				webnas_senddir(fd,buf+5,buf+5,ha->addr);
		}
	}
close:
	lwip_close(fd);
	lock();
	(*(ha->counter))--;
	if (verbose)
		printlog(LOG_DEBUG,"CLOSED %d",(*(ha->counter)));
	unlock();
	free(ha);
}

void nowaddr(struct ip_addr *addr, char *pwd, time_t now)
{
	char *s;
	MHASH td;
	unsigned char out[mhash_get_block_size(MHASH_MD5)];
	int len=asprintf(&s,"%d %s",now >> 6,pwd);
	td=mhash_init(MHASH_MD5);
	mhash(td, s, len);
	mhash_deinit(td, out);
	free(s);
	addr->addr[2] ^= htonl(
			((out[0] ^ out[8]) << 24) |
			((out[1] ^ out[9]) << 16) |
			((out[2] ^ out[10]) << 8) |
			(out[3] ^ out[11]));
	addr->addr[3] ^= htonl(
			((out[4] ^ out[12]) << 24) |
			((out[5] ^ out[13]) << 16) |
			((out[6] ^ out[14]) << 8) |
			(out[7] ^ out[15]));
	if (verbose)
		printlog(LOG_DEBUG,"%x:%x:%x:%x:%x:%x:%x:%x",
				ntohl(addr->addr[0]) >> 16, ntohl(addr->addr[0]) & 0xffff,
				ntohl(addr->addr[1]) >> 16, ntohl(addr->addr[1]) & 0xffff,
				ntohl(addr->addr[2]) >> 16, ntohl(addr->addr[2]) & 0xffff,
				ntohl(addr->addr[3]) >> 16, ntohl(addr->addr[3]) & 0xffff);
}

struct stacklist {
	struct stack *stack;
	struct netif *netif;
	int server;
	time_t starttime;
	int activeclients;
	struct ip_addr addr;
	struct stacklist *next;
} *headst = NULL;

struct stacklist *recclose(struct stacklist *st, time_t now)
{
	if (st == NULL) 
		return NULL;
	else {
		//printf("%p %d:%d - ",st->stack,st->server,st->activeclients);
		if (now - st->starttime >= 128) {
			if (st->server >= 0) {
				lwip_close(st->server);
				st->server = -1;
			}
			int activeclients;
			lock();
			activeclients = st->activeclients;
			unlock();
			if (activeclients == 0) {
				struct stacklist *next = st->next;
				lwip_del_stack(st->stack);
				free(st);
				return recclose(next, now);
			} 
		} 
		st->next=recclose(st->next, now);
		return st;
	} 
}

void usage(void)
{
	fprintf(stderr,"Usage: %s OPTIONS base_addr pwd [switch]\n"
			"\t--help|-h\n"
			"\t--daemon|-d\n"
			"\t--pidfile pidfile\n"
			"\t--verbose|-v\n",
			"\t--noecho|-n\n",
			progname);
	exit(1);
}

void printlog(int priority, const char *format, ...)
{
	va_list arg;

	va_start (arg, format);

	if (logok)
		vsyslog(priority,format,arg);
	else {
		fprintf(stderr,"%s: ",progname);
		vfprintf(stderr,format,arg);
		fprintf(stderr,"\n");
	}
	va_end (arg);
}

static void save_pidfile()
{
	if(pidfile[0] != '/')
		strncat(pidfile_path, pidfile, PATH_MAX - strlen(pidfile_path));
	else
		strcpy(pidfile_path, pidfile);

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

int main(int argc, char *argv[])
{
	struct ip_addr baseaddr,addr;
	struct ip_addr mask;
	int ip1,ip2,ip3,ip4,maskbit;
	char *pwd;
	time_t now;
	time_t laststack=0;
	struct sockaddr_in6 serv_addr;
	struct pollfd pfd[2];
#define PIDFILEARG 131
	static struct option long_options[] = {
		{"help",0 , 0, 'h'},
		{"daemon",0 , 0, 'd'},
		{"pidfile", 1, 0, PIDFILEARG},
		{"verbose",0 , 0, 'v'},
		{"noecho",0 , 0, 'n'},
		{"switch",1 , 0, 's'},
		{"sock",1 , 0, 's'},
		{0,0,0,0}
	};
	int option_index;
	progname=argv[0];
	while(1) {
		int c;
		c = getopt_long (argc, argv, "hdvns:",
				long_options, &option_index);
		if (c<0)
			break;
		switch (c) {
			case 'h':
				usage();
				break;
			case 'd':
				daemonize=1;
				break;
			case 'v':
				verbose=1;
				break;
			case 'n':
				noecho=1;
				break;
			case 's':
				switch_path=strdup(optarg);
				break;
			case PIDFILEARG:
				pidfile=strdup(optarg);
				break;
			default:
				usage();
				break;
		}
	}

	if (argc-optind == 3 && switch_path==NULL) {
		switch_path=strdup(argv[optind+2]);
		argc--;
	}
	if (argc-optind != 2)
		usage();

	if (daemonize) {
		openlog(basename(progname), LOG_PID, 0);
		logok=1;
		syslog(LOG_INFO,"%s started",progname);
	}
	/* saves current path in pidfile_path, because otherwise with daemonize() we
	 * forget it */
	if(getcwd(pidfile_path, PATH_MAX-1) == NULL) {
		printlog(LOG_ERR, "getcwd: %s", strerror(errno));
		exit(1);
	}
	strcat(pidfile_path, "/");
	if (daemonize && daemon(0, 0)) {
		printlog(LOG_ERR,"daemon: %s",strerror(errno));
		exit(1);
	}

	/* once here, we're sure we're the true process which will continue as a
	 * server: save PID file if needed */
	if(pidfile) save_pidfile();
	pfd[0].events = POLLIN;
	pfd[1].events = POLLIN;
	pwd=argv[optind+1];

	maskbit=64;

	struct addrinfo *res;
	static struct addrinfo hints={.ai_family=AF_INET6};
	int gaierr;
	if ((gaierr=getaddrinfo(argv[optind],NULL,&hints,&res))!=0) {
		printlog(LOG_ERR,"prefix: %s",gai_strerror(gaierr));
		exit(1);
	}

	struct sockaddr_in6 *sock6=(struct sockaddr_in6 *)res->ai_addr;
	memcpy(&baseaddr,&(sock6->sin6_addr),sizeof(baseaddr));
	freeaddrinfo(res);

	IP6_ADDR(&mask,0xffff,0xffff,0xffff,0xffff,0,0,0,0);
	memset((char *) &serv_addr,0,sizeof(serv_addr));
	serv_addr.sin6_family      = AF_INET6;
	serv_addr.sin6_addr        = in6addr_any;
	serv_addr.sin6_port        = htons(80);

	time(&now);
	while (1) {
		int n;
		recclose(headst,now);
		//printf("\n");
		if ((now >> 6) > laststack) {
			struct stacklist *new;
			struct ifreq ifr;
			int fd;

			new = malloc(sizeof(struct stacklist));
			new->starttime = now;
			new->activeclients = 0;
			new->stack = lwip_add_stack(noecho?LWIP_STACK_FLAG_NO_ECHO:0); 
			new->netif = lwip_add_vdeif(new->stack, switch_path, NETIF_STD_FLAGS);
			memcpy(&addr,&baseaddr,sizeof(addr));
			nowaddr(&addr,pwd,now);
			fd= lwip_msocket(new->stack,AF_INET, SOCK_DGRAM, 0);
			memcpy(ifr.ifr_hwaddr.sa_data,&addr.addr[2],6);
			strncpy(ifr.ifr_name, "vd0", IFNAMSIZ-1);
			ifr.ifr_hwaddr.sa_data[0] = (ifr.ifr_hwaddr.sa_data[0] & 0xfc) | 0x2;
			lwip_ioctl(fd, SIOCSIFHWADDR, &ifr);
			lwip_close(fd);
			lwip_ifup_flags(new->netif, 1);
			lwip_add_addr(new->netif,&addr,&mask);
			new->server = lwip_msocket(new->stack, AF_INET6, SOCK_STREAM, 0);
			lwip_bind(new->server, (struct sockaddr *)(&serv_addr),sizeof(serv_addr));
			lwip_listen(new->server, 10);
			new->addr = addr;
			new->next = headst;
			headst = new;
			laststack = now >> 6;
		}
		pfd[0].fd=headst->server;
		if (headst->next && headst->next->server >= 0) {
			pfd[1].fd=headst->next->server;
			n=2;
		} else
			n=1;
		pfd[0].revents=0;
		pfd[1].revents=0;
		int q=lwip_poll(pfd,n,1000);
		//printf("n%d %d %d-%d %d-%d\n",n,q,pfd[0].fd,pfd[0].revents,pfd[1].fd,pfd[1].revents);
		if (pfd[0].revents) {
			int connected = lwip_accept(pfd[0].fd, NULL, NULL);
			lock();
			headst->activeclients++;
			unlock();
			if (verbose)
				printlog(LOG_DEBUG,"lwip_thread_new %d %d %d",pfd[0].fd,connected,headst->activeclients);
			struct handlearg *ha = malloc(sizeof(struct handlearg));
			ha->fd = connected;
			ha->counter = &(headst->activeclients);
			ha->addr = &(headst->addr);
			lwip_thread_new(handle,(void *)ha);
		}
		if (n>1 && pfd[1].revents) {
			int connected = lwip_accept(pfd[1].fd, NULL, NULL);
			lock();
			headst->next->activeclients ++;
			unlock();
			struct handlearg *ha = malloc(sizeof(struct handlearg));
			ha->fd = connected;
			ha->counter = &(headst->next->activeclients);
			ha->addr = &(headst->next->addr);
			lwip_thread_new(handle,(void *)ha);
		}
		time(&now);
		now+=0x20;
	}
}

