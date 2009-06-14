/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   example of um-ViewOS module
 *   
 *   Copyright 2005 Renzo Davoli University of Bologna - Italy
 *   
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License, version 2, as
 *   published by the Free Software Foundation.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA.
 *
 *   $Id$
 *
 */   
#include <dlfcn.h>
#include "module.h"
#include <lwipv6.h>
#include <linux/net.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <limits.h>
#include <string.h>
#include "asm/unistd.h"
#include <sys/ioctl.h>
#include <asm/ioctls.h>
#include <linux/net.h>
#include <linux/sockios.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <poll.h>
#include <config.h>

#define UMLWIPV6_SERVICE_CODE 0x02

static struct service s;
static struct timestamp ts;

static int alwaysfalse()
{
	return 0;
}

static int alwaystrue(char *path)
{
	return 1;
}

static sysfun real_lwip_ioctl;
static int sockioctl(int d, int request, void *arg)
{
	if (request == SIOCGIFCONF) {
		int rv;
		void *save;
		struct ifconf *ifc=(struct ifconf *)arg;
		save=ifc->ifc_buf;
		ioctl(d,request,arg);
		ifc->ifc_buf=malloc(ifc->ifc_len);
		um_mod_umoven((long) save,ifc->ifc_len,ifc->ifc_buf);
		rv=real_lwip_ioctl(d,request,arg);
		if (rv>=0)
			um_mod_ustoren((long) save,ifc->ifc_len,ifc->ifc_buf);
		free(ifc->ifc_buf);
		ifc->ifc_buf=save;
		return rv;
	}
	return real_lwip_ioctl(d,request,arg);
}

static int ioctlparms(struct ioctl_len_req *arg)
{
	switch (arg->req) {
		case FIONREAD:
			return sizeof(int) | IOCTL_W;
		case FIONBIO:
			return sizeof(int) | IOCTL_R;
		case SIOCGIFCONF:
			return sizeof(struct ifconf) | IOCTL_R | IOCTL_W;
		case SIOCGSTAMP:
			return sizeof(struct timeval) | IOCTL_W;
		case SIOCGIFTXQLEN:
		case SIOCGIFFLAGS:
		case SIOCGIFADDR:
		case SIOCGIFDSTADDR:
		case SIOCGIFBRDADDR:
		case SIOCGIFNETMASK:
		case SIOCGIFMETRIC:
		case SIOCGIFMEM:
		case SIOCGIFMTU:
		case SIOCGIFHWADDR:
		case SIOCGIFINDEX:
			return sizeof(struct ifreq) | IOCTL_R | IOCTL_W;
		case SIOCSIFFLAGS:
		case SIOCSIFADDR:
		case SIOCSIFDSTADDR:
		case SIOCSIFBRDADDR:
		case SIOCSIFNETMASK:
		case SIOCSIFMETRIC:
		case SIOCSIFMEM:
		case SIOCSIFMTU:
		case SIOCSIFHWADDR:
			return sizeof(struct ifreq) | IOCTL_R;
		default:
			return 0;
	}
}

#define TRUE 1
#define FALSE 0

static epoch_t checksock(int type, void *arg)
{
	epoch_t e=0;
	if ((e=tst_matchingepoch(&ts)) == 0)
		return 0;
	if (type == CHECKSOCKET) {
		int domain=*((int *) arg);
		return (domain == AF_INET || domain == PF_INET6 || domain == PF_NETLINK || domain == PF_PACKET)?e:0;
	} else if (type == CHECKIOCTLPARMS) {
		//printf("=========lwipv6 %x ioctlparms %x\n",*((int *)arg),ioctlparms(arg));
		return ioctlparms(arg);
	} else if (type == CHECKPATH) {
		char *path=arg;
		return (strncmp(path,"/proc/net",9) == 0)?e:0;
	}
	else
		return FALSE;
}

static int noprocnetdev()
{
	errno=ENOENT;
	return -1;
}



typedef long (*longfun)();
#define LWIPSOCKET(X,Y) s.socket[(X)]=(longfun)lwip_##Y
#define LWIPSYSCALL(X,Y) s.syscall[uscno(X)]=(longfun)lwip_##Y
static void *lwiphandle;
static struct stack *lwipstack;

typedef struct stack * (* pstackfun)();
typedef void (*voidfun)();

static void openlwiplib()
{
	int i;
	sysfun fun;
	lwipstack=lwip_stack_new();
	lwip_stack_set(lwipstack);
	LWIPSOCKET(SYS_SOCKET, 	socket);
	LWIPSOCKET(SYS_BIND,	bind);
	LWIPSOCKET(SYS_CONNECT,	connect);
	LWIPSOCKET(SYS_LISTEN,	listen);
	LWIPSOCKET(SYS_ACCEPT,	accept);
	LWIPSOCKET(SYS_GETSOCKNAME,	getsockname);
	LWIPSOCKET(SYS_GETPEERNAME,	getpeername);
	LWIPSOCKET(SYS_SEND,	send);
	LWIPSOCKET(SYS_RECV,	recv);
	LWIPSOCKET(SYS_SENDTO,	sendto);
	LWIPSOCKET(SYS_RECVFROM,	recvfrom);
	LWIPSOCKET(SYS_SHUTDOWN,	shutdown);
	LWIPSOCKET(SYS_SETSOCKOPT,	setsockopt);
	LWIPSOCKET(SYS_GETSOCKOPT,	getsockopt);
	LWIPSOCKET(SYS_SENDMSG,	sendmsg);
	LWIPSOCKET(SYS_RECVMSG,	recvmsg);
	LWIPSYSCALL(__NR_read,	read);
	LWIPSYSCALL(__NR_write,	write);
	LWIPSYSCALL(__NR_close,	close);
	/*LWIPSYSCALL(__NR_fcntl,	fcntl);*/
	/*LWIPSYSCALL(__NR_fcntl64,	fcntl64);*/
	LWIPSYSCALL(__NR_ioctl,	ioctl);
	s.event_subscribe=(longfun)lwip_event_subscribe;
	real_lwip_ioctl=s.syscall[uscno(__NR_ioctl)];
	SERVICESYSCALL(s, ioctl, sockioctl);
	SERVICESYSCALL(s, open, noprocnetdev);
	SERVICESYSCALL(s, lstat64, noprocnetdev);
	SERVICESYSCALL(s, access, noprocnetdev);
}

static void closelwiplib()
{
	if (lwiphandle!=NULL) {
		if (lwipstack != NULL) 
			lwip_stack_free(lwipstack);
		dlclose(lwiphandle);
	}
}

#if 0
long llwip_recvmsg(int fd, struct msghdr *msg, int flags) {
	int rv;
	rv=(s.socket[SYS_RECVFROM])(fd,msg->msg_iov->iov_base,msg->msg_iov->iov_len,flags,
			msg->msg_name,&msg->msg_namelen);
	msg->msg_controllen=0;
	return rv;
}

long llwip_sendmsg(int fd, const struct msghdr *msg, int flags) {
	int rv;
	rv=(s.socket[SYS_SENDTO])(fd,msg->msg_iov->iov_base,msg->msg_iov->iov_len,flags,
			msg->msg_name,msg->msg_namelen);
	return rv;
}
#endif

static char *intname[]={"vd","tp","tn"};
#define INTTYPES (sizeof(intname)/sizeof(char *))
typedef struct netif *((*netifstarfun)());
static netifstarfun initfun[INTTYPES]={lwip_vdeif_add,lwip_tapif_add,lwip_tunif_add};
static char intnum[INTTYPES];
struct ifname {
	unsigned char type;
	unsigned char num;
	char *name;
	struct ifname *next;
} *ifh;

/* Other parameters */
static char *paramname[]={"ra"};
#define PARAMTYPES (sizeof(paramname)/sizeof(char *))
typedef int *((*paramstarfun)(struct stack *stack,char *opt));
static paramstarfun paramfun[PARAMTYPES]={(paramstarfun)lwip_radv_load_configfile}; /* parameter handler */
static char        *paramval[PARAMTYPES]; /* parameter value */

static void iffree(struct ifname *head)
{
	if (head==NULL)
		return;
	else {
		iffree(head->next);
		free(head->name);
		free(head);
	}
}

static char *ifname(struct ifname *head,unsigned char type,unsigned char num)
{
	if (head==NULL)
		return NULL;
	else if (head->type == type && head->num == num)
		return head->name;
	else return ifname(head->next,type,num);
}

static void ifaddname(char type,char num,char *name)
{
	struct ifname *thisif=malloc(sizeof (struct ifname));
	if (thisif != NULL) {
		thisif->type=type;
		thisif->num=num;
		thisif->name=strdup(name);
		thisif->next=ifh;
		ifh=thisif;
	}
}

static void myputenv(char *arg)
{
	int i,j;
	for (i=0;i<INTTYPES;i++) {
		if (strncmp(arg,intname[i],2)==0 && arg[2] >= '0' && arg[2] <= '9') {
			if (arg[3] == '=') {
				ifaddname(i,arg[2]-'0',arg+4);
				if (arg[2]-'0'+1 > intnum[i]) intnum[i]=arg[2]-'0'+1;
			}
			else if (arg[3] == 0) {
				if (arg[2]-'0' > intnum[i]) intnum[i]=arg[2]-'0';
			}
			break;
		}
	}	

	for (i=0;i<PARAMTYPES;i++) {
		if (strncmp(arg,paramname[i],2)==0) {
			if (arg[2] == '=') {
				paramval[i]=arg+3;
			}
		}
	}
}

static char stdargs[]="vd1";
static void lwipargtoenv(char *initargs)
{
	char *next;
	char *unquoted;
	char quoted=0;
	char totint=0;
	register int i,j;

	ifh=NULL;

	if (*initargs == 0) initargs=stdargs;
	while (*initargs != 0) {
		next=initargs;
		unquoted=initargs;
		while ((*next != ',' || quoted) && *next != 0) {
			*unquoted=*next;
			if (*next == quoted)
				quoted=0;
			else if (*next == '\'' || *next == '\"')
				quoted=*next; 
			else
				unquoted++;
			next++;
		}
		if (*next == ',') {
			*unquoted=*next=0;
			next++;
		}
		if (*initargs != 0)
			myputenv(initargs);
		initargs=next;
	}

	/* load interfaces */
	for (i=0;i<INTTYPES;i++) 
		totint+=intnum[i];
	if (totint==0)
		intnum[0]=1;
	for (i=0;i<INTTYPES;i++)
		for (j=0;j<intnum[i];j++)
			if (initfun[i] != NULL) {
				initfun[i](lwipstack,ifname(ifh,i,j));
			}
	iffree(ifh);

	/* load other parameters */
	for (i=0;i<PARAMTYPES;i++)
		if (paramval[i] != NULL)
			if (paramfun[i] != NULL) {
				paramfun[i](lwipstack,paramval[i]);
			}

}

static int initflag=0;
	static void
	__attribute__ ((constructor))
init (void)
{
	initflag=1;
}

void _um_mod_init(char *initargs)
{
	if (initflag) {
		fprint2("lwipv6 init\n");
		s.name="light weight ipv6 stack";
		s.code=UMLWIPV6_SERVICE_CODE;
		s.checkfun=checksock;
		s.syscall=(sysfun *)calloc(scmap_scmapsize, sizeof(sysfun));
		s.socket=(sysfun *)calloc(scmap_sockmapsize, sizeof(sysfun));
		openlwiplib();
		lwipargtoenv(initargs);
		SERVICESYSCALL(s, _newselect, alwaysfalse);
		SERVICESYSCALL(s, poll, alwaysfalse);
		//s.socket[SYS_SENDMSG]=llwip_sendmsg;
		//s.socket[SYS_RECVMSG]=llwip_recvmsg;

		add_service(&s);
		initflag=0;
		ts=tst_timestamp();
	}
}

	static void
	__attribute__ ((destructor))
fini (void)
{
	closelwiplib;
	free(s.syscall);
	free(s.socket);
	fprint2("lwipv6 fini\n");
}
