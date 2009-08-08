/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   UMNETLWIPV6: UMNET - LWIPV6 gateway
 *   (using the standard IBM-PC partition scheme based on MBR/Extended MBR)
 *
 *    Copyright (C) 2008  Renzo Davoli <renzo@cs.unibo.it>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; version 2 of the License
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
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/net.h>
#include <linux/net.h>
#include <linux/sockios.h>
#include <linux/if.h>
#include <dlfcn.h>
#include <lwipv6.h>
#include "umnet.h"

static int umnetlwipv6_ioctlparms(int fd, int req, struct umnet *nethandle)
{
	switch (req) {
		case FIONREAD:
			return sizeof(int) | IOCTL_W;
		case FIONBIO:
			return sizeof(int) | IOCTL_R;
		case SIOCGIFCONF:
			return sizeof(struct ifconf) | IOCTL_R | IOCTL_W;
		case SIOCGSTAMP:
			return sizeof(struct timeval) | IOCTL_W;
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
		case SIOCGIFTXQLEN:
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
		case SIOCSIFTXQLEN:
			return sizeof(struct ifreq) | IOCTL_R;
		default:
			return 0;
	}
}

static int umnetlwipv6_ioctl(int d, int request, void *arg)
{
	if (request == SIOCGIFCONF) {
		int rv;
		void *save;
		struct ifconf *ifc=(struct ifconf *)arg;
		save=ifc->ifc_buf;
		ioctl(d,request,arg);
		ifc->ifc_buf=malloc(ifc->ifc_len);
		um_mod_umoven((long) save,ifc->ifc_len,ifc->ifc_buf);
		rv=lwip_ioctl(d,request,arg);
		if (rv>=0)
			um_mod_ustoren((long) save,ifc->ifc_len,ifc->ifc_buf);
		free(ifc->ifc_buf);
		ifc->ifc_buf=save;
		return rv;
	}
	return lwip_ioctl(d,request,arg);
}

static int umnetlwipv6_msocket (int domain, int type, int protocol,
		struct umnet *nethandle){
	struct stack *s=(struct stack *)umnet_getprivatedata(nethandle);
	return lwip_msocket(s,domain, type, protocol);
}

static char *intname[]={"vd","tn","tp"};
#define INTTYPES (sizeof(intname)/sizeof(char *))
static char *paramname[]={"ra"};
#define PARAMTYPES (sizeof(paramname)/sizeof(char *))

struct ifname {
	unsigned char type;
	unsigned char num;
	char *name;
	struct ifname *next;
};

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

static void ifaddname(struct ifname **head,char type,char num,char *name)
{
	struct ifname *thisif=malloc(sizeof (struct ifname));
	if (thisif != NULL) {
		thisif->type=type;
		thisif->num=num;
		thisif->name=strdup(name);
		thisif->next=*head;
		*head=thisif;
	}
}

static void myputenv(struct ifname **head, int *intnum, char *paramval[], char *arg)
{
	int i,j;
	for (i=0;i<INTTYPES;i++) {
		if (strncmp(arg,intname[i],2)==0 && arg[2] >= '0' && arg[2] <= '9') {
			if (arg[3] == '=') {
				ifaddname(head, i,arg[2]-'0',arg+4);
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
static void lwipargtoenv(struct stack *s,char *initargs)
{
	char *next;
	char *unquoted;
	char quoted=0;
	char totint=0;
	register int i,j;
	struct ifname *ifh=NULL;
	int intnum[INTTYPES];
	char *paramval[PARAMTYPES];

	memset(intnum,0,sizeof(intnum));
	memset(paramval,0,sizeof(paramval));

	if (initargs==0 || *initargs == 0) initargs=stdargs;
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
			myputenv(&ifh,intnum,paramval,initargs);
		initargs=next;
	}
	/* load interfaces */
	for (i=0;i<INTTYPES;i++)
		totint+=intnum[i];
	if (totint==0)
		intnum[0]=1;
	for (j=0;j<intnum[0];j++)
		lwip_vdeif_add(s,ifname(ifh,0,j));
	for (j=0;j<intnum[1];j++)
		lwip_tunif_add(s,ifname(ifh,1,j));
	for (j=0;j<intnum[2];j++)
		lwip_tapif_add(s,ifname(ifh,2,j));
	iffree(ifh);

	if (paramval[0] != NULL)
		lwip_radv_load_configfile(s,paramval[0]);
}


int umnetlwipv6_init (char *source, char *mountpoint, unsigned long flags, char *args, struct umnet *nethandle) {
	struct stack *s=lwip_stack_new();
	if (s) {
		lwipargtoenv(s,args);
		umnet_setprivatedata(nethandle,s);
		return 0;
	} else {
		errno=EFAULT;
		return -1;
	}
}

int umnetlwipv6_fini (struct umnet *nethandle){
	lwip_stack_free(umnet_getprivatedata(nethandle));
	return 0;
}

#if 0
int umnetlwipv6_event_subscribe(voidfun cb, void *arg, int fd, int how)
{
	//printk("umnetlwipv6_event_subscribe %d %d\n",fd,how);
	return lwip_event_subscribe(cb,arg,fd,how);
}
#endif

int umnetlwipv6_supported_domain(int domain)
{
	switch(domain) {
		case AF_INET:
		case PF_INET6:
		case PF_NETLINK:
		case PF_PACKET:
			return 1;
		default:
			return 0;
	}
}


struct umnet_operations umnet_ops={
	.msocket=umnetlwipv6_msocket,
	.ioctl=umnetlwipv6_ioctl,
	.ioctlparms=umnetlwipv6_ioctlparms,
	.init=umnetlwipv6_init,
	.fini=umnetlwipv6_fini,
	.supported_domain=umnetlwipv6_supported_domain
};

typedef int (*intfun)();
#define UMNETLWIPV6(X) umnet_ops.X=(intfun)lwip_##X

	static void
	__attribute__ ((constructor))
init (void)
{
	/*printk("umnetlwipv6 constructor\n");*/
	UMNETLWIPV6(bind);
	UMNETLWIPV6(connect);
	UMNETLWIPV6(listen);
	UMNETLWIPV6(accept);
	UMNETLWIPV6(getsockname);
	UMNETLWIPV6(getpeername);
	UMNETLWIPV6(send);
	UMNETLWIPV6(recv);
	UMNETLWIPV6(sendto);
	UMNETLWIPV6(recvfrom);
	//UMNETLWIPV6(shutdown);
	UMNETLWIPV6(getsockopt);
	UMNETLWIPV6(setsockopt);
	UMNETLWIPV6(read);
	UMNETLWIPV6(write);
	UMNETLWIPV6(close);
	UMNETLWIPV6(event_subscribe);
}

	static void
	__attribute__ ((destructor))
fini (void)
{
	/*printk("umnetlwipv6 destructor\n");*/
}
