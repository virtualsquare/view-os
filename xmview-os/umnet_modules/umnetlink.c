/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   UMNETNATIVE: Virtual Native Network
 *    Copyright (C) 2008  Renzo Davoli <renzo@cs.unibo.it>
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
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/net.h>
#include <linux/net.h>
#include <linux/sockios.h>
#include <linux/if.h>

#include "umnet.h"

#define UMNETLINK_OVERRIDE 1
struct umnetlink {
	char *source;
	char *mountpoint;
	char flags;
	char proto[AF_MAXMAX];
};

static int umnetlink_ioctlparms(int fd, int req, struct umnet *nethandle)
{
	switch (req) {
		case FIONREAD:
			return _IOR(0,0,int);
		case FIONBIO:
			return _IOW(0,0,int);
		case SIOCGIFCONF:
			return _IOWR(0,0,struct ifconf);
		case SIOCGSTAMP:
			return _IOR(0,0,struct timeval);
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
			return _IOWR(0,0,struct ifreq);
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
			return _IOW(0,0,struct ifreq);
		default:
			return 0;
	}
}

static int umnetlink_ioctl(int d, int request, void *arg)
{
	if (request == SIOCGIFCONF) {
		int rv;
		void *save;
		struct ifconf *ifc=(struct ifconf *)arg;
		save=ifc->ifc_buf;
		ioctl(d,request,arg);
		ifc->ifc_buf=malloc(ifc->ifc_len);
		um_mod_umoven((long) save,ifc->ifc_len,ifc->ifc_buf);
		rv=ioctl(d,request,arg);
		if (rv>=0)
			um_mod_ustoren((long) save,ifc->ifc_len,ifc->ifc_buf);
		free(ifc->ifc_buf);
		ifc->ifc_buf=save;
		return rv;
	}
	return ioctl(d,request,arg);
}

int umnetlink_msocket (int domain, int type, int protocol,
		struct umnet *nethandle){
	struct umnetlink *umnl=umnet_getprivatedata(nethandle);
	if (domain > 0 && domain <= AF_MAXMAX && umnl->proto[domain])
		return msocket(umnl->source,domain, type, protocol);
	else {
		if (umnl->flags & UMNETLINK_OVERRIDE) 
			return msocket(umnl->mountpoint,domain, type, protocol);
		else
			return msocket(NULL,domain, type, protocol);
	}
}

static uint32_t hash4(char *s) {
	uint32_t result=0;
	uint32_t wrap=0;
	while (*s) {
		wrap = result >> 24;
		result <<= 8;
		result |= (*s ^ wrap);
		s++;
	}
	return result;
}

static void umnetlink_setproto(char *args,char *proto,char *flags)
{
	char *str, *token, *saveptr;
	int i,val=1;
	if (args[0] == '+' || (args[0] == '-' && args[1] == 0)) {
		for (i=0; i<AF_MAXMAX; i++)
			proto[i]=0;
	} else {
		for (i=0; i<AF_MAXMAX; i++)
			proto[i]=1;
	}
	for (str=args;
			(token=strtok_r(str, ",", &saveptr))!=NULL;str=NULL) {
		if (*token=='+' || *token=='-') {
			val=(*token=='+')?1:0;
			token++;
		}
		switch (hash4(token)) {
			case 0x00000000:
			case 0x00616c6c: for (i=0; i<AF_MAXMAX; i++)
												 proto[AF_UNIX]=val;
											 break;
			case 0x00000075:
			case 0x756e6978: proto[AF_UNIX]=val; break;
			case 0x00000034:
			case 0x69707634: proto[AF_INET]=val; break;
			case 0x00000036:
			case 0x69707636: proto[AF_INET6]=val; break;
			case 0x0000006e:
			case 0x6c070b1f: proto[AF_NETLINK]=val; break;
			case 0x00000070:
			case 0x636b1515: proto[AF_PACKET]=val; break;
			case 0x00000062:
			case 0x031a117e: proto[AF_BLUETOOTH]=val; break;
			case 0x00000069:
			case 0x69726461: proto[AF_IRDA]=val; break;
			case 0x00006970: proto[AF_INET]=val;
											 proto[AF_INET6]=val;
											 proto[AF_NETLINK]=val;
											 proto[AF_PACKET]=val;
											 break;
			case 0x0000006f:
			case 0x1d1f0117: *flags |= UMNETLINK_OVERRIDE;
											 break;
			default: if (*token == '#' || *token == 'f') {
								 int family=atoi(token+1);
								 if (family > 0 && family < AF_MAXMAX)
									 proto[family]=val;
								 else
									 printk("umnetlink: unknown protocol \"%s\"\n",token);
							 } else
								 printk("umnetlink: unknown protocol \"%s\"\n",token);
							 break;
		}
	}
}

int umnetlink_init (char *source, char *mountpoint, unsigned long flags, char *args, struct umnet *nethandle) {
	if (source != NULL) {
		struct umnetlink *umnl=calloc(1,sizeof(struct umnetlink));
		umnl->source=strdup(source);
		umnl->mountpoint=strdup(mountpoint);
		umnet_setprivatedata(nethandle,umnl);
		if (args) 
			umnetlink_setproto(args,umnl->proto,&(umnl->flags));
		else {
			int i;
			for (i=0;i<AF_MAXMAX;i++)
				umnl->proto[i]=1;
		}
		return 0;
	}
	else
		return -1;
}

int umnetlink_fini (struct umnet *nethandle){
	struct umnetlink *umnl=umnet_getprivatedata(nethandle);
	free(umnl->source);
	free(umnl->mountpoint);
	free(umnl);
	return 0;
}

int um_mod_event_subscribe(void (* cb)(), void *arg, int fd, int how);

struct umnet_operations umnet_ops={
	.msocket=umnetlink_msocket,
	.bind=bind,
	.connect=connect,
	.listen=listen,
	.accept=accept,
	.getsockname=getsockname,
	.getpeername=getpeername,
	.send=send,
	.sendto=sendto,
	.recvfrom=recvfrom,
	.sendmsg=sendmsg,
	.recvmsg=recvmsg,
	.getsockopt=getsockopt,
	.setsockopt=setsockopt,
	.shutdown=shutdown,
	.read=read,
	.write=write,
	.ioctl=umnetlink_ioctl,
	.close=close,
	.ioctlparms=umnetlink_ioctlparms,
	.init=umnetlink_init,
	.fini=umnetlink_fini,
	.event_subscribe=um_mod_event_subscribe
};

