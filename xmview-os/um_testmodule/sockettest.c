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
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <linux/net.h>
#include <string.h>
#include <config.h>
#include "module.h"
#include "libummod.h"
#include "gdebug.h"
#include <asm/ioctls.h>
#include <linux/net.h>
#include <linux/sockios.h>
#include <linux/if.h>


// int read(), write(), close();

static struct service s;
VIEWOS_SERVICE(s)

static long ioctlparms(int fd,int req)
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
		case SIOCGIFTXQLEN:
			return sizeof(struct ifreq) | IOCTL_R | IOCTL_W;
		case SIOCGIFFLAGS:
		case SIOCGIFADDR:
		case SIOCGIFDSTADDR:
		case SIOCGIFBRDADDR:
		case SIOCGIFNETMASK:
		case SIOCGIFMETRIC:
		case SIOCGIFMEM:
		case SIOCGIFMTU:
		case SIOCGIFHWADDR:
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
		case SIOCGIFINDEX:
			return sizeof(struct ifreq) | IOCTL_R;
		default:
			return 0;
	}
}

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
		rv=ioctl(d,request,arg);
		if (rv>=0)
			um_mod_ustoren((long) save,ifc->ifc_len,ifc->ifc_buf);
		free(ifc->ifc_buf);
		ifc->ifc_buf=save;
		return rv;
	}
	return ioctl(d,request,arg);
}

void *viewos_init(char *args)
{
	return ht_tab_add(CHECKSOCKET,NULL,0,&s,NULL,NULL);
}

void viewos_fini(void *data)
{
	struct ht_elem *proc_ht=data;
	ht_tab_del(proc_ht);
}


	static void
	__attribute__ ((constructor))
init (void)
{
	printk(KERN_NOTICE "sockettest init\n");
	s.name="sockettest"; 
	s.description="socket syscalls are executed server side";
	s.ioctlparms=ioctlparms;
	s.syscall=(sysfun *)calloc(scmap_scmapsize,sizeof(sysfun));
	s.socket=(sysfun *)calloc(scmap_sockmapsize,sizeof(sysfun));
	SERVICESOCKET(s, socket, socket);
	SERVICESOCKET(s, bind, bind);
	SERVICESOCKET(s, connect, connect);
	SERVICESOCKET(s, listen, listen);
	SERVICESOCKET(s, accept, accept);
	SERVICESOCKET(s, getsockname, getsockname);
	SERVICESOCKET(s, getpeername, getpeername);
	SERVICESOCKET(s, send, send);
	SERVICESOCKET(s, recv, recv);
	SERVICESOCKET(s, sendto, sendto);
	SERVICESOCKET(s, recvfrom, recvfrom);
	SERVICESOCKET(s, shutdown, shutdown);
	SERVICESOCKET(s, setsockopt, setsockopt);
	SERVICESOCKET(s, getsockopt, getsockopt);
	SERVICESOCKET(s, sendmsg, sendmsg);
	SERVICESOCKET(s, recvmsg, recvmsg);
	SERVICESYSCALL(s, read, read);
	SERVICESYSCALL(s, write, write);
	SERVICESYSCALL(s, close, close);
#ifdef __NR_fcntl64
	SERVICESYSCALL(s, fcntl, fcntl64);
#else
	SERVICESYSCALL(s, fcntl, fcntl);
#endif
	SERVICESYSCALL(s, ioctl, sockioctl);
	SERVICESYSCALL(s, _newselect, select);
	SERVICESYSCALL(s, poll, poll);
}

	static void
	__attribute__ ((destructor))
fini (void)
{
	free(s.syscall);
	free(s.socket);
	printk(KERN_NOTICE "sockettest fini\n");
}
