/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   um_ioctl: ioctl mgmt
 *   
 *   Copyright 2005 Renzo Davoli University of Bologna - Italy
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
 *   $Id$
 *
 */   
#include <assert.h>
#include <string.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <asm/ptrace.h>
#include <asm/unistd.h>
#include <asm/ioctls.h>
#include <linux/net.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include "defs.h"
#include "umproc.h"
#include "services.h"
#include "um_services.h"
#include "sctab.h"
#include "scmap.h"
#include "utils.h"
#include <sys/time.h>
#include <time.h>

#define umNULL ((int) NULL)

static void ioctl_getarg(pid_t pid, int request, unsigned int arg, void **larg)
{
	switch (request) {
		case FIONREAD:
			*larg=malloc(sizeof(int));
			break;
		case SIOCGIFCONF:
			*larg=malloc(sizeof(struct ifconf));
			break;
		case SIOCGSTAMP:
			*larg=malloc(sizeof(struct timeval));
			break;
		case SIOCGIFFLAGS:
		case SIOCGIFADDR:
		case SIOCGIFDSTADDR:
		case SIOCGIFBRDADDR:
		case SIOCGIFNETMASK:
		case SIOCGIFMETRIC:
		case SIOCGIFMEM:
		case SIOCGIFMTU:
		case SIOCGIFHWADDR:
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
			*larg=malloc(sizeof(struct ifreq));
			umoven(pid,arg,sizeof(struct ifreq),*larg);
			break;
		default:
			*larg=NULL;
			break;
	}
}

/* arg can be scalar or address. In the latter case memory has been allocated
 * and must be freed. When arg is a scalar must be set to NULL into putarg.
 * otherwise is misunderstood and erroneously freed */

static void ioctl_putarg(pid_t pid, int request, unsigned int arg, void *larg)
{
	switch (request) {
		case FIONREAD:
			ustoren(pid,arg,sizeof(int),larg);
			break;
		case SIOCGIFCONF:
			ustoren(pid,arg,sizeof(struct ifconf),larg);
			break;
		case SIOCGSTAMP:
			ustoren(pid,arg,sizeof(struct timeval),larg);
			break;
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
			ustoren(pid,arg,sizeof(struct ifreq),larg);
			break;
	}
}

int wrap_in_ioctl(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		char sercode, intfun syscall)
{
	int sfd=fd2sfd(pcdata->fds,pc->arg0);
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else {
		unsigned int req=getargn(1,pc);
		unsigned int arg=getargn(2,pc);
		pc->arg1=req;
		void *larg;
		ioctl_getarg(pc->pid,req,arg,&larg);
		//printf("wrap_in_ioctl %d req %x arg %x\n",sfd,req,larg);
		pc->retval = syscall(sfd,req,larg);
		pc->erno=errno;
		if (pc->retval >= 0)
			ioctl_putarg(pc->pid,req,arg,larg);
		if (larg != NULL)
			free(larg);
		//printf("wrap_in_ioctl %d %d\n",pc->retval,pc->erno);
	}
	return SC_FAKE;
}
