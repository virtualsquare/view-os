/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   um_ioctl: ioctl mgmt
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
#include <net/if.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <config.h>
#include "defs.h"
#include "umproc.h"
#include "services.h"
#include "um_services.h"
#include "sctab.h"
#include "scmap.h"
#include "utils.h"
#include <sys/time.h>
#include <time.h>

static void ioctl_getarg(struct pcb* pc, int ioctlparms, unsigned long arg, void **larg)
{
	int len=ioctlparms & IOCTLLENMASK;
	if (len > 0) {
		*larg=malloc(len);
		if (ioctlparms & IOCTL_R)
			umoven(pc,arg,len,*larg);
	} else
		*larg = (void *) arg;
}

static void ioctl_putarg(struct pcb* pc, int ioctlparms, unsigned long arg, void *larg)
{
	int len=ioctlparms & IOCTLLENMASK;
	if (len > 0) {
		if (ioctlparms & IOCTL_W)
			ustoren(pc,arg,len,larg);
		free(larg);
	}
}

int wrap_in_ioctl(int sc_number,struct pcb *pc,
		service_t sercode, sysfun um_syscall)
{
	int sfd=fd2sfd(pc->fds,pc->sysargs[0]);
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else {
		unsigned long req=pc->sysargs[1];
		unsigned long arg=pc->sysargs[2];
		void *larg;
		epochfun checkarg;
		int ioctlparms=0;
		if ((checkarg=service_checkfun(sercode)) != NULL) {
			struct ioctl_len_req ioreq={sfd,req};
			ioctlparms=checkarg(CHECKIOCTLPARMS, &ioreq);
		}
		ioctl_getarg(pc,ioctlparms,arg,&larg);
		if ((pc->retval = um_syscall(sfd,req,larg)) >= 0)
			ioctl_putarg(pc,ioctlparms,arg,larg);
		else {
			pc->erno=errno;
			ioctl_putarg(pc,ioctlparms & ~IOCTL_W,arg,larg);
		}
		/* printf("wrap_in_ioctl %d req %x arg %x parms %x -> %d\n",sfd,req,larg,ioctlparms,pc->retval);*/

		/*printf("wrap_in_ioctl %d %d\n",pc->retval,pc->erno);*/
	}
	return SC_FAKE;
}
