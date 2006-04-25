/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   um_wdm: working directory management
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
#include <asm/ptrace.h>
#include <asm/unistd.h>
#include <linux/net.h>
#include <sys/uio.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include "defs.h"
#include "umproc.h"
#include "services.h"
#include "um_services.h"
#include "sctab.h"
#include "scmap.h"
#include "utils.h"

#define umNULL ((int) NULL)

int wrap_in_getcwd(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		service_t sercode, intfun syscall)
{
	int arg1=getargn(1,pc);
	if (pc->arg0==(int) NULL) {
		pc->retval=(int) NULL;
		pc->erno=EFAULT;
	} else {
		//printf("dsys_getcwd %s\n",pcdata->fdfs->cwd);
		if (arg1 > PATH_MAX)
			arg1=PATH_MAX;
		if (ustorestr(pc->pid,pc->arg0,arg1,pcdata->fdfs->cwd) < 0) {
			pc->retval= -1;
			pc->erno=ERANGE;
		} else {
			pc->retval=strlen(pcdata->fdfs->cwd)+1;
			pc->erno=0;
		}
	}
	//printf("dsys_getcwd %s\n",pcdata->fdfs->cwd);
	return SC_FAKE;
}

int wrap_in_chdir(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		service_t sercode, intfun syscall)
{
	if (pc->erno == 0) {
		int sp=getsp(pc);
		int pathlen;
		if (sercode != UM_NONE) {
			//printf("virtual path chdir to /tmp\n");
			pathlen=8;
			ustorestr(pc->pid,sp-pathlen,pathlen,"/tmp");
		} else {
			pathlen=(strlen(pcdata->path) + 4) & (~3);
			ustorestr(pc->pid,sp-pathlen,pathlen,pcdata->path);
		}
		putargn(0,sp-pathlen,pc);
		putarg0orig(sp-pathlen,pc);
		return SC_CALLONXIT;
	} else {
		pc->retval = -1;
		return SC_FAKE;
	}
}

int wrap_out_chdir(int sc_number,struct pcb *pc,struct pcb_ext *pcdata) 
{
	if (pc->behavior == SC_FAKE) {
		int err;
		//printf("chdir err %d\n",pc->erno);
		err=putrv(pc->retval,pc);
		err=puterrno(pc->erno,pc);
	} else {
		pc->retval=getrv(pc);
		//printf("chdir returns %d\n",pc->retval);
		putarg0orig(pc->arg0,pc);
		if (pc->retval >= 0) {
			free(pcdata->fdfs->cwd);
			pcdata->fdfs->cwd = pcdata->path;
			//printf("new dir %d - %s\n",pc->pid,
			//((struct pcb_ext *)(pc->data))->cwd);
		} else {
			free((char *)pcdata->path);
		}
	}
	pcdata->path=NULL;
	return STD_BEHAVIOR;
}

int wrap_in_fchdir(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		service_t sercode, intfun syscall)
{
	if (pc->erno == 0) {
		int sp=getsp(pc);
		int pathlen;
		if ((pcdata->path=strdup(fd_getpath(pcdata->fds,pc->arg0))) != NULL) {
			//printf("fchdir to %s\n",pcdata->path);
			if (sercode != UM_NONE) {
				//printf("virtual path chdir to /tmp\n");
				pathlen=8;
				ustorestr(pc->pid,sp-pathlen,pathlen,"/tmp");
			} else {
				pathlen=(strlen(pcdata->path) + 4) & (~3);
				ustorestr(pc->pid,sp-pathlen,pathlen,pcdata->path);
			}
			putargn(0,sp-pathlen,pc);
			putarg0orig(sp-pathlen,pc);
			putscno(__NR_chdir,pc);
			return SC_CALLONXIT;
		} else {
			pc->retval = -1;
			pc->erno = EINVAL; /* right error code? XXX */
			return SC_FAKE;
		}
	} else {
		pc->retval = -1;
		return SC_FAKE;
	}
}

int wrap_in_umask(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		service_t sercode, intfun syscall)
{
	mode_t mode=pc->arg0;
	pcdata->fdfs->mask = mode;
	return STD_BEHAVIOR;
}

int wrap_in_chroot(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		service_t sercode, intfun syscall)
{
	if (pc->erno == 0) {
		free(pcdata->fdfs->root);
		pcdata->fdfs->root=strdup(pcdata->path);
		/* TODO management of chroot */
		/*pc->erno = pc->retval = 0;*/
		pc->retval = -1;
		pc->erno = EACCES;
		return SC_FAKE;
	} else {
		pc->retval = -1;
		return SC_FAKE;
	}
}

