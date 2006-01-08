/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   um_plusio: io wrappers (second part)
 *   
 *   Copyright 2005 Renzo Davoli University of Bologna - Italy
 *   Modified 2005 Ludovico Gardenghi
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
#include <sys/types.h>
#include <sys/time.h>
#include <asm/ptrace.h>
#include <asm/unistd.h>
#include <linux/net.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <alloca.h>
#include <utime.h>
#include "defs.h"
#include "gdebug.h"
#include "umproc.h"
#include "services.h"
#include "um_services.h"
#include "sctab.h"
#include "scmap.h"
#include "utils.h"
#include "uid16to32.h"

#define umNULL ((int) NULL)

int wrap_in_mkdir(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		char sercode, intfun syscall)
{
	int mode;
	mode=getargn(1,pc);
	pc->retval = syscall(pcdata->path,mode & ~ (pcdata->fdfs->mask),pc);
	pc->erno=errno;
	return SC_FAKE;
}

int wrap_in_unlink(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		                char sercode, intfun syscall)
{
	pc->retval = syscall(pcdata->path,pc);
	pc->erno=errno;
	return SC_FAKE;
}

int wrap_in_chown(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		char sercode, intfun syscall)
{
	unsigned int owner,group;
	owner=getargn(1,pc);
	group=getargn(2,pc);
#if __NR_chown != __NR_chown32
	if (sc_number == __NR_chown || sc_number == __NR_lchown) {
		owner=id16to32(owner);
		group=id16to32(group);
	}
#endif
	pc->retval = syscall(pcdata->path,owner,group,pc);
	pc->erno=errno;
	return SC_FAKE;
}

int wrap_in_fchown(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		char sercode, intfun syscall)
{
	int sfd=fd2sfd(pcdata->fds,pc->arg0);
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
		return SC_FAKE;
	} else {
		unsigned int owner,group;
		owner=getargn(1,pc);
		group=getargn(2,pc);
#if __NR_fchown != __NR_fchown32
	if (sc_number == __NR_fchown) {
		owner=id16to32(owner);
		group=id16to32(group);
	}
#endif
		pc->retval = syscall(sfd,owner,group,pc);
		pc->erno=errno;
		return SC_FAKE;
	}
}

int wrap_in_chmod(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		char sercode, intfun syscall)
{
	int mode;
	mode=getargn(1,pc);
	pc->retval = syscall(pcdata->path,mode,pc);
	pc->erno=errno;
	return SC_FAKE;
}

int wrap_in_fchmod(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		char sercode, intfun syscall)
{
	int sfd=fd2sfd(pcdata->fds,pc->arg0);
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
		return SC_FAKE;
	} else {
		int mode;
		mode=getargn(1,pc);
		pc->retval = syscall(sfd,mode,pc);
		pc->erno=errno;
		return SC_FAKE;
	}
}

/* DUP & DUP2.
 * Always processed in any case.
 * if the dup fd refers an open file it must be closed (if it is managed by a service 
 * module the close request must be forwarded to that module).
 */

int wrap_in_dup(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		service_t sercode, intfun syscall)
{
	if (sc_number == __NR_dup2) {
		pc->arg1=getargn(1,pc);
	} else
		pc->arg1= -1;
	int sfd=fd2sfd(pcdata->fds,pc->arg0);
	GDEBUG(4, "DUP %d %d sfd %d %s",pc->arg0,pc->arg1,sfd,fd_getpath(pcdata->fds,pc->arg0));
	if (sfd < 0 && sercode != UM_NONE) {
		pc->retval= -1;
		pc->erno= EBADF;
		return SC_FAKE;
	} else {
		pc->retval=fd2lfd(pcdata->fds,pc->arg0);
		pc->erno = 0;
		/*if (pc->retval < 0) {
			pc->retval= -1;
			pc->erno= EBADF;
			return SC_FAKE;
		} else { */
		lfd_dup(pc->retval);
		return SC_CALLONXIT;
		/*}*/
	}
}

int wrap_out_dup(int sc_number,struct pcb *pc,struct pcb_ext *pcdata)
{
	/* TODO Dup is incomplete */
	//if (pc->retval >= 0) {
	if (pc->behavior == SC_CALLONXIT) {
		int fd=getrv(pc);
		if (fd >= 0) {
			if (pc->arg1 != -1)
				lfd_deregister_n_close(pcdata->fds,pc->arg1);
			lfd_register(pcdata->fds,fd,pc->retval);
		} else {
			lfd_close(pc->retval);
		}
	} else {
		putrv(pc->retval,pc);
		puterrno(pc->erno,pc);
	}
	return STD_BEHAVIOR;
}

int wrap_in_fcntl(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		service_t sercode, intfun syscall)
{
	int cmd=getargn(1,pc);
	unsigned long arg=getargn(2,pc);
	int sfd=fd2sfd(pcdata->fds,pc->arg0);
	pc->arg1=cmd;
	//printf("wrap_in_fcntl %d %d %d %d \n",pc->arg0,sfd,cmd,fd2lfd(pcdata->fds,pc->arg0));
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
		return SC_FAKE;
	} else {
		if (cmd == F_GETLK || cmd == F_SETLK || cmd == F_SETLKW) {
			/* LOCKING unsupported yet XXX */
			printf("Locking unsupported\n");
			pc->retval= -1;
			pc->erno= EBADF;
			return SC_FAKE;
		} else if (cmd == F_DUPFD) {
			pc->retval=fd2lfd(pcdata->fds,pc->arg0);
			lfd_dup(pc->retval);
			return SC_CALLONXIT;
		} else {
			pc->retval = syscall(sfd,cmd,arg,pc);
			//pc->erno= pc->retval<0?errno:0;
			pc->erno= errno;
			return SC_FAKE;
		}
	}
}


int wrap_out_fcntl(int sc_number,struct pcb *pc,struct pcb_ext *pcdata)
{
	int fd;
	switch (pc->arg1) {
		case F_DUPFD:
			fd=getrv(pc);
			//printf("F_DUPFD %d->%d\n",pc->retval,fd);
			if (fd>=0)
				lfd_register(pcdata->fds,fd,pc->retval);
			else
				lfd_close(pc->retval);
			break;
		case F_SETFD:
			/* take care of FD_CLOEXEC flag value XXX */
		default:
			//printf("fcntl returns %d %d\n",pc->retval,pc->erno);
			putrv(pc->retval,pc);
			puterrno(pc->erno,pc);
			break;
	}
	return STD_BEHAVIOR;
}

int wrap_in_fsync(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		char sercode, intfun syscall)
{
	int sfd=fd2sfd(pcdata->fds,pc->arg0);
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
		return SC_FAKE;
	} else {
		pc->retval = syscall(sfd,pc);
		pc->erno=errno;
	}
	return SC_FAKE;
}

int wrap_in_link(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		char sercode, intfun syscall)
{
	struct stat64 sourcest;
	char *source=um_abspath(pc->arg0,pc,&sourcest,0);

	if (source==um_patherror) {
		pc->retval= -1;
		pc->erno= ENOENT;
	} else {
		int ser2=service_check(CHECKPATH,source,pc);
		if (ser2 != sercode) {
			pc->retval= -1;
			pc->erno= EXDEV;
		} else {
			pc->retval=syscall(source,pcdata->path,pc);
			pc->erno= errno;
		}
		free(source);
	}
	return SC_FAKE;
}

int wrap_in_symlink(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		char sercode, intfun syscall)
{
	char *source=um_getpath(pc->arg0,pc);
	if (source==um_patherror) {
		pc->retval= -1;
		pc->erno= ENOENT;
	} else {
		pc->retval=syscall(source,pcdata->path,pc);
		free(source);
	}
	return SC_FAKE;
}

int wrap_in_utime(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		char sercode, intfun syscall)
{
	unsigned int argaddr=getargn(1,pc);
	int argsize;
	char *larg;
	if (argaddr == umNULL) 
		larg=NULL;
	else {
		if (sc_number == __NR_utime)
			argsize=sizeof(struct utimbuf);
		else
			argsize=2*sizeof(struct timeval);
		larg=alloca(argsize);
	}
	umoven(pc->pid,argaddr,argsize,larg);
	pc->retval = syscall(pcdata->path,larg,pc);
	pc->erno=errno;
	return SC_FAKE;
}

int wrap_in_mount(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		                char sercode, intfun syscall)
{
	char source[PATH_MAX];
	char filesystemtype[PATH_MAX];
	char data[PATH_MAX];
	char *datax=data;
	unsigned int argaddr=pc->arg0;
	unsigned int fstype=getargn(2,pc);
	unsigned int mountflags=getargn(3,pc);
	unsigned int pdata=getargn(4,pc);
	umovestr(pc->pid,fstype,PATH_MAX,filesystemtype);
	umovestr(pc->pid,argaddr,PATH_MAX,source);
	if (pdata != umNULL)
		umovestr(pc->pid,pdata,PATH_MAX,data);
	else
		datax=NULL;
	pc->retval = syscall(source,pcdata->path,filesystemtype,mountflags,datax,pc);
	pc->erno=errno;
	return SC_FAKE;
}

int wrap_in_umount(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		                char sercode, intfun syscall)
{
	unsigned int flags=0;
	if (sc_number == __NR_umount2)
		flags=getargn(1,pc);
	pc->retval = syscall(pcdata->path,flags,pc);
	pc->erno=errno;
	return SC_FAKE;
}
