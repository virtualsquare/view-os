/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   um_wdm: working directory management
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
#include <asm/ptrace.h>
#include <asm/unistd.h>
#include <linux/net.h>
#include <sys/uio.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <config.h>
#include "defs.h"
#include "umproc.h"
#include "services.h"
#include "um_services.h"
#include "sctab.h"
#include "scmap.h"
#include "utils.h"
#include "gdebug.h"

#define umNULL ((int) NULL)

int wrap_in_getcwd(int sc_number,struct pcb *pc,
		service_t sercode, sysfun um_syscall)
{
	long arg1=pc->sysargs[1];
	if (pc->sysargs[0]==(int) NULL) {
		pc->retval=(int) NULL;
		pc->erno=EFAULT;
	} else {
		//printf("dsys_getcwd %s\n",pc->fdfs->cwd);
		int len=strlen(pc->fdfs->cwd)+1;
		if (len > arg1) {
			pc->retval= -1;
			pc->erno=ERANGE;
		} else {
			/*if (arg1 > PATH_MAX)
				arg1=PATH_MAX;*/
			if (ustorestr(pc,pc->sysargs[0],arg1,pc->fdfs->cwd) < 0) {
				pc->retval= -1;
				pc->erno=ERANGE;
			} else {
				pc->retval=len;
				pc->erno=0;
			}
		}
	}
	return SC_FAKE;
}

/* TODO: While fchdir tries to make a chdir to the real directory instead of
 * /tmp (if it exists), chdir does not try this yet. I was not sure about
 * the correct check and where to put it, so I haven't done it at the moment.
 * But it should be changed. */
int wrap_in_chdir(int sc_number,struct pcb *pc,
		service_t sercode, sysfun um_syscall)
{
	if (!S_ISDIR(pc->pathstat.st_mode)) {
		if (pc->pathstat.st_mode == 0)
			pc->erno=ENOENT;
		else
			pc->erno=ENOTDIR;
	}
	if ( (pc->erno==0) && (um_x_access(pc->path,X_OK,pc)!=0) ) {
			pc->erno=EACCES;
	}
	if (pc->erno == 0 && S_ISDIR(pc->pathstat.st_mode)) {
		long sp=getsp(pc);
		int pathlen;
		if (sercode != UM_NONE) {
			char *chdir_fake_dir = um_proc_fakecwd();
			//fprint2("virtual path chdir to %s\n", chdir_fake_dir);
			//XXX: check length of parameter??? if sysargs[0] was one byte long?
			pathlen = WORDALIGN(strlen(chdir_fake_dir));
			ustoren(pc, sp-pathlen, pathlen, chdir_fake_dir);
		} else {
			pathlen = WORDALIGN(strlen(pc->path));
			ustoren(pc, sp-pathlen, pathlen, pc->path);
		}
		pc->sysargs[0]=sp-pathlen;
		return SC_CALLONXIT;
	} else {
		pc->retval = -1;
		return SC_FAKE;
	}
}

int wrap_out_chdir(int sc_number,struct pcb *pc) 
{
	if (pc->behavior == SC_FAKE) {
		//printf("chdir err %d\n",pc->erno);
		putrv(pc->retval,pc);
		puterrno(pc->erno,pc);
		pc->path=NULL;
		return SC_MODICALL;
	} else {
		pc->retval=getrv(pc);
		if (pc->retval >= 0) {
			free(pc->fdfs->cwd);
			pc->fdfs->cwd = pc->path;
			//fprint2("new dir %d - %s\n",pc->pid, pc->fdfs->cwd);
		} else {
			free((char *)pc->path);
		}
		pc->path=NULL;
		return STD_BEHAVIOR;
	}
}

int wrap_in_fchdir(int sc_number,struct pcb *pc,
		service_t sercode, sysfun um_syscall)
{
	long sp=getsp(pc);
	int pathlen;
	char *path;

	if ((path=fd_getpath(pc->fds,pc->sysargs[0])) != NULL) {
		//printf("fchdir to %s\n",pc->path);
		pc->path=strdup(path);
		um_x_lstat64(pc->path, &(pc->pathstat), pc);
		/* If there is a real directory with this name, and it is chdir-able,
		 * we can chdir there instead of /tmp/ so the core and the process
		 * will see the same cwd. */
		if (S_ISDIR(pc->pathstat.st_mode) && (access(pc->path, X_OK) == 0))
		{
			pathlen = WORDALIGN(strlen(pc->path));
			ustoren(pc, sp - pathlen, pathlen, pc->path);
			pc->sysargs[0]=sp-pathlen;
			putscno(__NR_chdir, pc);
			GDEBUG(4, "FCHDIR making fake chdir to real %s", pc->path);
			return SC_CALLONXIT;
		}
		else
		{
			um_x_lstat64(pc->path, &(pc->pathstat), pc);
			if (S_ISDIR(pc->pathstat.st_mode)) {
				if (sercode != UM_NONE) {
					char *chdir_fake_dir= um_proc_fakecwd();
					GDEBUG(4, "FCHDIR making chdir to %s (instead of %s)", chdir_fake_dir, pc->path);
					pathlen = WORDALIGN(strlen(chdir_fake_dir));
					ustoren(pc, sp-pathlen, pathlen, chdir_fake_dir);
				} else {
					GDEBUG(4, "FCHDIR making chdir to unmanaged %s", pc->path);
					pathlen = WORDALIGN(strlen(pc->path));
					ustoren(pc, sp-pathlen, pathlen, pc->path);
				}
				pc->sysargs[0]=sp-pathlen;
				putscno(__NR_chdir,pc);
				return SC_CALLONXIT;
			} else {
				GDEBUG(4, "FCHDIR ENOTDIR for %s", pc->path);
				pc->retval = -1;
				pc->erno=ENOTDIR;
				return SC_FAKE;
			}
		}
	} else {
		GDEBUG(4, "FCHDIR EBADF for %s", pc->path);
		pc->retval = -1;
		pc->erno = EBADF; 
		return SC_FAKE;
	}
}

int wrap_in_umask(int sc_number,struct pcb *pc,
		service_t sercode, sysfun um_syscall)
{
	mode_t mode=pc->sysargs[0];
	pc->fdfs->mask = mode;
	return STD_BEHAVIOR;
}

int wrap_in_chroot(int sc_number,struct pcb *pc,
		service_t sercode, sysfun um_syscall)
{
	if (pc->erno == 0) {
		/* TODO management of chroot */
		/*free(pc->fdfs->root);
		pc->fdfs->root=strdup(pc->path) */
		/*pc->erno = pc->retval = 0;*/
		pc->retval = -1;
		pc->erno = EACCES;
		return SC_FAKE;
	} else {
		pc->retval = -1;
		return SC_FAKE;
	}
}

