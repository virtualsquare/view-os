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
#include "gdebug.h"

#define umNULL ((int) NULL)

// Could this be "/"?
#define CHDIR_FAKE_DIR "/tmp"

/* TODO mgmt of cwd buffer overflow */
int wrap_in_getcwd(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		service_t sercode, intfun um_syscall)
{
	long arg1=getargn(1,pc);
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

/* TODO: While fchdir tries to make a chdir to the real directory instead of
 * /tmp (if it exists), chdir does not try this yet. I was not sure about
 * the correct check and where to put it, so I haven't done it at the moment.
 * But it should be changed. */
int wrap_in_chdir(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		service_t sercode, intfun um_syscall)
{
	if (!S_ISDIR(pcdata->pathstat.st_mode)) {
		if (pcdata->pathstat.st_mode == 0)
			pc->erno=ENOENT;
		else
			pc->erno=ENOTDIR;
	}
	if (pc->erno == 0 && S_ISDIR(pcdata->pathstat.st_mode)) {
		long sp=getsp(pc);
		int pathlen;
		if (sercode != UM_NONE) {
			//printf("virtual path chdir to %s\n", CHDIR_FAKE_DIR);
			//XXX: check length of parameter??? if arg0 was one byte long?
			pathlen = WORDALIGN(strlen(CHDIR_FAKE_DIR));
			ustorestr(pc->pid, sp-pathlen, pathlen, CHDIR_FAKE_DIR);
		} else {
			pathlen = WORDALIGN(strlen(pcdata->path));
			ustorestr(pc->pid, sp-pathlen, pathlen, pcdata->path);
		}
		putargn(0,sp-pathlen,pc);
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
		/*printf("chdir returns %d\n",pc->retval);*/
		if (pc->retval >= 0) {
			free(pcdata->fdfs->cwd);
			pcdata->fdfs->cwd = pcdata->path;
			/*printf("new dir %d - %s\n",pc->pid,
			((struct pcb_ext *)(pc->data))->fdfs->cwd);*/
		} else {
			free((char *)pcdata->path);
		}
	}
	pcdata->path=NULL;
	return STD_BEHAVIOR;
}

int wrap_in_fchdir(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		service_t sercode, intfun um_syscall)
{
	long sp=getsp(pc);
	int pathlen;
	char *path;

	if ((path=fd_getpath(pcdata->fds,pc->arg0)) != NULL) {
		//printf("fchdir to %s\n",pcdata->path);
		pcdata->path=strdup(path);
		um_x_lstat64(pcdata->path, &(pcdata->pathstat), pc);
		/* If there is a real directory with this name, and it is chdir-able,
		 * we can chdir there instead of /tmp/ so the core and the process
		 * will see the same cwd. */
		if (S_ISDIR(pcdata->pathstat.st_mode) && (access(pcdata->path, X_OK) == 0))
		{
			pathlen = WORDALIGN(strlen(pcdata->path));
			ustorestr(pc->pid, sp - pathlen, pathlen, pcdata->path);
			putargn(0, sp - pathlen, pc);
			putscno(__NR_chdir, pc);
			GDEBUG(4, "FCHDIR making fake chdir to real %s", pcdata->path);
			return SC_CALLONXIT;
		}
		else
		{
			um_x_lstat64(pcdata->path, &(pcdata->pathstat), pc);
			if (S_ISDIR(pcdata->pathstat.st_mode)) {
				if (sercode != UM_NONE) {
					//printf("virtual path chdir to %s\n", CHDIR_FAKE_DIR);
					GDEBUG(4, "FCHDIR making chdir to %s (instead of %s)", CHDIR_FAKE_DIR, pcdata->path);
					pathlen = WORDALIGN(strlen(CHDIR_FAKE_DIR));
					ustorestr(pc->pid, sp-pathlen, pathlen, CHDIR_FAKE_DIR);
				} else {
					GDEBUG(4, "FCHDIR making chdir to unmanaged %s", pcdata->path);
					pathlen = WORDALIGN(strlen(pcdata->path));
					ustorestr(pc->pid, sp-pathlen, pathlen, pcdata->path);
				}
				putargn(0,sp-pathlen,pc);
				putscno(__NR_chdir,pc);
				return SC_CALLONXIT;
			} else {
				GDEBUG(4, "FCHDIR ENOTDIR for %s", pcdata->path);
				pc->retval = -1;
				pc->erno=ENOTDIR;
				return SC_FAKE;
			}
		}
	} else {
		GDEBUG(4, "FCHDIR EBADF for %s", pcdata->path);
		pc->retval = -1;
		pc->erno = EBADF; 
		return SC_FAKE;
	}
}

int wrap_in_umask(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		service_t sercode, intfun um_syscall)
{
	mode_t mode=pc->arg0;
	pcdata->fdfs->mask = mode;
	return STD_BEHAVIOR;
}

int wrap_in_chroot(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		service_t sercode, intfun um_syscall)
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

