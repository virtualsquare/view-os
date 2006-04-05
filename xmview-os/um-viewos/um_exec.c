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

#define umNULL ((int) NULL)

static int filecopy(service_t sercode,const char *from, const char *to, void *umph)
{
	char buf[BUFSIZ];
	int fdf,fdt;
	int n;
	if ((fdf=service_syscall(sercode,uscno(__NR_open))(from,O_RDONLY,0,umph)) < 0)
		return -errno;
	if ((fdt=open(to,O_CREAT|O_TRUNC|O_WRONLY,0600)) < 0)
		return -errno;
	while ((n=service_syscall(sercode,uscno(__NR_read))(fdf,buf,BUFSIZ,umph)) > 0)
		write (fdt,buf,n);
	service_syscall(sercode,uscno(__NR_close))(fdf,umph);
	fchmod (fdt,0700); /* permissions? */
	close (fdt);
	return 0;
}

int wrap_in_execve(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		service_t sercode, intfun um_syscall)
{
	//int mode;
	//int argv=getargn(2,pc);
	//int env=getargn(3,pc);
	char *filename=strdup(um_proc_tmpname());
	//fprintf(stderr, "wrap_in_execve! %s\n",(char *)pcdata->path);

	/* argv and env should be downloaded then
	 * pc->retval = um_syscall(pcdata->path, argv, env); */
	if ((pc->retval=filecopy(sercode,pcdata->path,filename,pc))>=0) {
		long sp=getsp(pc);
		int filenamelen=WORDALIGN(strlen(filename));
		pc->retval=lfd_open(UM_NONE,-1,filename);
		ustorestr(pc->pid,sp-filenamelen,filenamelen,filename);
		putargn(0,sp-filenamelen,pc);
		putarg0orig(sp-filenamelen,pc);
		free(filename);
		return SC_CALLONXIT;
	} else {
		free(filename);
    pc->erno= -(pc->retval);
		pc->retval= -1;
		return SC_FAKE;
	}
}


int wrap_out_execve(int sc_number,struct pcb *pc,struct pcb_ext *pcdata) 
{
	if (pc->retval >= 0) {
		/* remove the temp file */
		unlink(lfd_getpath(pc->retval));
		lfd_close(pc->retval,pc);
	} else {
		putrv(pc->retval,pc);
		puterrno(pc->erno,pc);
	}
	return STD_BEHAVIOR;
}
