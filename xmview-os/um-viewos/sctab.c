/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   sctab.c: um-ViewOS interface to capture_sc
 *   
 *   Copyright 2005 Renzo Davoli University of Bologna - Italy
 *   Modified 2005 Mattia Belletti, Ludovico Gardenghi
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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sched.h>
#include <asm/ptrace.h>
#include <asm/unistd.h>
#include <linux/net.h>
#include <errno.h>
#include <limits.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>

#include "defs.h"
#include "umproc.h"
#include "services.h"
#include "um_services.h"
#include "sctab.h"
#include "um_select.h"
#include "scmap.h"
#include "utils.h"
#include "canonicalize.h"
#include "gdebug.h"

void um_set_errno(struct pcb *pc,int i) {
	pc->erno=i;
}

char *um_getcwd(struct pcb *pc,char *buf,int size) {
	strncpy(buf,((struct pcb_ext *)(pc->data))->fdfs->cwd,size);
	return buf;
}

int um_lstat64(char *filename, struct stat64 *buf)
{
	service_t sercode;
	//printf("-> um_lstat: %s\n",filename);
	if ((sercode=service_path(filename)) == UM_NONE)
		return lstat64(filename,buf);
	else 
		return service_syscall(sercode,uscno(__NR_lstat64))(filename,buf);
}

int um_readlink(char *path, char *buf, size_t bufsiz)
{
	service_t sercode;
	if ((sercode=service_path(path)) == UM_NONE)
		return readlink(path,buf,bufsiz);
	else 
		return service_syscall(sercode,uscno(__NR_readlink))(path,buf,bufsiz);
}

char um_patherror[]="PE";

char *um_getpath(int laddr,struct pcb *pc)
{
	char path[PATH_MAX];
	if (umovestr(pc->pid,laddr,PATH_MAX,path) == 0)
		return strdup(path);
	else
		return um_patherror;
}

char *um_abspath(int laddr,struct pcb *pc,int link)
{
	char path[PATH_MAX];
	char newpath[PATH_MAX];
	if (umovestr(pc->pid,laddr,PATH_MAX,path) == 0) {
		if (link) {
			char tmppath[PATH_MAX];
			strcpy(tmppath,path);
			um_realpath(pc,dirname(tmppath),newpath);
			strncat(newpath,"/",PATH_MAX);
			strncat(newpath,basename(path),PATH_MAX);
			//printf("um_abslpath %s %s %s %s\n",path,dirname(path),basename(path),newpath);
		} else
			um_realpath(pc,path,newpath);
		//printf("um_abspath %d %s %s\n",pc->erno,path,newpath);
		return strdup(newpath);
		/*
		if (pc->erno)
			return um_patherror;	//error
		else
			return strdup(newpath);*/
	}
	else {
		pc->erno = EINVAL;
		return um_patherror;
	}
}

/* Common framework for the dsys_{megawrap,socketwrap,mmapwrap,...} - they all
 * do the usual work, but with different parameter handling.
 * What a dsys_* function do is, in general, receiving the notification of an
 * IN/OUT phase of syscall about a certain process, and decide what to do. What
 * it has to do is to deliver the notification to the correct functions.
 * This common framework asks for three more parameters to make such a
 * decision:
 * - An argument parser function (dcpa): this function extracts the arguments
 *   from the process registers/memory into our data structures (usually
 *   arg{0,1,...}, but also others - e.g., sockregs). It must also return the
 *   index inside the system call table that regards the current system call.
 * - A service call function (sc): the service code and system call number is
 *   given to this function, and it must return the function of the
 *   module/service which manage the syscall
 * - A system call table (sm): this is a table of sc_map entries - look at that
 *   structure for more informations.
 */
typedef int (*dsys_commonwrap_parse_arguments)(struct pcb *pc, struct pcb_ext *pcdata, int usc);
typedef intfun (*service_call)(service_t code, int scno);
int dsys_commonwrap(int sc_number,int inout,struct pcb *pc,
		dsys_commonwrap_parse_arguments dcpa, service_call sc,
		struct sc_map *sm)
{
	struct pcb_ext *pcdata=(struct pcb_ext *)(pc->data);
	int usc=uscno(sc_number);
	/* -- IN phase -- */
	if (inout == IN) {
		service_t sercode;
		/* extract argument, and get the index of the system call table
		 * regarding this syscall */
		int index = dcpa(pc, pcdata, usc);
		/* looks in the system call table what is the 'choice function'
		 * and ask it the service to manage */
		sercode=sm[index].scchoice(sc_number,pc,pcdata);
		/* something went wrong during a path lookup - fake the
		 * syscall, we do not want to make it run */
		if (pcdata->path == um_patherror) {
			pc->retval = -1;
			return SC_FAKE;
		}
		/* if some service want to manage the syscall (or the ALWAYS
		 * flag is set), we process it */
		if (sercode != UM_NONE || (sm[usc].flags & ALWAYS)) {
			/* suspend management - TODO: don't know how it works!
			 * :P */
			int howsusp = sm[index].flags & 0x7;
			int what;
			if (howsusp != 0 && (what=check_suspend_on(pc, pcdata, pc->arg2, howsusp))!=STD_BEHAVIOR)
				return what;
			else
				/* normal management: call the wrapin function,
				 * with the correct service syscall function */
				return sm[index].wrapin(sc_number,pc,pcdata,sercode,sc(sercode,index));
		}
		else {
			/* we do not want to manage the syscall: free the path
			 * field in case, since we do not need it, and ask for
			 * a standard behavior */
			if (pcdata->path != NULL)
				free(pcdata->path);
			return STD_BEHAVIOR;
		}
	/* -- OUT phase -- */
	} else {
		if (pcdata->path != um_patherror) {
			/* ok, try to call the wrapout */
			int retval;
			/* call the wrapout */
			retval=scmap[usc].wrapout(sc_number,pc,pcdata);
			/* check if we can free the path (not NULL and not
			 * used) */
			if (pcdata->path != NULL && (retval & SC_SUSPENDED) == 0)
				free(pcdata->path);
			return retval;
		}
		else {
			/* during the IN phase something gone wrong (XXX: is
			 * this the point?) - simply pass return value and
			 * errno to the process */
			putrv(pc->retval,pc);
			puterrno(pc->erno,pc);
			return STD_BEHAVIOR;
		}
	}
}

int dsys_socketwrap_parse_arguments(struct pcb *pc, struct pcb_ext *pcdata, int usc)
{
	pc->arg0=getargn(0,pc); // arg0 is the current socket call
	pc->arg1=getargn(1,pc);
	pcdata->path = NULL;
	if (has_ptrace_multi) {
		struct ptrace_multi req[] = {{PTRACE_PEEKDATA, pc->arg1, &(pcdata->sockregs[0]), sockmap[pc->arg0].nargs}};
		errno=0;
		ptrace(PTRACE_MULTI,pc->pid,req,1);
		pc->arg2=pcdata->sockregs[0];
	}
	else
	{
		int i;
		pc->arg2=pcdata->sockregs[0]=ptrace(PTRACE_PEEKDATA,pc->pid,pc->arg1,0);
		for (i=1;i<sockmap[pc->arg0].nargs;i++)
			pcdata->sockregs[i]=ptrace(PTRACE_PEEKDATA,pc->pid,4*i+pc->arg1,0);
	}

	return pc->arg0;
}

int dsys_socketwrap(int sc_number,int inout,struct pcb *pc)
{
	return dsys_commonwrap(sc_number, inout, pc,
			dsys_socketwrap_parse_arguments, service_socketcall,
			sockmap);
}

/* ??? */
void um_proc_add(struct pcb *pc)
{
}

/* ??? */
void um_proc_del(struct pcb *pc)
{
}

static mode_t local_getumask(void) {
	mode_t mask = umask(0);
	umask(mask);
	return mask;
}

void pcb_plus(struct pcb *pc,int flags)
{
	struct pcb_ext *pcpe;
	pc->data = (void *) (pcpe = (struct pcb_ext *) malloc(sizeof (struct pcb_ext)));
	/* CLONE_PARENT = I'm not your child, I'm your brother. So, parent is
	 * different from what we thought */
	if (flags & CLONE_PARENT)
		pc->pp=pc->pp->pp;
	/* CLONE_FS = share filesystem information */
	if (flags & CLONE_FS) {
		pcpe->fdfs = ((struct pcb_ext *)pc->pp->data)->fdfs;
		pcpe->fdfs->count++;
	} else {
		pcpe->fdfs =  (struct pcb_fs *) malloc(sizeof (struct pcb_fs));
		pcpe->fdfs->count=1;
	}
	if (pc->pp == pc) {
		pcpe->fdfs->cwd=getcwd(NULL,0);
		pcpe->fdfs->root=strdup("/");
		pcpe->fdfs->mask=local_getumask();
		umask(pcpe->fdfs->mask);
	} else {
		pcpe->fdfs->cwd=strdup(((struct pcb_ext *)(pc->pp->data))->fdfs->cwd);
		pcpe->fdfs->root=strdup(((struct pcb_ext *)(pc->pp->data))->fdfs->root);
		pcpe->fdfs->mask=((struct pcb_ext *)(pc->pp->data))->fdfs->mask;
	}
	pcpe->path=pcpe->selset=NULL;
	/* if CLONE_FILES, file descriptor table is shared */
	if (flags & CLONE_FILES)
		pcpe->fds = ((struct pcb_ext *)(pc->pp->data))->fds;
	lfd_addproc(&(pcpe->fds),flags & CLONE_FILES);
	um_proc_add(pc);
}

void pcb_minus(struct pcb *pc)
{
	struct pcb_ext *pcpe=pc->data;
	//printf("pcb_desctructor %d\n",pc->pid);
	lfd_delproc(&(pcpe->fds));
	um_proc_del(pc);
	assert (pcpe->fdfs != NULL);
	pcpe->fdfs->count--;
	if (pcpe->fdfs->count == 0) {
		free (pcpe->fdfs->cwd);
		free (pcpe->fdfs->root);
		free (pcpe->fdfs);
	}
	free(pcpe);
	/*if (pc->data != NULL) {
		free(((struct pcb_ext *)pc->data)->fdfs->cwd);
		free(pc->data);
	}*/
}

int dsys_dummy(int sc_number,int inout,struct pcb *pc)
{
	if (inout == IN) {
		GDEBUG(1, "dummy diverted syscall pid %d call %d",pc->pid,sc_number);
		return STD_BEHAVIOR;
	} else {
	}
	return STD_BEHAVIOR;
}

int dsys_error(int sc_number,int inout,struct pcb *pc)
{
	GDEBUG(1, "dsys_error pid %d call %d",pc->pid,sc_number);
	pc->retval = -1;
	pc->erno = ENOSYS;
	return STD_BEHAVIOR;
}

char choice_fd(int sc_number,struct pcb *pc,struct pcb_ext *pcdata)
{
	int fd=(sc_number == __NR_socketcall)?pc->arg2:pc->arg0;
	/*`int rv;
	rv= service_fd(&(pcdata->fds),fd);
	printf("choice_fd sc=%d %d %x\n",sc_number,fd,rv);
	return rv;*/
	return service_fd(pcdata->fds,fd);
}

/* choice mount (mount point must be defined + filesystemtype is used
 * instead of the pathname for service selection) */
char choice_mount(int sc_number,struct pcb *pc,struct pcb_ext *pcdata)
{
	pc->arg1=getargn(1,pc);
	pcdata->path=um_abspath(pc->arg1,pc,0); 
	
	if (pcdata->path!=um_patherror) {
		char filesystemtype[PATH_MAX];
		unsigned int fstype=getargn(2,pc);
		if (umovestr(pc->pid,fstype,PATH_MAX,filesystemtype) == 0) {
			return service_path(filesystemtype);
		}
		else
			return UM_NONE;
	} else
		return UM_NONE;
}

/* choice path (filename must be defined) */
char choice_path(int sc_number,struct pcb *pc,struct pcb_ext *pcdata)
{
	pcdata->path=um_abspath(pc->arg0,pc,0); 
	//printf("choice_path %d %s\n",sc_number,pcdata->path);
	
	if (pcdata->path==um_patherror)
		return UM_NONE;
	else
		return service_path(pcdata->path);
}

/* choice link (dirname must be defined, basename can be non-existent) */
char choice_link(int sc_number,struct pcb *pc,struct pcb_ext *pcdata)
{
	pcdata->path=um_abspath(pc->arg0,pc,1); 
	//printf("choice_path %d %s\n",sc_number,pcdata->path);
	if (pcdata->path==um_patherror)
		return UM_NONE;
	else
		return service_path(pcdata->path);
}

/* choice link (dirname must be defined, basename can be non-existent second arg)*/
char choice_link2(int sc_number,struct pcb *pc,struct pcb_ext *pcdata)
{
	pc->arg1=getargn(1,pc);
	pcdata->path=um_abspath(pc->arg1,pc,1); 
	//printf("choice_path %d %s\n",sc_number,pcdata->path);
	if (pcdata->path==um_patherror)
		return UM_NONE;
	else
		return service_path(pcdata->path);
}

char choice_socket(int sc_number,struct pcb *pc,struct pcb_ext *pcdata)
{
	return service_socket(pc->arg2);
}

char always_umnone(int sc_number,struct pcb *pc,struct pcb_ext *pcdata)
{
	return UM_NONE;
}

int dsys_megawrap_parse_arguments(struct pcb *pc, struct pcb_ext *pcdata, int usc)
{
	pcdata->path = NULL;
	pc->arg0 = getargn(0, pc);
	return usc;
}

int dsys_megawrap(int sc_number,int inout,struct pcb *pc)
{
	return dsys_commonwrap(sc_number, inout, pc,
			dsys_megawrap_parse_arguments, service_syscall,
			scmap);
}

#define __NR_UM_SERVICE BASEUSC+0
void scdtab_init()
{
	register int i;
	pcb_constr=pcb_plus;
	pcb_destr=pcb_minus;

	setcdtab(__NR_socketcall,dsys_socketwrap);

	setcdtab(__NR_UM_SERVICE,dsys_um_service);
	init_scmap();
	for (i=0; i<scmap_scmapsize; i++) {
		int scno=scmap[i].scno;
		setcdtab(scno,dsys_megawrap);
	}
	um_proc_open();
	atexit(um_proc_close);
}
