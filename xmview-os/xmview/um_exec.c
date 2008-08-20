/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   um_exec: support for virtual executables and binfmt services
 *   
 *   Copyright 2005 Renzo Davoli University of Bologna - Italy
 *   Modified 2005 Ludovico Gardenghi
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
#include <config.h>
#include "defs.h"
#include "gdebug.h"
#include "umproc.h"
#include "services.h"
#include "um_services.h"
#include "sctab.h"
#include "scmap.h"
#include "utils.h"
#include "canonicalize.h"

#define SCRIPTBUFLEN 128
#define UM_SCRIPT UM_ERR /*we use UM_ERR to say UM_SCRIPT */
#define STDINTERP "/bin/bash"

/* filecopy creates a copy of the executable inside the tmp file dir */
static int filecopy(service_t sercode,const char *from, const char *to)
{
	char buf[BUFSIZ];
	int fdf,fdt;
	int n;
	if ((fdf=service_syscall(sercode,uscno(__NR_open))(from,O_RDONLY,0)) < 0)
		return -errno;
	if ((fdt=open(to,O_CREAT|O_TRUNC|O_WRONLY,0600)) < 0)
		return -errno;
	while ((n=service_syscall(sercode,uscno(__NR_read))(fdf,buf,BUFSIZ)) > 0)
		r_write (fdt,buf,n);
	service_syscall(sercode,uscno(__NR_close))(fdf);
	fchmod (fdt,0700); /* permissions? */
	close (fdt);
	return 0;
}

/* is the executable a script? */
static int checkscript(service_t sercode,struct binfmt_req *req,char *scriptbuf)
{
	int fd,n;
	if (sercode == UM_NONE) {
		if ((fd=open(req->path,O_RDONLY,0)) < 0)
			return UM_NONE;
		n=read(fd,scriptbuf,SCRIPTBUFLEN-1);
		close(fd);
	} else {
		if ((fd=service_syscall(sercode,uscno(__NR_open))(req->path,O_RDONLY,0)) < 0)
			return UM_NONE;
		n=service_syscall(sercode,uscno(__NR_read))(fd,scriptbuf,SCRIPTBUFLEN-1);
		service_syscall(sercode,uscno(__NR_close))(fd);
	}
	if (n>1) {
		/* this should include ELF, COFF and a.out */
		if (scriptbuf[0] < '\n' || scriptbuf[0] == '\177')
			return UM_NONE;
		else if (scriptbuf[0]=='#' && scriptbuf[1]=='!') {
			/* parse the first line */
			char *s=scriptbuf+2;
			scriptbuf[n]=0;
			/* skip leading spaces */
			while(*s == ' ' || *s == '\t')
				s++;
			/* the first non blank is the interpreter */
			req->interp=s; 
			while(*s != ' ' && *s != '\t' && *s != '\n' && *s!=0)
				s++;
			if (*s == 0 || *s=='\n') 
				*s=0;
			else {
				*s++ = 0;
				while(*s == ' ' || *s == '\t')
					*s++ = 0;
				req->extraarg=s;
				while(*s != '\n' && *s!=0)
					s++;
				while(*(s-1)==' ' || *(s-1)=='\t')
					s--;
				*s=0;
				if (*(req->extraarg)==0)
					req->extraarg=NULL;
			}
			if (*(req->interp)==0)
				req->interp=STDINTERP;
			return UM_SCRIPT;
		}
		else {
			/* heuristics here */
			return UM_NONE;
		}
	}
	return UM_NONE;
}

/* getparms (argv) from the user space */
#define CHUNKSIZE 16
static char **getparms(struct pcb *pc,long laddr) {
	long *paddr=NULL;
	char **parms;
	int size=0;
	int n=0;
	int i;
	do {
		int rv;
		if (n >= size) {
			size+=CHUNKSIZE;
			paddr=realloc(paddr,size*sizeof(long));
			assert(paddr);
		}
		rv=umoven(pc,laddr,sizeof(char *),&(paddr[n]));
		assert(rv=4);
		laddr+= sizeof(char *);
		n++;
	} while (paddr[n-1] != 0);
	parms=malloc(n*sizeof(char *));
	assert(parms);
	parms[n-1]=NULL;
	for (i=0;i<n-1;i++) {
		char tmparg[PATH_MAX+1];
		tmparg[PATH_MAX]=0;
		umovestr(pc,paddr[i],PATH_MAX,tmparg);
		parms[i]=strdup(tmparg);
	}
	free(paddr);
	return parms;
}

/* freeparms: free the mem allocated for parms */
static void freeparms(char **parms)
{
	char **scan=parms;
	while (*scan != 0) {
		free(*scan);
		scan++;
	}
	free(parms);
}

/*
static void printparms(char *what,char **parms)
{
	fprint2("%s\n",what);
	while (*parms != 0) {
		fprint2("--> %s\n",*parms);
		parms++;
	}
}
*/

static int is_regular(char *path,struct pcb *pc)
{
	char newpath[PATH_MAX];
	struct stat64 st;
	um_realpath(path,"/",newpath,&st,0,pc);
	if (S_ISREG(st.st_mode))
		return 1;
	else {
		if (st.st_mode==0) 
			pc->erno=ENOENT;
		else
			pc->erno=EACCES;
		return 0;
	}
}

#define UMBINWRAP LIBEXECDIR "/umbinwrap"
/* WIP XXX try to run scripts and interpreters without UMBINWRAP */
#undef NOUMBINWRAP
/* wrap_in: execve handling */
int wrap_in_execve(int sc_number,struct pcb *pc,
		service_t sercode,sysfun um_syscall)
{
	struct binfmt_req req={(char *)pc->path,NULL,NULL,0};
	char scriptbuf[SCRIPTBUFLEN];
	epoch_t nestepoch=um_setepoch(0);
	service_t binfmtser;
	if (um_x_access(req.path,X_OK,pc)!=0) {
		pc->erno=errno;
		pc->retval=-1;
		return SC_FAKE;
	}
	/* The epoch should be just after the mount 
	 * which generated the executable */
	um_setepoch(nestepoch+1);
	binfmtser=checkscript(sercode,&req,scriptbuf);
	if (binfmtser == UM_NONE)
		binfmtser=service_check(CHECKBINFMT,&req,0);
	//fprint2("wrap_in_execve %x |%s| |%s|\n",binfmtser,req.interp,req.extraarg);
	um_setepoch(nestepoch);
	/* is there a binfmt service for this executable? */
	if (binfmtser != UM_NONE) {
		char *umbinfmtarg0;
		int sep;
		long largv=pc->sysargs[1];
		long larg0;
		char oldarg0[PATH_MAX+1];
		int rv;
		int filenamelen;
		int arg0len;
		long sp=getsp(pc);
		if (*(req.interp) != '/') { /* full pathname required */
			pc->erno=ENOENT;
			pc->retval=-1;
			return SC_FAKE;
		}
#ifndef NOUMBINWRAP
		if (!is_regular(req.interp,pc)) {
			pc->retval=-1;
			return SC_FAKE;
		}
		if (um_x_access(req.interp,X_OK,pc)!=0) {
			pc->erno=errno;
			pc->retval=-1;
			return SC_FAKE;
		}
#endif
		/* create the argv for the wrapper! */
		rv=umoven(pc,largv,sizeof(char *),&(larg0));
		//fprint2("%s %d %ld %ld rv=%d\n",pc->path,getpc(pc),largv,larg0,rv); 
		/* XXX this is a workaround. strace has the same error!
		 * exec seems to cause an extra prace in a strange address space
		 * to be solved (maybe using PTRACE OPTIONS!) */
		//assert(rv);
		if (!rv) return STD_BEHAVIOR;
		if (req.flags & BINFMT_KEEP_ARG0) {
			oldarg0[PATH_MAX]=0;
			umovestr(pc,larg0,PATH_MAX,oldarg0);
		} else
			oldarg0[0]=0;
		/* search for an unused char to act as arg separator */
		for (sep=1;sep<255 && 
				(strchr((char *)pc->path,sep)!=NULL ||
				 strchr(req.interp,sep)!=NULL ||
				 strchr(oldarg0,sep)!=NULL);
				sep++)
			;
		if (req.extraarg==NULL)
			req.extraarg="";
#ifdef NOUMBINWRAP
#else
		/* collapse all the args in only one arg */
		if (req.flags & BINFMT_KEEP_ARG0) 
			asprintf(&umbinfmtarg0,"%c%s%c%s%c%s%c%s",
					sep,req.interp,
					sep,req.extraarg,
					sep,(char *)pc->path,
					sep,oldarg0);
		else 
			asprintf(&umbinfmtarg0,"%c%s%c%s%c%s",
					sep,req.interp,
					sep,req.extraarg,
					sep,(char *)pc->path);
		filenamelen=WORDALIGN(strlen(UMBINWRAP));
		arg0len=WORDALIGN(strlen(umbinfmtarg0));
		pc->retval=0;
		ustorestr(pc,sp-filenamelen,filenamelen,UMBINWRAP);
		pc->sysargs[0]=sp-filenamelen;
		larg0=sp-filenamelen-arg0len;
		ustoren(pc,larg0,arg0len,umbinfmtarg0);
		ustoren(pc,largv,sizeof(char *),&larg0);
		//fprint2("%s %s\n",UMBINWRAP,umbinfmtarg0);
		/* exec the wrapper instead of the executable! */
		free(umbinfmtarg0);
#endif
		if (req.flags & BINFMT_MODULE_ALLOC)
			free(req.interp);
		return SC_CALLONXIT;
	}
	else if (sercode != UM_NONE) {
		pc->retval=ERESTARTSYS;
		/* does the module define a semantics for execve? */
		if (!isnosys(um_syscall)) {
			long largv=pc->sysargs[1];
			long lenv=pc->sysargs[2];
			char **argv=getparms(pc,largv);
			char **env=getparms(pc,lenv);
			/*printparms("ARGV",argv);
				printparms("ENV",env);*/
			/* call the module's execve implementation */
			if ((pc->retval=um_syscall(pc->path,argv,env)) < 0)
				pc->erno=errno;
			freeparms(argv);
			freeparms(env);
		}
		/* Either no execve implementation in the module, or the module decided
		 * to require the real execve */
		if (pc->retval==ERESTARTSYS){
			char *filename=strdup(um_proc_tmpname());
			//fprint2("wrap_in_execve! %s %p %d\n",(char *)pc->path,um_syscall,isnosys(um_syscall));

			/* copy the file and change the first arg of execve to 
			 * address the copy */
			if ((pc->retval=filecopy(sercode,pc->path,filename))>=0) {
				long sp=getsp(pc);
				int filenamelen=WORDALIGN(strlen(filename));
				pc->retval=0;
				/* remember to clean up the copy as soon as possible */
				pc->tmpfile2unlink_n_free=filename;
				ustoren(pc,sp-filenamelen,filenamelen,filename);
				pc->sysargs[0]=sp-filenamelen;
				return SC_CALLONXIT;
			} else {
				/* something went wrong during the copy */
				free(filename);
				pc->erno= -(pc->retval);
				pc->retval= -1;
				return SC_FAKE;
			}
		} else 
			return SC_FAKE;
	} else 
		return STD_BEHAVIOR;
}


int wrap_out_execve(int sc_number,struct pcb *pc) 
{ 
	/* If this function is executed it means that something went wrong! */
	//fprint2("wrap_out_execve %d\n",pc->retval);
	/* The tmp file gets automagically deleted (see sctab.c) */
	if (pc->retval < 0) {
		putrv(pc->retval,pc);
		puterrno(pc->erno,pc);
		return SC_MODICALL;
	} else
		return STD_BEHAVIOR;
}
