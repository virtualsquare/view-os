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
#include "hashtab.h"
#include "um_services.h"
#include "sctab.h"
#include "scmap.h"
#include "utils.h"
#include "canonicalize.h"

#define BINFMTBUFLEN 128
#define HT_SCRIPT ((struct ht_elem *) 1)
#define STDINTERP "/bin/bash"

/* filecopy creates a copy of the executable inside the tmp file dir */
static int filecopy(struct ht_elem *hte,const char *from, const char *to)
{
	char buf[BUFSIZ];
	int fdf,fdt;
	int n;
	/* NO need for hte search. from is the path so hte and private data
		 is already set for modules */
	if ((fdf=ht_syscall(hte,uscno(__NR_open))(from,O_RDONLY,0)) < 0)
		return -errno;
	if ((fdt=open(to,O_CREAT|O_TRUNC|O_WRONLY,0600)) < 0)
		return -errno;
	while ((n=ht_syscall(hte,uscno(__NR_read))(fdf,buf,BUFSIZ)) > 0)
		r_write (fdt,buf,n);
	ht_syscall(hte,uscno(__NR_close))(fdf);
	fchmod (fdt,0700); /* permissions? */
	close (fdt);
	return 0;
}

/* is the executable a script? */
static struct ht_elem *checkscript(struct ht_elem *hte,struct binfmt_req *req)
{
	char *scriptbuf=req->buf;
	/* this should include ELF, COFF and a.out */
	if (scriptbuf[0] < '\n' || scriptbuf[0] == '\177')
		return NULL;
	else if (scriptbuf[0]=='#' && scriptbuf[1]=='!') {
		/* parse the first line */
		char *s=scriptbuf+2;
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
		return HT_SCRIPT;
	}
	else {
		/* heuristics here */
		return NULL;
	}
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
		assert(rv>=0);
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
	printk("%s\n",what);
	while (*parms != 0) {
		printk("--> %s\n",*parms);
		parms++;
	}
}
*/

#define UMBINWRAP LIBEXECDIR "/umbinwrap"
/* wrap_in: execve handling */
int wrap_in_execve(int sc_number,struct pcb *pc,
		struct ht_elem *hte,sysfun um_syscall)
{
	char buf[BINFMTBUFLEN+1];
	struct binfmt_req req={(char *)pc->path,NULL,NULL,buf,0};
	epoch_t nestepoch=um_setnestepoch(0);
	struct ht_elem *binfmtht;
	if (um_xx_access(req.path,X_OK,pc)!=0) {
		pc->erno=errno;
		pc->retval=-1;
		return SC_FAKE;
	}
	/* management of set[ug]id executables */
	if (pc->pathstat.st_mode & S_ISUID) {
		pc->suid=pc->euid;
		pc->euid=pc->fsuid=pc->pathstat.st_uid;
	} else if (pc->ruid == pc->euid)
		pc->suid=pc->ruid;
	if (pc->pathstat.st_mode & S_ISGID) {
		pc->sgid=pc->egid;
		pc->egid=pc->fsgid=pc->pathstat.st_gid;
	} else if (pc->rgid == pc->egid)
		pc->sgid=pc->rgid;
	if (strcmp(pc->path,"/bin/mount") == 0 || 
		strcmp(pc->path,"/bin/umount") == 0) {
		pc->suid=pc->euid;
		pc->ruid=pc->suid=0;
	}
	/* The epoch should be just after the mount 
	 * which generated the executable */
	um_setnestepoch(nestepoch+1);
	memset(buf,0,BINFMTBUFLEN+1);
	int fd=open(req.path,O_RDONLY);
	if (fd >= 0) {
		read(fd, buf, BINFMTBUFLEN);
		close(fd);
	}
	binfmtht=checkscript(hte,&req);
	if (binfmtht == NULL) 
		binfmtht=ht_check(CHECKBINFMT,&req,NULL,0);
	//printk("wrap_in_execve %s |%s| |%s|\n",ht_get_servicename(binfmtht),req.interp,req.extraarg);
	um_setnestepoch(nestepoch);
	/* is there a binfmt service for this executable? */
	if (binfmtht != NULL) {
		char *umbinfmtarg0;
		int sep;
		long largv=pc->sysargs[1];
		long larg0;
		char oldarg0[PATH_MAX+1];
		int rv;
		int filenamelen;
		int arg0len;
		long sp=getsp(pc);
		char *chrootpath=pc->path;
		if (*(req.interp) != '/') { /* full pathname required */
			pc->erno=ENOENT;
			pc->retval=-1;
			return SC_FAKE;
		}
		/* strip the root path when running in a chroot environment */
		if (pc->fdfs->root[1] != 0) {
			int len=strlen(pc->fdfs->root);
			if (strncmp(chrootpath,pc->fdfs->root,len)==0)
				chrootpath+=len;
		}
		/* create the argv for the wrapper! */
		rv=umoven(pc,largv,sizeof(char *),&(larg0));
		//printk("%s %d %ld %ld rv=%d\n",chrootpath,getpc(pc),largv,larg0,rv); 
		/* XXX this is a workaround. strace has the same error!
		 * exec seems to cause an extra prace in a strange address space
		 * to be solved (maybe using PTRACE OPTIONS!) */
		//assert(rv);
		if (rv<0) return STD_BEHAVIOR;
		if (req.flags & BINFMT_KEEP_ARG0) {
			oldarg0[PATH_MAX]=0;
			umovestr(pc,larg0,PATH_MAX,oldarg0);
		} else
			oldarg0[0]=0;
		/* search for an unused char to act as arg separator */
		for (sep=1;sep<255 && 
				(strchr((char *)chrootpath,sep)!=NULL ||
				 strchr(req.interp,sep)!=NULL ||
				 strchr(oldarg0,sep)!=NULL);
				sep++)
			;
		if (req.extraarg==NULL)
			req.extraarg="";
#ifndef NOUMBINWRAP
		/* collapse all the args in only one arg */
		if (req.flags & BINFMT_KEEP_ARG0) 
			asprintf(&umbinfmtarg0,"%c%s%c%s%c%s%c%s",
					sep,req.interp,
					sep,req.extraarg,
					sep,(char *)chrootpath,
					sep,oldarg0);
		else 
			asprintf(&umbinfmtarg0,"%c%s%c%s%c%s",
					sep,req.interp,
					sep,req.extraarg,
					sep,(char *)chrootpath);
		filenamelen=WORDALIGN(strlen(UMBINWRAP));
		arg0len=WORDALIGN(strlen(umbinfmtarg0));
		pc->retval=0;
		ustorestr(pc,sp-filenamelen,filenamelen,UMBINWRAP);
		pc->sysargs[0]=sp-filenamelen;
		larg0=sp-filenamelen-arg0len;
		ustoren(pc,larg0,arg0len,umbinfmtarg0);
		ustoren(pc,largv,sizeof(char *),&larg0);
		//printk("%s %s\n",UMBINWRAP,umbinfmtarg0);
		/* exec the wrapper instead of the executable! */
		free(umbinfmtarg0);
#endif
		if (req.flags & BINFMT_MODULE_ALLOC)
			free(req.interp);
		return SC_CALLONXIT;
	}
	else if (hte != NULL) {
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
			//printk("wrap_in_execve! %s %p %d\n",(char *)pc->path,um_syscall,isnosys(um_syscall));

			/* copy the file and change the first arg of execve to 
			 * address the copy */
			if ((pc->retval=filecopy(hte,pc->path,filename))>=0) {
				um_x_rewritepath(pc,filename,0,0);
				/* remember to clean up the copy as soon as possible */
				pc->tmpfile2unlink_n_free=filename;
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
		if (__builtin_expect(pc->needs_path_rewrite,0)) {
			um_x_rewritepath(pc,pc->path,0,0);
			return SC_CALLONXIT;
		} else
			return STD_BEHAVIOR;
}


int wrap_out_execve(int sc_number,struct pcb *pc) 
{ 
	/* If this function is executed it means that something went wrong! */
	//printk("wrap_out_execve %d\n",pc->retval);
	/* The tmp file gets automagically deleted (see sctab.c) */
	if (pc->retval < 0) {
		pc->euid=pc->fsuid=pc->suid;
		pc->egid=pc->fsgid=pc->sgid;
		putrv(pc->retval,pc);
		puterrno(pc->erno,pc);
		return SC_MODICALL;
	} else
		return STD_BEHAVIOR;
}
