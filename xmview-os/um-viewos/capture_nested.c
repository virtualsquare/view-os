/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   capture_nested.c : capture and divert system calls from modules
 *   
 *   Copyright 2006 Renzo Davoli University of Bologna - Italy
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
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>
#include <stdarg.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <alloca.h>
#include <limits.h>
#include <errno.h>
#include <fcntl.h>
#include "capture_nested.h"
#include "capture_sc.h"
#include "sctab.h"
#include "scmap.h"
#include "defs.h"
#include "canonicalize.h"

#include "syscallnames.h"

#define _NESTED_CALL_DEBUG_

static struct pcb_file umview_file;

typedef long int (*sfun)(long int __sysno, ...);

char *nest_abspath(long laddr,struct npcb *npc,struct stat64 *pst,int dontfollowlink)
{
	char *path=(char*)laddr;
	char newpath[PATH_MAX];
	um_realpath(path,newpath,pst,dontfollowlink,npc);
	if (npc->erno)
		return um_patherror;  //error
	else
		return strdup(newpath);
}

service_t nchoice_fd(int sc_number,struct npcb *npc)
{
	int fd=(sc_number == __NR_socketcall)?npc->args[2]:npc->args[0];
	//fprint2("nchoice_fd %d %lld\n",fd,npc->tst.epoch);
	return service_fd(&umview_file,fd);
}

service_t nchoice_sc(int sc_number,struct npcb *npc) {
	  return service_check(CHECKSC,&sc_number);
}

service_t nchoice_mount(int sc_number,struct npcb *npc) {
	npc->path=nest_abspath(npc->args[1],npc,&(npc->pathstat),0);
	if(npc->path==um_patherror) 
		return UM_NONE;
	else 
		return service_check(CHECKFSTYPE,(char *)(npc->args[2]));
}

service_t nchoice_path(int sc_number,struct npcb *npc) {
	//fprint2("nchoice_path %s %lld\n",(char *)(npc->args[0]),npc->tst.epoch);
	npc->path=nest_abspath(npc->args[0],npc,&(npc->pathstat),0);
	//fprint2("nchoice_abspath %s %lld\n",npc->path,npc->tst.epoch);
	if(npc->path==um_patherror)
		return UM_NONE;
	else
		return service_check(CHECKPATH,npc->path);
}

service_t nchoice_link(int sc_number,struct npcb *npc) {
	//fprint2("nchoice_link %s\n",(char *)(npc->args[0]));
	npc->path=nest_abspath(npc->args[0],npc,&(npc->pathstat),1);
	//fprint2("nchoice_abslink %s\n",npc->path);
	if(npc->path==um_patherror)
		return UM_NONE;
	else
		return service_check(CHECKPATH,npc->path);
}

service_t nchoice_link2(int sc_number,struct npcb *npc) {
	npc->path=nest_abspath(npc->args[1],npc,&(npc->pathstat),1);
	if(npc->path==um_patherror)
		return UM_NONE;
	else
		return service_check(CHECKPATH,npc->path);
}

service_t nchoice_socket(int sc_number,struct npcb *npc) {
	return service_check(CHECKSOCKET, &(npc->args[2]));
}

int do_nested_call(intfun um_syscall,long *args,int n)
{
		return um_syscall(args[0],args[1],args[2],args[3],args[4],args[5]);
}

int nw_syspath_std(int scno,struct npcb *npc,service_t sercode,intfun um_syscall)
{
	npc->args[0]=(long) npc->path;
	return do_nested_call(um_syscall,&(npc->args[0]),scmap[uscno(scno)].nargs);
}

int nw_syspath2_std(int scno,struct npcb *npc,service_t sercode,intfun um_syscall)
{
	npc->args[1]=(long) npc->path;
	return do_nested_call(um_syscall,&(npc->args[0]),scmap[uscno(scno)].nargs);
}

int nw_syslink(int scno,struct npcb *npc,service_t sercode,intfun um_syscall)
{
	char *source=nest_abspath(npc->args[0],npc,&(npc->pathstat),0);
	if (npc->path==um_patherror) {
		npc->erno= ENOENT;
		return -1;
	} else {
		npc->args[0]=(long) source;
		npc->args[1]=(long) npc->path;
		return do_nested_call(um_syscall,&(npc->args[0]),scmap[uscno(scno)].nargs);
	}
}

int nw_sysopen(int scno,struct npcb *npc,service_t sercode,intfun um_syscall)
{
	int sfd;
	npc->args[0]=(long) npc->path;
	if (scno == __NR_creat) {
		npc->args[2]=npc->args[1];
		npc->args[1]=O_CREAT|O_WRONLY|O_TRUNC;
		scno=__NR_open;
	}
	sfd=do_nested_call(um_syscall,&(npc->args[0]),scmap[uscno(scno)].nargs);
	if (sfd >= 0) {
		int lfd;
		int newfd=r_dup(STDOUT_FILENO);
		lfd=lfd_open(sercode,sfd,NULL,1);
		lfd_register(&umview_file,newfd,lfd);
		return newfd;
	} else
		return -1;
}

int nw_sysclose(int scno,struct npcb *npc,service_t sercode,intfun um_syscall)
{
	int rv;
	int fd=npc->args[0];
	int lfd=fd2lfd(&umview_file,npc->args[0]);
	if (lfd >= 0 && lfd_getcount(lfd) <= 1) { //no more opened lfd on this file:
		npc->args[0]=fd2sfd(&umview_file,fd);
		r_close(fd);
		rv=do_nested_call(um_syscall,&(npc->args[0]),scmap[uscno(scno)].nargs);
		if (rv >= 0) {
			lfd_nullsfd(lfd);
			lfd_deregister_n_close(&umview_file,fd);
		}
		return rv;
	} else
		return -1;
}

int nw_sysdup(int scno,struct npcb *npc,service_t sercode,intfun um_syscall)
{
	int fd=npc->args[0];
	int sfd;
	if (scno==__NR_dup) 
		npc->args[1]=-1;
	scno=__NR_dup2;
	sfd=fd2sfd(&umview_file,npc->args[0]);
	if (sfd < 0 && sercode != UM_NONE) {
		npc->erno=EBADF;
		return -1;
	}else {
		int rv;
		int lfd=fd2lfd(&umview_file,npc->args[0]);
		rv=do_nested_call(um_syscall,&(npc->args[0]),scmap[uscno(scno)].nargs);
		if (rv >= 0) {
			int newfd;
			if (npc->args[1] != -1) {
				lfd_deregister_n_close(&umview_file,npc->args[1]);
				newfd=fd;
			}
			else
				newfd=r_dup(fd);
			lfd_dup(lfd);
			lfd_register(&umview_file,newfd,lfd);
			return newfd;
		} else
			return -1;
	}
}

int nw_sysfd_std(int scno,struct npcb *npc,service_t sercode,intfun um_syscall)
{
	int fd=npc->args[0];
	npc->args[0]=fd2sfd(&umview_file,fd);
	int rv;
	rv=do_nested_call(um_syscall,&(npc->args[0]),scmap[uscno(scno)].nargs);
	return rv;
}

int nw_sockfd_std(int scno,struct npcb *npc,service_t sercode,intfun um_syscall)
{
	int fd=npc->args[2];
	npc->args[2]=fd2sfd(&umview_file,fd);
	return do_nested_call(um_syscall,&(npc->args[0]),sockmap[scno].nargs);
}

int nw_notsupp(int scno,struct npcb *npc,service_t sercode,intfun um_syscall)
{
	npc->erno=EOPNOTSUPP;
	return -1;
}

static int nested_sysindex(struct npcb *npc, int usc)
{
	  return usc;
}

static int nested_sockindex(struct npcb *npc, int usc)
{
	  return npc->args[2];
}

static int nested_call_syscall (int sysno, struct npcb *npc)
{
	return syscall(sysno, npc->args[0], npc->args[1], npc->args[2],
			      npc->args[3], npc->args[4], npc->args[5]);
}

static int nested_call_sockcall (int sysno, struct npcb *npc)
{
	return syscall(__NR_socketcall,sysno,&(npc->args[2]));
}

typedef int (*nested_commonwrap_index_function)(struct npcb *pc, int usc);
typedef int (*nested_commonwrap_call_function)(int sysno,struct npcb *pc);
typedef intfun (*service_call)(service_t code, int scno);
int nested_commonwrap(int sc_number,struct npcb *npc,
		nested_commonwrap_index_function dcif,
		nested_commonwrap_call_function do_kernel_call,
		service_call sc,
		struct sc_map *sm) {
	int usc=uscno(sc_number);
	long rv;
	service_t sercode;
	int index = dcif(npc, usc);
	//fprint2("nested_commonwrap %d -> %lld\n",sc_number,npc->tst.epoch);
	sercode=sm[index].nestchoice(sc_number,npc);
	if (npc->path == um_patherror) {
		errno=npc->erno;
		return -1;
	}
	//fprint2("nested_commonwrap choice %d -> %lld %x\n",sc_number,npc->tst.epoch,sercode);
	if (sercode != UM_NONE /* || (sm[usc].flags & ALWAYS) */) {
		/* SUSPEND MGMT? */
		rv=sm[index].nestwrap(sc_number,npc,sercode,sc(sercode,index));
		if (rv<0 && npc->erno > 0)
			errno=npc->erno;
	} else
		rv=do_kernel_call(sc_number,npc);
	if (npc->path != NULL)
		free(npc->path);
	return rv;
}

static void nsaveargs(struct pcb *caller,struct npcb *callee,long int sysno){
	callee->flags=0;
	callee->scno=sysno;
	callee->path=NULL;
	callee->erno=0;
	if ((caller->flags & PCB_INUSE) == 0) {
		struct npcb *ncaller=(struct npcb *)caller;
		callee->tst=ncaller->tst;
		callee->tst.epoch=ncaller->nestepoch;
  } else {
		struct pcb_ext *npc=(struct pcb_ext *)caller->data;
		callee->tst=npc->tst;
		callee->tst.epoch=npc->nestepoch;
	}
}

static void nrestoreargs(struct pcb *caller,struct npcb *callee){
}

static long int capture_nested_socketcall(long int sysno, ...){
	va_list ap;
	register int i;
	register int narg=sockmap[sysno].nargs;
	long rv;
	struct pcb *caller_pcb=get_pcb();
	struct npcb callee_pcb;
	nsaveargs(caller_pcb, &callee_pcb,__NR_socketcall);
	set_pcb(&callee_pcb);
#ifdef _NESTED_CALL_DEBUG_
	{
		static char buf[128];
		snprintf(buf,128,"SkC=%ld\n",sysno);
		syscall(__NR_write,2,buf,strlen(buf));
	}
#endif
	callee_pcb.args[0]=sysno;
	callee_pcb.args[1]=(long) &(callee_pcb.args[2]);
	va_start(ap, sysno);
	for (i=0; i<narg;i++)
		callee_pcb.args[2+i]=va_arg(ap,long int);
	va_end(ap);
	rv=nested_commonwrap(sysno, &callee_pcb, nested_sockindex, nested_call_sockcall, service_socketcall, sockmap);
	/*rv=syscall(__NR_socketcall,sysno,&(callee_pcb.args[2]));*/
	nrestoreargs(caller_pcb, &callee_pcb);
	set_pcb(caller_pcb);
	return rv;
}

static long int capture_nested_syscall(long int sysno, ...)
{
	va_list ap;
	va_start (ap, sysno);
	long rv;
	struct pcb *caller_pcb=get_pcb();
	struct npcb callee_pcb;
	register int i;
	nsaveargs(caller_pcb, &callee_pcb,sysno);
	set_pcb(&callee_pcb);
	for (i=0;i<6;i++){
		if( i < scmap[uscno(sysno)].nargs ) 
			callee_pcb.args[i]=va_arg(ap,long int);
		else
			callee_pcb.args[i]=0;
	}
	va_end(ap);
#ifdef _NESTED_CALL_DEBUG_
	{
		static char buf[256];
		snprintf(buf,256,"SyC=%ld - %s %p - parametri: %p %p %p %p %p %p\n",sysno,SYSCALLNAME(sysno),get_pcb(),
					callee_pcb.args[0],
					callee_pcb.args[1],
					callee_pcb.args[2],
					callee_pcb.args[3],
					callee_pcb.args[4],
					callee_pcb.args[5]);
		syscall(__NR_write,2,buf,strlen(buf));
	}
#endif

	rv=nested_commonwrap(sysno, &callee_pcb, nested_sysindex, nested_call_syscall, service_syscall, scmap);
	/*rv=syscall(sysno, callee_pcb.args[0], callee_pcb.args[1], callee_pcb.args[2],
			callee_pcb.args[3], callee_pcb.args[4], callee_pcb.args[5]);*/
	nrestoreargs(caller_pcb, &callee_pcb);
	set_pcb(caller_pcb);
#ifdef _NESTED_CALL_DEBUG_
	{
		static char buf[128];
		snprintf(buf,128,"Nested: return value:%ld %p\n",rv,get_pcb());
		syscall(__NR_write,2,buf,strlen(buf));
	}
#endif
	return rv;
}

/* capture all umview+modules thread creations */
#if defined(__i386__) || defined(__powerpc__)
static intfun libc__clone=clone;
#elif defined(__x86_64)
static intfun libc__clone=clone2;
#endif

struct clonearg {
	int (*fn) (void *arg);
	void *arg;
	void *parentpcb;
};

static struct npcb *new_npcb(struct pcb *old)
{
	struct npcb *npcb;
	npcb=calloc(1,sizeof(struct npcb));
	npcb->flags=PCB_ALLOCATED;
	if ((old->flags & PCB_INUSE) == 0) {
		struct npcb *nold=(struct npcb *)old;
		npcb->tst=nold->tst;
  } else {
		struct pcb_ext *pcdata=(struct pcb_ext *)old->data;
		npcb->tst=pcdata->tst;
	}
	npcb->tst.epoch=npcb->nestepoch=get_epoch();
	//fprint2("new_npcb %lld\n",npcb->tst.epoch);
	return npcb;
}

static int clonewrap(void *carg){
	int (*fn) (void *arg) = ((struct clonearg *)(carg))->fn;
	void *arg=((struct clonearg *)(carg))->arg;
	set_pcb(new_npcb(((struct clonearg *)(carg))->parentpcb));	
	free(carg);
	return fn(arg);
}

#if defined(__i386__) || defined(__powerpc__)
int __clone (int (*fn) (void *arg), void *child_stack,
		        int flags, void *arg, void *arg2, void *arg3, void *arg4) 
#elif defined(__x86_64__)
int __clone2 (int (*fn) (void *arg), void *child_stack_base,
		size_t child_stack_size, int flags, void *arg, void *arg2, void *arg3, void *arg4)
#else
#error Unsupported HW Architecure
#endif
{
	int rv;
	struct clonearg *carg=malloc(sizeof(struct clonearg));
#ifdef _NESTED_CALL_DEBUG_
	fprint2("CLONE\n");
#endif
	carg->fn=fn;
	carg->arg=arg;
	carg->parentpcb=get_pcb();
#if defined(__i386__) || defined(__powerpc__)
	rv= libc__clone(clonewrap,child_stack,flags,carg,arg2,arg3,arg4);

#elif defined(__x86_64__)
	rv= libc__clone(fn,clonewrap,child_stack_size,flags,carg,arg2,arg3,arg4);
#endif
	return rv;
}

void capture_nested_init()
{
	sfun *_pure_syscall;
	sfun *_pure_socketcall;
#if defined(__i386__) || defined(__powerpc__)
	libc__clone = dlsym (RTLD_NEXT, "__clone");
#elif defined(__x86_64__)
	libc__clone = dlsym (RTLD_NEXT, "__clone2");
#endif
	umview_file.count=1;
	umview_file.nolfd=0;
	umview_file.lfdlist=NULL;
	if ((_pure_syscall=dlsym(RTLD_DEFAULT,"_pure_syscall")) != NULL) {
		fprintf(stderr, "pure_libc library found: module nesting allowed\n\n");
		*_pure_syscall=capture_nested_syscall;
	}
	if ((_pure_socketcall=dlsym(RTLD_DEFAULT,"_pure_socketcall")) != NULL) {
		*_pure_socketcall=capture_nested_socketcall;
	}
}


