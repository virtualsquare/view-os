/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   capture_nested.c : capture and divert system calls from modules
 *   
 *   Copyright 2006 Renzo Davoli University of Bologna - Italy
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
#include <assert.h>
#include <config.h>
#include "capture_nested.h"
#include "capture.h"
#include "sctab.h"
#include "scmap.h"
#include "defs.h"
#include "canonicalize.h"
#include "mainpoll.h"

#include "gdebug.h"
//#define _NESTED_CALL_DEBUG_
#ifdef _NESTED_CALL_DEBUG_
#include "syscallnames.h"
#endif

static struct pcb_file umview_file;

/* for modules: nesting select register */
int um_mod_event_subscribe(void (* cb)(), void *arg, int fd, int how)
{
	struct pcb *pc=get_pcb();
	int sercode;
	assert(pc);
	epoch_t epoch=pc->tst.epoch;
	epoch_t nestepoch=pc->tst.epoch=pc->nestepoch;
	int rv;
	//fprint2("um_mod_event_subscribe %p %p %d %d ",cb,arg,fd,how);
	//fprint2("epoch %lld n %lld \n",epoch,nestepoch);
	sercode=service_fd(&umview_file,fd,1);
	//fprint2("service %d \n",sercode);
	if (sercode != UM_NONE) {
		sysfun local_event_subscribe=service_event_subscribe(sercode);
		rv=local_event_subscribe(cb,arg,fd,how);
	} else {
		/*int newhow=0;
		if(how & 1) newhow |= POLLIN;
		if(how & 2) newhow |= POLLOUT;
		if(how & 4) newhow |= POLLPRI;
		struct pollfd pdf={fd,newhow,0};*/
		struct pollfd pdf={fd,how,0};
		rv=poll(&pdf,1,0);
		if (cb) {
			if (rv == 0) 
				mp_add(fd,how,cb,arg,0);
		}else
			mp_del(fd,arg);
		if (rv > 0) 
			rv = pdf.revents ;
		/*
		if (rv > 0) {
			rv=0;
			if (pdf.revents & POLLIN) rv |= 1;
			if (pdf.revents & POLLOUT) rv |= 2;
			if (pdf.revents & POLLPRI) rv |= 4;
		}*/
  }	
	pc->nestepoch = nestepoch;
	pc->tst.epoch = epoch;
	//fprint2("um_mod_event_subscribe -> %d\n",rv);
	return rv;
}

/* convert the path into an absolute path (for nested calls) */
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

/* choice function for nested calls: on the process visible fd */
service_t nchoice_fd(int sc_number,struct npcb *npc)
{
	int fd=npc->sysargs[0];
	//fprint2("nchoice_fd sc %d %d %lld\n",sc_number,fd,npc->tst.epoch);
	return service_fd(&umview_file,fd,1);
}

/* choice function for nested calls: on the private fd */
service_t nchoice_sfd(int sc_number,struct npcb *npc)
{
	int fd=npc->sysargs[0];
	//fprint2("nchoice_sfd sc %d %d %lld\n",sc_number,fd,npc->tst.epoch);
	return service_fd(&umview_file,fd,1);
}

/* choice function for nested calls: on the sc number */
service_t nchoice_sc(int sc_number,struct npcb *npc) {
	  return service_check(CHECKSC,&sc_number,1);
}

/* choice function for nested calls: mount */
service_t nchoice_mount(int sc_number,struct npcb *npc) {
	npc->path=nest_abspath(npc->sysargs[1],npc,&(npc->pathstat),0);
	if(npc->path==um_patherror) 
		return UM_NONE;
	else 
		return service_check(CHECKFSTYPE,(char *)(npc->sysargs[2]),1);
}

/* choice function for nested calls: path (1st arg) */
service_t nchoice_path(int sc_number,struct npcb *npc) {
	//fprint2("nchoice_path %s %lld\n",(char *)(npc->sysargs[0]),npc->tst.epoch);
	npc->path=nest_abspath(npc->sysargs[0],npc,&(npc->pathstat),0);
	//fprint2("nchoice_abspath %s %lld\n",npc->path,npc->tst.epoch);
	if(npc->path==um_patherror)
		return UM_NONE;
	else
		return service_check(CHECKPATH,npc->path,1);
}

/* choice function for nested calls: link (1st arg) */
service_t nchoice_link(int sc_number,struct npcb *npc) {
	//fprint2("nchoice_link %s\n",(char *)(npc->sysargs[0]));
	npc->path=nest_abspath(npc->sysargs[0],npc,&(npc->pathstat),1);
	//fprint2("nchoice_abslink %s\n",npc->path);
	if(npc->path==um_patherror)
		return UM_NONE;
	else
		return service_check(CHECKPATH,npc->path,1);
}

/* choice function for nested calls: link (2nd arg) */
service_t nchoice_link2(int sc_number,struct npcb *npc) {
	npc->path=nest_abspath(npc->sysargs[1],npc,&(npc->pathstat),1);
	if(npc->path==um_patherror)
		return UM_NONE;
	else
		return service_check(CHECKPATH,npc->path,1);
}

/* choice function for nested calls: socket */
service_t nchoice_socket(int sc_number,struct npcb *npc) {
	/* This is the real statement for socket call nesting,
	 * it has been commented out as um_lwipv6 soes not support
	 * multistack and nestine yet. To be restored asap */
	/*return service_check(CHECKSOCKET, &(npc->sysargs[0]),1);*/
	return UM_NONE;
}

/* call the implementation */
int do_nested_call(sysfun um_syscall,unsigned long *args,int n)
{
		return um_syscall(args[0],args[1],args[2],args[3],args[4],args[5]);
}

/* nested wrapper for syscall with a path*/
int nw_syspath_std(int scno,struct npcb *npc,service_t sercode,sysfun um_syscall)
{
	npc->sysargs[0]=(long) npc->path;
	return do_nested_call(um_syscall,&(npc->sysargs[0]),scmap[uscno(scno)].nargs);
}

/* nested wrapper for syscall with a path on the sencond arg*/
int nw_syspath2_std(int scno,struct npcb *npc,service_t sercode,sysfun um_syscall)
{
	npc->sysargs[1]=(long) npc->path;
	return do_nested_call(um_syscall,&(npc->sysargs[0]),scmap[uscno(scno)].nargs);
}

/* nested wrapper for link*/
int nw_syslink(int scno,struct npcb *npc,service_t sercode,sysfun um_syscall)
{
	char *source=nest_abspath(npc->sysargs[0],npc,&(npc->pathstat),0);
	if (npc->path==um_patherror) {
		npc->erno= ENOENT;
		return -1;
	} else {
		npc->sysargs[0]=(long) source;
		npc->sysargs[1]=(long) npc->path;
		return do_nested_call(um_syscall,&(npc->sysargs[0]),scmap[uscno(scno)].nargs);
	}
}

/* nested wrapper for open*/
int nw_sysopen(int scno,struct npcb *npc,service_t sercode,sysfun um_syscall)
{
	int sfd;
	npc->sysargs[0]=(long) npc->path;
	if (scno == __NR_creat) {
		npc->sysargs[2]=npc->sysargs[1];
		npc->sysargs[1]=O_CREAT|O_WRONLY|O_TRUNC;
		scno=__NR_open;
	}
	sfd=do_nested_call(um_syscall,&(npc->sysargs[0]),scmap[uscno(scno)].nargs);
	if (sfd >= 0) {
		int lfd;
		int newfd=r_dup(STDOUT_FILENO); /* fake a file descriptor! */
		lfd=lfd_open(sercode,sfd,NULL,npc->sysargs[2],1);
		lfd_register(&umview_file,newfd,lfd);
		return newfd;
	} else
		return -1;
}

/* nested wrapper for close*/
int nw_sysclose(int scno,struct npcb *npc,service_t sercode,sysfun um_syscall)
{
	int rv;
	int fd=npc->sysargs[0];
	int lfd=fd2lfd(&umview_file,npc->sysargs[0]);
	if (lfd >= 0 && lfd_getcount(lfd) <= 1) { //no more opened lfd on this file:
		npc->sysargs[0]=fd2sfd(&umview_file,fd);
		r_close(fd);
		rv=do_nested_call(um_syscall,&(npc->sysargs[0]),scmap[uscno(scno)].nargs);
		if (rv >= 0) {
			lfd_nullsfd(lfd);
			lfd_deregister_n_close(&umview_file,fd);
		}
		return rv;
	} else
		return -1;
}

/* nested wrapper for dup*/
int nw_sysdup(int scno,struct npcb *npc,service_t sercode,sysfun um_syscall)
{
	int fd=npc->sysargs[0];
	int sfd;
	if (scno==__NR_dup) 
		npc->sysargs[1]=-1;
	scno=__NR_dup2;
	sfd=fd2sfd(&umview_file,npc->sysargs[0]);
	if (sfd < 0 && sercode != UM_NONE) {
		npc->erno=EBADF;
		return -1;
	}else {
		int rv;
		int lfd=fd2lfd(&umview_file,npc->sysargs[0]);
		rv=do_nested_call(um_syscall,&(npc->sysargs[0]),scmap[uscno(scno)].nargs);
		if (rv >= 0) {
			int newfd;
			if (npc->sysargs[1] != -1) {
				lfd_deregister_n_close(&umview_file,npc->sysargs[1]);
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

/* nested wrapper for statfs64*/
int nw_sysstatfs64(int scno,struct npcb *npc,service_t sercode,sysfun um_syscall)
{
	npc->sysargs[0]=(long) npc->path;
	npc->sysargs[1]=npc->sysargs[2]; /* there is an extra arg (size) */
	return do_nested_call(um_syscall,&(npc->sysargs[0]),scmap[uscno(scno)].nargs);
}

/* nested wrapper for fstatfs64*/
int nw_sysfstatfs64(int scno,struct npcb *npc,service_t sercode,sysfun um_syscall)
{
	int fd=npc->sysargs[0];
	npc->sysargs[0]=fd2sfd(&umview_file,fd);
	npc->sysargs[1]=npc->sysargs[2]; /* there is an extra arg (size) */
	return do_nested_call(um_syscall,&(npc->sysargs[0]),scmap[uscno(scno)].nargs);
}

/* nested wrapper for standard system calls using fd*/
int nw_sysfd_std(int scno,struct npcb *npc,service_t sercode,sysfun um_syscall)
{
	int fd=npc->sysargs[0];
	npc->sysargs[0]=fd2sfd(&umview_file,fd);
	return do_nested_call(um_syscall,&(npc->sysargs[0]),scmap[uscno(scno)].nargs);
}

/* nested wrapper for standard socket calls */
int nw_sockfd_std(int scno,struct npcb *npc,service_t sercode,sysfun um_syscall)
{
	int fd=npc->sysargs[0];
	npc->sysargs[0]=fd2sfd(&umview_file,fd);
#if __NR_socketcall != __NR_doesnotexist
	return do_nested_call(um_syscall,&(npc->sysargs[0]),sockmap[scno].nargs);
#else
	return do_nested_call(um_syscall,&(npc->sysargs[0]),scmap[uscno(scno)].nargs);
#endif
}

/* nested wrapper for not supported call */
int nw_notsupp(int scno,struct npcb *npc,service_t sercode,sysfun um_syscall)
{
	npc->erno=EOPNOTSUPP;
	return -1;
}

/* dcif (index) for syscalls */
static int nested_sysindex(struct npcb *npc, int scno)
{
	  return uscno(scno);
}

#if __NR_socketcall != __NR_doesnotexist
/* dcif (index) for sockets */
static int nested_sockindex(struct npcb *npc, int scno)
{
	  //return npc->sysargs[0];
	  return scno;
}
#endif

/* do_kernel_call for syscalls */
static int nested_call_syscall (int sysno, struct npcb *npc)
{
	return native_syscall(sysno, npc->sysargs[0], npc->sysargs[1], npc->sysargs[2],
			      npc->sysargs[3], npc->sysargs[4], npc->sysargs[5]);
}

#if __NR_socketcall != __NR_doesnotexist
/* do_kernel_call for sockets */
static int nested_call_sockcall (int sysno, struct npcb *npc)
{
	return native_syscall(__NR_socketcall,sysno,npc->sysargs);
}
#endif

/* COMMON WRAP FOR NESTED CALLS */
typedef int (*nested_commonwrap_index_function)(struct npcb *pc, int scno);
typedef int (*nested_commonwrap_call_function)(int sysno,struct npcb *pc);
typedef sysfun (*service_call)(service_t code, int scno);
int nested_commonwrap(int sc_number,struct npcb *npc,
		nested_commonwrap_index_function dcif,
		nested_commonwrap_call_function do_kernel_call,
		service_call sc,
		struct sc_map *sm) {
	long rv;
	service_t sercode;
	int index = dcif(npc, sc_number); /* index of the call */
	if (__builtin_expect(npc->tmpfile2unlink_n_free!=NULL,0)) {
		r_unlink(npc->tmpfile2unlink_n_free);
		free(npc->tmpfile2unlink_n_free);
		npc->tmpfile2unlink_n_free=NULL;
	}
	//fprint2("nested_commonwrap %d -> %lld\n",sc_number,npc->tst.epoch);
	sercode=sm[index].nestchoice(sc_number,npc); /* module code */
#ifdef _UM_MMAP
	if (sercode == UM_ERR) {
		fprint2("NESTED BADF!\n");
		errno=EBADF;
		return -1;
	}
	else
#endif
	if (npc->path == um_patherror) {
		errno=npc->erno;
		return -1;
	}
	//fprint2("nested_commonwrap choice %d -> %lld %x\n",sc_number,npc->tst.epoch,sercode);
	if (sercode != UM_NONE /* || (sm[index].flags & ALWAYS) */) {
		/* SUSPEND MGMT? */
		rv=sm[index].nestwrap(sc_number,npc,sercode,sc(sercode,index));
		if (rv<0 && npc->erno > 0)
			errno=npc->erno;
	} else {
		rv=do_kernel_call(sc_number,npc);
	}
	if (npc->path != NULL)
		free(npc->path);
	return rv;
}

/* set the args intp the callee temporary pcb*/
static void nsaveargs(struct pcb *caller,struct npcb *callee,long int sysno){
	callee->flags=0;
	callee->sysscno=sysno;
	callee->erno=0;
	callee->tst=caller->tst;
	callee->tst.epoch=caller->nestepoch;
	callee->nestepoch=callee->tst.epoch;
	pcb_constructor((struct pcb *)callee,0,1);
}

/* restore args (there is nothing to do!) */
static void nrestoreargs(struct pcb *caller,struct npcb *callee){
}

#if __NR_socketcall != __NR_doesnotexist
/* management of module generated socket calls */
static long int capture_nested_socketcall(long int sysno, ...){
	va_list ap;
	register int i;
	register int narg=sockmap[sysno].nargs;
	long rv;
	struct pcb *caller_pcb=get_pcb();
	/* this is a new pcb, the actual pcb for syscall evaluation */
	struct npcb callee_pcb;
	nsaveargs(caller_pcb, &callee_pcb,__NR_socketcall);
	set_pcb(&callee_pcb);
	va_start(ap, sysno);
	for (i=0; i<narg;i++)
		callee_pcb.sysargs[i]=va_arg(ap,long int);
	va_end(ap);
#ifdef _NESTED_CALL_DEBUG_
	fprint2(256,"SkC=%ld - %p %lld %lld- parametri: %p %p %p %p %p %p\n",sysno,get_pcb(),callee_pcb.tst.epoch,callee_pcb.nestepoch,
					(void*)callee_pcb.sysargs[0],
					(void*)callee_pcb.sysargs[1],
					(void*)callee_pcb.sysargs[2],
					(void*)callee_pcb.sysargs[3],
					(void*)callee_pcb.sysargs[4],
					(void*)callee_pcb.sysargs[5]);
#endif
	/* commonwrap for nested socket calls */
	rv=nested_commonwrap(sysno, &callee_pcb, nested_sockindex, nested_call_sockcall, service_socketcall, sockmap);

	nrestoreargs(caller_pcb, &callee_pcb);
	set_pcb(caller_pcb);
#ifdef _NESTED_CALL_DEBUG_
	fprint2(128,"->(Sk) %ld: return value:%ld %p\n",
				sysno,rv,get_pcb());
#endif
	return rv;
}
#endif

/* management of module generated syscalls */
static long int capture_nested_syscall(long int sysno, ...)
{
	va_list ap;
	long rv;
	struct pcb *caller_pcb=get_pcb();
	/* this is a new pcb, the actual pcb for syscall evaluation */
	struct npcb callee_pcb;
	register int i;
	va_start (ap, sysno);
#if 0
	if( caller_pcb == NULL ){
		GERROR("ERROR: not finding a suitable thread syscall %d",sysno);
		errno=ENOSYS;
		return -1;
	}
#endif
	nsaveargs(caller_pcb, &callee_pcb,sysno);
	set_pcb(&callee_pcb);
	for (i=0;i<6;i++){
		if( i < scmap[uscno(sysno)].nargs ) 
			callee_pcb.sysargs[i]=va_arg(ap,long int);
		else
			callee_pcb.sysargs[i]=0;
	}
	va_end(ap);
#ifdef _NESTED_CALL_DEBUG_
		fprint2("SyC=%ld - %s %p %lld %lld- parametri: %x %x %x %x %x %x\n",sysno,SYSCALLNAME(sysno),get_pcb(),callee_pcb.tst.epoch,callee_pcb.nestepoch,
					(void*)callee_pcb.sysargs[0],
					(void*)callee_pcb.sysargs[1],
					(void*)callee_pcb.sysargs[2],
					(void*)callee_pcb.sysargs[3],
					(void*)callee_pcb.sysargs[4],
					(void*)callee_pcb.sysargs[5]);
#endif

	/* commonwrap for nested calls */
	rv=nested_commonwrap(sysno, &callee_pcb, nested_sysindex, nested_call_syscall, service_syscall, scmap);

	nrestoreargs(caller_pcb, &callee_pcb);
	set_pcb(caller_pcb);
#ifdef _NESTED_CALL_DEBUG_
		fprint2("-> %ld - %s: return value:%ld %p\n",
				sysno,SYSCALLNAME(sysno),rv,get_pcb());
#endif
	return rv;
}

/* capture all umview+modules thread creations */
static sysfun libc__clone=(sysfun)clone;

struct clonearg {
	int (*fn) (void *arg);
	void *arg;
	void *parentpcb;
};

/* create a new (reduced) pcb for a thread */
static struct npcb *new_npcb(struct pcb *old)
{
	struct npcb *npcb;
	npcb=calloc(1,sizeof(struct npcb));
	npcb->flags=PCB_ALLOCATED;
	/* inherit the treepoch path from the generating thread */
	npcb->tst=old->tst;
	/* timestamp the new thread with the current time (is it correct?) */
	npcb->tst.epoch=npcb->nestepoch=get_epoch();
	//fprint2("new_npcb %lld\n",npcb->tst.epoch);
	pcb_constructor((struct pcb *)npcb,0,1);
	return npcb;
}

/* thread wrapper */
static int clonewrap(void *carg){
	int (*fn) (void *arg) = ((struct clonearg *)(carg))->fn;
	void *arg=((struct clonearg *)(carg))->arg;
	/* create a new pcb for the new thread, and link the pcb with this new 
	 * thread */
	set_pcb(new_npcb(((struct clonearg *)(carg))->parentpcb));	
	/* free the data structure used to keep the thread info */
	free(carg);
	/* start the real thread */
	return fn(arg);
}

/* clone management */
int __clone (int (*fn) (void *arg), void *child_stack,
		        int flags, void *arg, void *arg2, void *arg3, void *arg4) 
{
	int rv;
	struct clonearg *carg=malloc(sizeof(struct clonearg));
#ifdef _NESTED_CALL_DEBUG_
	GMESSAGE("CLONE\n");
#endif
	carg->fn=fn;
	carg->arg=arg;
	carg->parentpcb=get_pcb();
	/* start a wrapper to the real main function of the thread */
	rv= libc__clone(clonewrap,child_stack,flags,carg,arg2,arg3,arg4);
	return rv;
}

/* capture system call generated by modules, pure_libc initialization */
void capture_nested_init()
{
	sfun (*_pure_start_p)();

	/* thread creation must be traced */
	libc__clone = dlsym (RTLD_NEXT, "__clone");
	/* fake pcb for path management */
	umview_file.count=1;
	umview_file.nolfd=0;
	umview_file.lfdlist=NULL;
	
	/* setting of _pure_syscall and _pure_socketcall, loading 
	 * of native_syscall to bypass the library */
	if ((_pure_start_p=dlsym(RTLD_DEFAULT,"_pure_start")) != NULL) {
		printf("pure_libc library found: syscall tracing allowed\n\n");
#if __NR_socketcall != __NR_doesnotexist
		native_syscall=_pure_start_p(capture_nested_syscall,capture_nested_socketcall,0);
#else
		native_syscall=_pure_start_p(capture_nested_syscall,NULL,0);
#endif
	}
}
