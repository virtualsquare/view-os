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
#include <linux/net.h>
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
#include "hashtab.h"


#define SOCK_DEFAULT 0

#include "gdebug.h"
//#define _NESTED_CALL_DEBUG_
#ifdef _NESTED_CALL_DEBUG_
#include "syscallnames.h"
#endif

static int nested_call_syscall (int sysno, struct npcb *npc);
#if __NR_socketcall != __NR_doesnotexist
static int nested_call_sockcall (int sysno, struct npcb *npc);
#endif
static int nested_call_virsc (int sysno, struct npcb *npc);

static struct pcb_file umview_file;

/* for modules: nesting select register */
int um_mod_event_subscribe(void (* cb)(), void *arg, int fd, int how)
{
	struct pcb *pc=get_pcb();
	struct ht_elem *hte;
	assert(pc);
	epoch_t epoch=pc->tst.epoch;
	epoch_t nestepoch=pc->tst.epoch=pc->nestepoch;
	int rv;
	//printk("um_mod_event_subscribe %p %p %d %d ",cb,arg,fd,how);
	//printk("epoch %lld n %lld \n",epoch,nestepoch);
	pc->hte=hte=ht_fd(&umview_file,fd,1);
	//printk("service %p \n",hte);
	if (hte != NULL) {
		int sfd=fd2sfd(&umview_file,fd);
		sysfun local_event_subscribe=ht_event_subscribe(hte);
		if(local_event_subscribe != NULL) 
			rv=local_event_subscribe(cb,arg,sfd,how);
		else
			rv=how;
	} else {
		struct pollfd pdf={fd,how,0};
		rv=poll(&pdf,1,0);
		if (cb) {
			if (rv == 0) 
				mp_add(fd,how,cb,arg,0);
		}else
			mp_del(fd,arg);
		if (rv > 0) 
			rv = pdf.revents ;
  }	
	pc->nestepoch = nestepoch;
	pc->tst.epoch = epoch;
	//printk("um_mod_event_subscribe -> %d\n",rv);
	return rv;
}

/* convert the path into an absolute path (for nested calls) */
static char *nest_abspath(int dirfd, long laddr,struct npcb *npc,struct stat64 *pst,int dontfollowlink)
{
	char *path=(char*)laddr;
	char newpath[PATH_MAX];
	/* modules/thread call should refer to absolute paths.
	 * management of cwd is missing and should be carefully 
	 * studied 
	 * if (dirfd==AT_FDCWD)
	 * 	cwd= ...cwd...
	 * else
	 *  cwd= ...path of dirfd... 
	 */
	npc->hte=NULL;
	um_realpath(path,NULL,newpath,pst,dontfollowlink,npc);
	if (npc->erno)
		return um_patherror;  //error
	else
		return strdup(newpath);
}

/* choice function for nested calls: on the process visible fd */
struct ht_elem * nchoice_fd(int sc_number,struct npcb *npc)
{
	int fd=npc->sysargs[0];
	//printk("nchoice_fd sc %d %d %lld %p\n",sc_number,fd,npc->tst.epoch,ht_fd(&umview_file,fd,1));
	return ht_fd(&umview_file,fd,1);
}

/* choice function for nested calls: on the private fd */
struct ht_elem * nchoice_sfd(int sc_number,struct npcb *npc)
{
	int fd=npc->sysargs[0];
	//printk("nchoice_sfd sc %d %d %lld\n",sc_number,fd,npc->tst.epoch);
	return ht_fd(&umview_file,fd,1);
}

/* choice function for nested calls: on the sc number */
struct ht_elem * nchoice_sc(int sc_number,struct npcb *npc) {
	return ht_check(CHECKSC,&sc_number,NULL,1);
}

/* choice function for nested calls: mount */
/* currently unused */
struct ht_elem * nchoice_mount(int sc_number,struct npcb *npc) {
	npc->path=nest_abspath(AT_FDCWD,npc->sysargs[1],npc,&(npc->pathstat),0);
	if(npc->path==um_patherror) 
		return NULL;
	else
		return ht_check(CHECKFSTYPE,(char *)(npc->sysargs[2]),NULL,1);
}

/* choice function for nested calls: path (1st arg) */
struct ht_elem * nchoice_path(int sc_number,struct npcb *npc) {
	//printk("nchoice_path %s %lld\n",(char *)(npc->sysargs[0]),npc->tst.epoch);
	npc->path=nest_abspath(AT_FDCWD,npc->sysargs[0],npc,&(npc->pathstat),0);
	//printk("nchoice_abspath %s %lld\n",npc->path,npc->tst.epoch);
	if(npc->path==um_patherror)
		return NULL;
	else
		return ht_check(CHECKPATH,npc->path,&(npc->pathstat),1);
}

/* choice function for nested calls: dirfd/path (1st,2nd arg) */
struct ht_elem * nchoice_pathat(int sc_number,struct npcb *npc) {
	npc->path=nest_abspath(npc->sysargs[0],npc->sysargs[1],npc,&(npc->pathstat),0);
	if(npc->path==um_patherror)
		return NULL;
	else
		return ht_check(CHECKPATH,npc->path,&(npc->pathstat),1);
}

/* choice function for nested msocket calls: path (1st arg) */
struct ht_elem * nchoice_sockpath(int sc_number,struct npcb *npc) {
	if (npc->sysargs[0]) {
		//printk("nchoice_sockpath %s %lld\n",(char *)(npc->sysargs[0]),npc->tst.epoch);
		npc->path=nest_abspath(AT_FDCWD,npc->sysargs[0],npc,&(npc->pathstat),0);
		//printk("nchoice_sockabspath %s %lld\n",npc->path,npc->tst.epoch);
		if(npc->path==um_patherror)
			return NULL;
		else
			return ht_check(CHECKPATH,npc->path,&(npc->pathstat),1);
	} else {
		//printk("nchoice_abspath SOCK %ld\n",npc->sysargs[1]);
		npc->path=NULL;
		return ht_check(CHECKSOCKET, &(npc->sysargs[1]),NULL,1);
	}
}

/* choice function for nested calls: link (1st arg) */
struct ht_elem * nchoice_link(int sc_number,struct npcb *npc) {
	//printk("nchoice_link %s\n",(char *)(npc->sysargs[0]));
	npc->path=nest_abspath(AT_FDCWD,npc->sysargs[0],npc,&(npc->pathstat),1);
	//printk("nchoice_abslink %s\n",npc->path);
	if(npc->path==um_patherror)
		return NULL;
	else
		return ht_check(CHECKPATH,npc->path,&(npc->pathstat),1);
}

/* choice function for nested calls: dirfd,link (1st,2nd arg) */
struct ht_elem * nchoice_linkat(int sc_number,struct npcb *npc) {
	npc->path=nest_abspath(npc->sysargs[0],npc->sysargs[1],npc,&(npc->pathstat),1);
	if(npc->path==um_patherror)
		return NULL;
	else
		return ht_check(CHECKPATH,npc->path,&(npc->pathstat),1);
}

/* choice function unlinkat (unlink = rmdir or unlink depending on flag) */ 
struct ht_elem * nchoice_unlinkat(int sc_number,struct npcb *npc) {
	npc->path=nest_abspath(npc->sysargs[0],npc->sysargs[1],npc,&(npc->pathstat),
			!(npc->sysargs[2] & AT_REMOVEDIR));
	if(npc->path==um_patherror)
		return NULL;
	else
		return ht_check(CHECKPATH,npc->path,&(npc->pathstat),1);
}

/* choice function for nested calls: dirfd,link/path (1st,2nd arg,choice on 4th) */
struct ht_elem * nchoice_pl4at(int sc_number,struct npcb *npc) {
	npc->path=nest_abspath(npc->sysargs[0],npc->sysargs[1],npc,&(npc->pathstat),
			npc->sysargs[3] & AT_SYMLINK_NOFOLLOW);
	if(npc->path==um_patherror)
		return NULL;
	else
		return ht_check(CHECKPATH,npc->path,&(npc->pathstat),1);
}

/* choice function for nested calls: dirfd,link/path (1st,2nd arg,choice on 5th) */
struct ht_elem * nchoice_pl5at(int sc_number,struct npcb *npc) {
	npc->path=nest_abspath(npc->sysargs[0],npc->sysargs[1],npc,&(npc->pathstat),
			npc->sysargs[4] & AT_SYMLINK_NOFOLLOW);
	if(npc->path==um_patherror)
		return NULL;
	else
		return ht_check(CHECKPATH,npc->path,&(npc->pathstat),1);
}

/* choice function for nested calls: link (2nd arg) */
struct ht_elem * nchoice_link2(int sc_number,struct npcb *npc) {
	npc->path=nest_abspath(AT_FDCWD,npc->sysargs[1],npc,&(npc->pathstat),1);
	if(npc->path==um_patherror)
		return NULL;
	else
		return ht_check(CHECKPATH,npc->path,&(npc->pathstat),1);
}

/* choice function for nested calls: dirfd/link (3rd/4th arg) */
struct ht_elem * nchoice_link3at(int sc_number,struct npcb *npc) {
	int link;
	/* is this the right semantics? */
#ifdef __NR_linkat
	if (sc_number == __NR_linkat)
		link=npc->sysargs[3] & AT_SYMLINK_NOFOLLOW;
	else
#endif
		link=1;
	npc->path=nest_abspath(npc->sysargs[2],npc->sysargs[3],npc,&(npc->pathstat),link);
	if(npc->path==um_patherror)
		return NULL;
	else
		return ht_check(CHECKPATH,npc->path,&(npc->pathstat),1);
}

/* choice function for nested calls: dirfd/link (3rd/4th arg) */
struct ht_elem * nchoice_link2at(int sc_number,struct npcb *npc) {
	npc->path=nest_abspath(npc->sysargs[1],npc->sysargs[2],npc,&(npc->pathstat),1);
	if(npc->path==um_patherror)
		return NULL;
	else
		return ht_check(CHECKPATH,npc->path,&(npc->pathstat),1);
}

/* choice function for nested calls: socket */
struct ht_elem * nchoice_socket(int sc_number,struct npcb *npc) {
	//printk("nchoice_socket SOCK %ld %d\n",npc->sysargs[0],um_mod_getumpid());
	return ht_check(CHECKSOCKET, &(npc->sysargs[0]),NULL,1);
}

/* call the implementation */
int do_nested_call(sysfun um_syscall,unsigned long *args,int nargx)
{
	/* int narg=NARGS(nargx)*/
	return um_syscall(args[0],args[1],args[2],args[3],args[4],args[5]);
}

/* nested wrapper for syscall with a path*/
long nw_syspath_std(int scno,struct npcb *npc,struct ht_elem *hte,sysfun um_syscall)
{
	npc->sysargs[0]=(long) npc->path;
	return do_nested_call(um_syscall,&(npc->sysargs[0]),scmap[uscno(scno)].nargx);
}

/* nested wrapper for syscall with a path, add -1 for non 'f' syscall*/
long nw_syspath_std_1(int scno,struct npcb *npc,struct ht_elem *hte,sysfun um_syscall)
{
	npc->sysargs[0]=(long) npc->path;
	npc->sysargs[NARGS(scmap[uscno(scno)].nargx)] = -1;
	return do_nested_call(um_syscall,&(npc->sysargs[0]),scmap[uscno(scno)].nargx+1);
}

/* nested wrapper for syscall with a path, EEXIST if the file already exists*/
long nw_syspath_stdnew(int scno,struct npcb *npc,struct ht_elem *hte,sysfun um_syscall)
{
	if (npc->pathstat.st_mode != 0) {
		npc->erno= EEXIST;
		return -1;
	} else {
		npc->sysargs[0]=(long) npc->path;
		return do_nested_call(um_syscall,&(npc->sysargs[0]),scmap[uscno(scno)].nargx);
	}
}

/* nested wrapper for syscall WITH DIRFD (*at) with a path*/
long nw_sysatpath_std(int scno,struct npcb *npc,struct ht_elem *hte,sysfun um_syscall)
{
	npc->sysargs[0]=(long) npc->path;
	npc->sysargs[1]=npc->sysargs[2];
	npc->sysargs[2]=npc->sysargs[3];
	npc->sysargs[3]=npc->sysargs[4];
	npc->sysargs[4]=npc->sysargs[5];
	return do_nested_call(um_syscall,&(npc->sysargs[0]),scmap[uscno(scno)].nargx);
}

/* nested wrapper for fstatat*/
long nw_sysstatat(int scno,struct npcb *npc,struct ht_elem *hte,sysfun um_syscall)
{
	return um_syscall((long) npc->path,npc->sysargs[2],-1);
}

/* nested wrapper for syscall WITH DIRFD (*at) with a path + EEXIST error*/
long nw_sysatpath_stdnew(int scno,struct npcb *npc,struct ht_elem *hte,sysfun um_syscall)
{
	if (npc->pathstat.st_mode != 0) {
		npc->erno= EEXIST;
		return -1;
	} else
		return nw_sysatpath_std(scno,npc,hte,um_syscall);
}

/* nested wrapper for symlinks */
long nw_syssymlink(int scno,struct npcb *npc,struct ht_elem *hte,sysfun um_syscall)
{
	if (npc->pathstat.st_mode != 0) {
		npc->erno= EEXIST;
		return -1;
	} else {
		/* symlinkat is mapped onto symlink */
		return um_syscall(npc->sysargs[0],npc->path);
	}
}

/* nested wrapper for link*/
long nw_syslink(int scno,struct npcb *npc,struct ht_elem *hte,sysfun um_syscall)
{
	char *source;
	int olddirfd;
	long oldpath;
	struct stat64 sourcest;
#ifdef __NR_linkat
	if (scno == __NR_linkat || scno == __NR_renameat) {
		olddirfd=npc->sysargs[0];
		oldpath=npc->sysargs[1];
	} else
#endif
	{
		olddirfd=AT_FDCWD;
		oldpath=npc->sysargs[0];
	} 
	source=nest_abspath(olddirfd,oldpath,npc,&sourcest,0);
	/* nest_abspath sets npc->hte */
	if (npc->pathstat.st_mode != 0 &&
			scno != __NR_rename && scno != __NR_renameat) {
		npc->erno= EEXIST;
		return -1;
	} else if (npc->path==um_patherror) {
		npc->erno= ENOENT;
		return -1;
	} else if (hte != npc->hte) {
		npc->erno= EXDEV;
		return -1;
	} else {
		long rv;
		npc->sysargs[0]=(long) source;
		npc->sysargs[1]=(long) npc->path;
		rv=do_nested_call(um_syscall,&(npc->sysargs[0]),scmap[uscno(scno)].nargx);
		free(source);
		return rv;
	}
}

long nw_systruncate(int scno,struct npcb *npc,struct ht_elem *hte,sysfun um_syscall)
{
	__off64_t off;
#if (__NR_truncate64 != __NR_doesnotexist)
	if (scno == __NR_truncate64)
		off=LONG_LONG(npc->sysargs[1+PALIGN], npc->sysargs[2+PALIGN]);
	else
#endif
		off=npc->sysargs[1];
	return um_syscall(npc->path,off);
}

long nw_sysftruncate(int scno,struct npcb *npc,struct ht_elem *hte,sysfun um_syscall)
{
	 int fd=npc->sysargs[0];
	__off64_t off;
#if (__NR_truncate64 != __NR_doesnotexist)
	if (scno == __NR_truncate64)
		off=LONG_LONG(npc->sysargs[1+PALIGN], npc->sysargs[2+PALIGN]);
	else
#endif
		off=npc->sysargs[1];
	return um_syscall(fd2sfd(&umview_file,fd),off);
}

/* nested wrapper for open*/
long nw_sysopen(int scno,struct npcb *npc,struct ht_elem *hte,sysfun um_syscall)
{
	int sfd;
	npc->sysargs[0]=(long) npc->path;
	if (scno == __NR_creat) {
		npc->sysargs[2]=npc->sysargs[1];
		npc->sysargs[1]=O_CREAT|O_WRONLY|O_TRUNC;
		scno=__NR_open;
	}
#ifdef __NR_openat
	else if (scno == __NR_openat) {
		npc->sysargs[1]=npc->sysargs[2];
		npc->sysargs[2]=npc->sysargs[3];
		scno=__NR_open;
	}
#endif
	sfd=do_nested_call(um_syscall,&(npc->sysargs[0]),scmap[uscno(scno)].nargx);
	if (sfd >= 0) {
		int lfd;
		int newfd=r_dup(STDOUT_FILENO); /* fake a file descriptor! */
		lfd=lfd_open(hte,sfd,NULL,npc->sysargs[2],1);
		lfd_register(&umview_file,newfd,lfd);
		return newfd;
	} else
		return -1;
}

/* nested wrapper for close*/
long nw_sysclose(int scno,struct npcb *npc,struct ht_elem *hte,sysfun um_syscall)
{
	int rv;
	int fd=npc->sysargs[0];
	int lfd=fd2lfd(&umview_file,fd);
	if (lfd >= 0 && lfd_getcount(lfd) <= 1) { //no more opened lfd on this file:
		rv=um_syscall(fd2sfd(&umview_file,fd));
		if (rv >= 0) {
			lfd_nullsfd(lfd);
			lfd_deregister_n_close(&umview_file,fd);
			r_close(fd);
		}
		return rv;
	} else
		return -1;
}

/* nested wrapper for dup*/
long nw_sysdup(int scno,struct npcb *npc,struct ht_elem *hte,sysfun um_syscall)
{
	int fd=npc->sysargs[0];
	int sfd;
	if (scno==__NR_dup) 
		npc->sysargs[1]=-1;
	scno=__NR_dup2;
	sfd=fd2sfd(&umview_file,npc->sysargs[0]);
	if (sfd < 0 && hte != NULL) {
		npc->erno=EBADF;
		return -1;
	}else {
		int rv;
		int lfd=fd2lfd(&umview_file,npc->sysargs[0]);
		rv=do_nested_call(um_syscall,&(npc->sysargs[0]),scmap[uscno(scno)].nargx);
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

struct um_flock32 {
	short l_type;
	short l_whence;
	off_t l_start;
	off_t l_len;
	pid_t l_pid;
};

struct um_flock64 {
	short  l_type;
	short  l_whence;
	loff_t l_start;
	loff_t l_len;
	pid_t  l_pid;
};

static inline void flock32to64(struct um_flock32 *fl32,struct um_flock64 *fl64)
{
	fl64->l_type=fl32->l_type;
	fl64->l_whence=fl32->l_whence;
	fl64->l_start=fl32->l_start;
	fl64->l_len=fl32->l_len;
	fl64->l_pid=fl32->l_pid;

}

static inline void flock64to32(struct um_flock64 *fl64,struct um_flock32 *fl32)
{
	fl32->l_type=fl64->l_type;
	fl32->l_whence=fl64->l_whence;
	fl32->l_start=fl64->l_start;
	fl32->l_len=fl64->l_len;
	fl32->l_pid=fl64->l_pid;

}

/* nested wrapper for fcntl/fcntl64 */
long nw_sysfcntl(int scno,struct npcb *npc,struct ht_elem *hte,sysfun um_syscall)
{
	int sfd;
	int fd= npc->sysargs[0];
	int cmd= npc->sysargs[1];
	unsigned long arg=npc->sysargs[2];
	long rv;
	sfd=fd2sfd(&umview_file,npc->sysargs[0]);
	if (sfd < 0 && hte != NULL) {
		npc->erno=EBADF;
		return -1;
	}else {
		switch (cmd) {
			case F_DUPFD: {
											int newfd;
											int lfd=fd2lfd(&umview_file,fd);
#if (__NR_fcntl64 != __NR_doesnotexist)
											newfd=r_fcntl64(fd,cmd,arg);
#else
											newfd=r_fcntl(fd,cmd,arg);
#endif
											if (newfd >= 0) {
												lfd_dup(lfd);
												lfd_register(&umview_file,newfd,lfd);
											}
											rv=newfd;
										}
			case F_GETFD:
										if ((rv=fd_getfdfl(&umview_file,fd)) < 0)
											npc->erno=EBADF;
			case F_SETFD:
										if ((rv=fd_setfdfl(&umview_file,fd,arg)) < 0)
											npc->erno=EBADF;
			case F_GETLK:
			case F_SETLK:
			case F_SETLKW:
#ifdef F_GETLK64
# if (F_GETLK64 != F_GETLK)
			case F_GETLK64:
			case F_SETLK64:
			case F_SETLKW64:
# endif
#endif
										{
											struct um_flock64 *flock=(struct um_flock64 *)npc->sysargs[2];
#ifdef __NR_fcntl64
											if (scno == __NR_fcntl && 
													(cmd == F_GETLK || cmd == F_SETLK || F_SETLKW)) {
												struct um_flock64 *flock64=alloca(sizeof(struct um_flock64));
												struct um_flock32 *flock32=(struct um_flock32 *)npc->sysargs[2];
												flock32to64(flock32,flock64);
												flock=flock64;
											}
#endif
											rv=um_syscall(sfd,cmd,flock);
#ifdef __NR_fcntl64
											if (scno == __NR_fcntl && 
													(cmd == F_GETLK || cmd == F_SETLK || F_SETLKW)) {
												struct um_flock64 *flock64=flock;
												struct um_flock32 *flock32=(struct um_flock32 *)npc->sysargs[2];
												flock64to32(flock64,flock32);
											}
#endif
										}
			default:
										if ((rv=um_syscall(sfd,cmd,arg)) == -1) {
											switch (cmd) {
												case F_GETFL:
													if ((rv=fd_getflfl(&umview_file,fd)) < 0)
														npc->erno=EBADF;
													else
														npc->erno=0;
											}
										}
		}
		return rv;
	}
}

/* nested wrapper for statfs64*/
long nw_sysstatfs64(int scno,struct npcb *npc,struct ht_elem *hte,sysfun um_syscall)
{
	npc->sysargs[0]=(long) npc->path;
	npc->sysargs[1]=npc->sysargs[2]; /* there is an extra arg (size) */
	return do_nested_call(um_syscall,&(npc->sysargs[0]),scmap[uscno(scno)].nargx);
}

/* nested wrapper for fstatfs64*/
long nw_sysfstatfs64(int scno,struct npcb *npc,struct ht_elem *hte,sysfun um_syscall)
{
	int fd=npc->sysargs[0];
	npc->sysargs[0]=fd2sfd(&umview_file,fd);
	npc->sysargs[1]=npc->sysargs[2]; /* there is an extra arg (size) */
	return do_nested_call(um_syscall,&(npc->sysargs[0]),scmap[uscno(scno)].nargx);
}

/* nested wrapper for standard system calls using fd*/
long nw_sysfd_std(int scno,struct npcb *npc,struct ht_elem *hte,sysfun um_syscall)
{
	int fd=npc->sysargs[0];
	npc->sysargs[0]=fd2sfd(&umview_file,fd);
	return do_nested_call(um_syscall,&(npc->sysargs[0]),scmap[uscno(scno)].nargx);
}

/* nested wrapper for standard system calls using fd converted to path*/
long nw_sysfdpath_std(int scno,struct npcb *npc,struct ht_elem *hte,sysfun um_syscall)
{
	int fd=npc->sysargs[0];
	npc->sysargs[0]=(long)fd_getpath(&umview_file,fd);
	npc->sysargs[NARGS(scmap[uscno(scno)].nargx)] = fd2sfd(&umview_file,fd);
	return do_nested_call(um_syscall,&(npc->sysargs[0]),scmap[uscno(scno)].nargx+1);
}

#if (__NR__llseek != __NR_doesnotexist)
long nw_syslseek(int scno,struct npcb *npc,struct ht_elem *hte,sysfun um_syscall)
{
	int fd=npc->sysargs[0];
	int sfd=fd2sfd(&umview_file,fd);
	long offset=npc->sysargs[1];
	int whence=npc->sysargs[2];
	long rv;
	if (isnosys(um_syscall)) {
		loff_t lresult;
		um_syscall=ht_syscall(hte,uscno(__NR__llseek));
		rv = um_syscall(sfd,(offset>0)?0:-1,offset,&lresult,whence);
		if (rv != -1) {
			rv=lresult;
			if (rv != lresult) {
				npc->erno = EOVERFLOW;
				return -1;
			}
		} 
		return rv;
	} else
		return um_syscall(sfd,offset,whence);
}


long nw_sysllseek(int scno,struct npcb *npc,struct ht_elem *hte,sysfun um_syscall)
{
	int fd=npc->sysargs[0];
	int sfd=fd2sfd(&umview_file,fd);
	unsigned long offhi=npc->sysargs[1];
	unsigned long offlo=npc->sysargs[2];
	loff_t *result=(loff_t *) npc->sysargs[3];
	unsigned int whence=npc->sysargs[4];
	if (!isnosys(um_syscall)) 
		return um_syscall(sfd,offhi,offlo,result,whence);
	else {
		if ((offhi==0 && !(offlo & 1<<31)) || ((offhi == ~0 && (offlo & 1<<31)))) {
			long shortresult;
			um_syscall=ht_syscall(hte,uscno(__NR_lseek));
			if ((shortresult=um_syscall(sfd,offlo,whence)) != -1) {
				*result=shortresult;
				return 0;
			} else
				return -1;
		}	else {
			npc->erno=EFAULT;
			return -1;
		}
	}
}
#endif

long nw_sysreadv(int scno,struct npcb *npc,struct ht_elem *hte,sysfun um_syscall)
{
	int sfd=fd2sfd(&umview_file,npc->sysargs[0]);
	struct iovec *iovec=(struct iovec *)npc->sysargs[1];
	unsigned long count=npc->sysargs[2];
	unsigned long i,totalsize,size;
	char *lbuf,*p;
	for (i=0,totalsize=0;i<count;i++)
		totalsize += iovec[i].iov_len;
	lbuf=p=(char *)lnalloca(totalsize);
	/* MAPPED ONTO READ */
	if ((size=um_syscall(sfd,lbuf,totalsize)) >= 0) {
		for (i=0;i<count && size>0;i++) {
			long qty=(size > iovec[i].iov_len)?iovec[i].iov_len:size;
			memcpy(iovec[i].iov_base,p,qty);
			p += qty;
			size -= qty;
		}
	}
	lfree(lbuf,totalsize);
	return size;
}

long nw_syswritev(int scno,struct npcb *npc,struct ht_elem *hte,sysfun um_syscall)
{
	int sfd=fd2sfd(&umview_file,npc->sysargs[0]);
	struct iovec *iovec=(struct iovec *)npc->sysargs[1];
	unsigned long count=npc->sysargs[2];
	unsigned long i,totalsize,size;
	char *lbuf,*p;
	for (i=0,totalsize=0;i<count;i++)
		totalsize += iovec[i].iov_len;
	lbuf=p=(char *)lnalloca(totalsize);
	for (i=0;i<count;i++) {
		long qty=iovec[i].iov_len;
		memcpy(p,iovec[i].iov_base,qty);
		p += qty;
	}
	/* MAPPED ONTO WRITE */
	size=um_syscall(sfd,lbuf,totalsize);
	lfree(lbuf,totalsize);
	return size;
}

long nw_syspreadv(int scno,struct npcb *npc,struct ht_elem *hte,sysfun um_syscall)
{
	int sfd=fd2sfd(&umview_file,npc->sysargs[0]);
	struct iovec *iovec=(struct iovec *)npc->sysargs[1];
	unsigned long count=npc->sysargs[2];
	unsigned long i,totalsize,size;
	char *lbuf,*p;
	unsigned long long offset;
#ifdef __NR_pread64
	offset=LONG_LONG(npc->sysargs[3],npc->sysargs[4]);
#else
	offset=npc->sysargs[3];
#endif
	for (i=0,totalsize=0;i<count;i++)
		totalsize += iovec[i].iov_len;
	lbuf=p=(char *)lnalloca(totalsize);
	/* MAPPED ONTO PREAD */
	if ((size=um_syscall(sfd,lbuf,totalsize,offset)) >= 0) {
		for (i=0;i<count && size>0;i++) {
			long qty=(size > iovec[i].iov_len)?iovec[i].iov_len:size;
			memcpy(iovec[i].iov_base,p,qty);
			p += qty;
			size -= qty;
		}
	}
	lfree(lbuf,totalsize);
	return size;
}

long nw_syspwritev(int scno,struct npcb *npc,struct ht_elem *hte,sysfun um_syscall)
{
	int sfd=fd2sfd(&umview_file,npc->sysargs[0]);
	struct iovec *iovec=(struct iovec *)npc->sysargs[1];
	unsigned long count=npc->sysargs[2];
	unsigned long i,totalsize,size;
	char *lbuf,*p;
	unsigned long long offset;
#ifdef __NR_pread64
	offset=LONG_LONG(npc->sysargs[3],npc->sysargs[4]);
#else
	offset=npc->sysargs[3];
#endif
	for (i=0,totalsize=0;i<count;i++)
		totalsize += iovec[i].iov_len;
	lbuf=p=(char *)lnalloca(totalsize);
	for (i=0;i<count;i++) {
		long qty=iovec[i].iov_len;
		memcpy(p,iovec[i].iov_base,qty);
		p += qty;
	}
	/* MAPPED ONTO PWRITE */
	size=um_syscall(sfd,lbuf,totalsize,offset);
	lfree(lbuf,totalsize);
	return size;
}


/* nested wrapper for standard socket calls */
long nw_sockfd_std(int scno,struct npcb *npc,struct ht_elem *hte,sysfun um_syscall)
{
	int fd=npc->sysargs[0];
	npc->sysargs[0]=fd2sfd(&umview_file,fd);
#if __NR_socketcall != __NR_doesnotexist
	return do_nested_call(um_syscall,&(npc->sysargs[0]),sockmap[scno].nargx);
#else
	return do_nested_call(um_syscall,&(npc->sysargs[0]),scmap[uscno(scno)].nargx);
#endif
}

long nw_msocket(int scno,struct npcb *npc,struct ht_elem *hte,sysfun um_syscall)
{
	npc->sysargs[0]=(long) npc->path;
	//printk("nw_msocket %s %d\n",npc->sysargs[0],hte);
	if (hte != NULL) {
		if (npc->sysargs[2] /*type*/ == SOCK_DEFAULT) {
			/* redefine default for recursive calls.
			 * it is not clear yet if it does make sense and
			 * which semantics is has */
			npc->erno=EOPNOTSUPP;
			return -1;
		} else {	
			int sfd;
			if ((sfd=do_nested_call(um_syscall,&(npc->sysargs[0]),4)) < 0) {
				if (errno == ENOSYS && npc->path == NULL) {
					/* backward compatibility:
					 * modules implementing only "socket". 
					 * the code reaches this case only from wrap_in_socket */
#if (__NR_socketcall != __NR_doesnotexist)
					um_syscall=ht_socketcall(hte,SYS_SOCKET);
#else
					um_syscall=ht_syscall(hte,uscno(__NR_socket));
#endif
					sfd=do_nested_call(um_syscall,&(npc->sysargs[0]),3);
				}
			}
			if (sfd >= 0) {
				int lfd;
				int newfd=r_dup(STDOUT_FILENO); /* fake a file descriptor! */
				lfd=lfd_open(hte,sfd,NULL,npc->sysargs[0],1);
				lfd_register(&umview_file,newfd,lfd);
				//printk("Fake a lfd msocket %s s%d l%d new%d\n",npc->sysargs[0],sfd,lfd,newfd);
				return newfd;
			} else
				return -1;
		}
	} else {
		/* msocket -> socket translation for native system calls
		 * just for the case path=NULL */
		if (npc->path == NULL) {
			npc->sysargs[0]=npc->sysargs[1];
			npc->sysargs[1]=npc->sysargs[2];
			npc->sysargs[2]=npc->sysargs[3];
#if (__NR_socketcall != __NR_doesnotexist)
			return nested_call_sockcall(SYS_SOCKET,npc);
#else
			return nested_call_syscall(__NR_msocket,npc);
#endif
		} else {
			errno=ENOTSUP;
			return -1;
		}
	}
}

/* nested wrapper for standard socket calls */
long nw_accept(int scno,struct npcb *npc,struct ht_elem *hte,sysfun um_syscall)
{
	int fd=npc->sysargs[0];
	int sfd;
	npc->sysargs[0]=fd2sfd(&umview_file,fd);
	sfd=do_nested_call(um_syscall,&(npc->sysargs[0]),3);
	if (sfd >= 0) {
		int lfd;
		int newfd=r_dup(STDOUT_FILENO); /* fake a file descriptor! */
		//printk("Fake a accept lfd msocket %d s%d l%d new%d\n",npc->sysargs[0],sfd,lfd,newfd);
		lfd=lfd_open(hte,sfd,NULL,npc->sysargs[0],1);
		lfd_register(&umview_file,newfd,lfd);
		return newfd;
	} else
		return -1;
}

long nw_socket(int scno,struct npcb *npc,struct ht_elem *hte,sysfun um_syscall)
{
	npc->sysargs[3]=npc->sysargs[2];
	npc->sysargs[2]=npc->sysargs[1];
	npc->sysargs[1]=npc->sysargs[0];
	npc->sysargs[0]=(long)NULL;
	return nw_msocket(__NR_msocket,npc,hte,ht_virsyscall(hte,VIRSYS_MSOCKET));
}

/* nested wrapper for not supported call */
long nw_notsupp(int scno,struct npcb *npc,struct ht_elem *hte,sysfun um_syscall)
{
	npc->erno=EOPNOTSUPP;
	return -1;
}

/* dcif (index) for syscalls */
static int nested_sysindex(struct npcb *npc, int scno)
{
	return uscno(scno);
}

/* dcif (index) for sockets or virtual: just the sysno*/
static int nested_sockvirindex(struct npcb *npc, int scno)
{
	return scno;
}


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

static int nested_call_virsc (int sysno, struct npcb *npc)
{
	npc->erno=EOPNOTSUPP;
	return -1;
}

/* COMMON WRAP FOR NESTED CALLS */
typedef int (*nested_commonwrap_index_function)(struct npcb *pc, int scno);
typedef int (*nested_commonwrap_call_function)(int sysno,struct npcb *pc);
typedef sysfun (*service_call)(struct ht_elem *hte, int scno);
int nested_commonwrap(int sc_number,struct npcb *npc,
		nested_commonwrap_index_function dcif,
		nested_commonwrap_call_function do_kernel_call,
		service_call sc,
		struct sc_map *sm) {
	long rv;
	struct ht_elem *hte;
	int index = dcif(npc, sc_number); /* index of the call */
	if (__builtin_expect(npc->tmpfile2unlink_n_free!=NULL,0)) {
		r_unlink(npc->tmpfile2unlink_n_free);
		free(npc->tmpfile2unlink_n_free);
		npc->tmpfile2unlink_n_free=NULL;
	}
	//printk("nested_commonwrap %d -> %lld\n",sc_number,npc->tst.epoch);
	npc->hte=hte=sm[index].nestchoice(sc_number,npc); /* module code */
#ifdef _UM_MMAP
	if (hte == HT_ERR) {
		printk("NESTED BADF!\n");
		errno=EBADF;
		return -1;
	}
	else
#endif
	if (npc->path == um_patherror) {
		errno=npc->erno;
		return -1;
	}
	//printk("nested_commonwrap choice %d -> %lld %x\n",sc_number,npc->tst.epoch,hte);
	if (hte != NULL || (sm[index].flags & NALWAYS)) {
		/* SUSPEND MGMT? */
		rv=sm[index].nestwrap(sc_number,npc,hte,sc(hte,index));
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
	callee->ruid=caller->ruid;
	callee->euid=caller->euid;
	callee->suid=caller->suid;
	callee->fsuid=caller->fsuid;
	callee->rgid=caller->rgid;
	callee->egid=caller->egid;
	callee->sgid=caller->sgid;
	callee->fsgid=caller->fsgid;
	callee->grouplist=supgrp_get(caller->grouplist);
	pcb_constructor((struct pcb *)callee,0,1);
}

/* restore args (there is nothing to do!) */
static void nrestoreargs(struct pcb *caller,struct npcb *callee){
	supgrp_put(callee->grouplist);
}

static long int capture_nested_virsc(long int sysno, ...);
int msocket (char *path, int domain, int type, int protocol)
{
	long rv=capture_nested_virsc(VIRSYS_MSOCKET,path,(long)domain,(long)(type),(long)protocol);
	//printk("msocket4modules %s %d -> %d\n",path,domain,rv);
	return rv;
}

/* management of module generated virtual system calls */
static long int capture_nested_virsc(long int sysno, ...){
	va_list ap;
	register int i;
	register int narg=NARGS(virscmap[sysno].nargx);
	long rv;
	struct pcb *caller_pcb=get_pcb();
	/* this is a new pcb, the actual pcb for syscall evaluation */
	struct npcb callee_pcb;
	nsaveargs(caller_pcb, &callee_pcb,__NR_socketcall); /* socketcall ??? */
	set_pcb(&callee_pcb);
	va_start(ap, sysno);
	for (i=0; i<narg;i++)
		callee_pcb.sysargs[i]=va_arg(ap,long int);
	va_end(ap);
#ifdef _NESTED_CALL_DEBUG_ 
	printk("SvC=%ld - %p %lld %lld- args: %p %p %p %p %p %p\n",sysno,get_pcb(),callee_pcb.tst.epoch,callee_pcb.nestepoch,
			(void*)callee_pcb.sysargs[0],
			(void*)callee_pcb.sysargs[1],
			(void*)callee_pcb.sysargs[2],
			(void*)callee_pcb.sysargs[3],
			(void*)callee_pcb.sysargs[4],
			(void*)callee_pcb.sysargs[5]);
#endif
	/*
	 * UMPID4NESTED
	 * callee_pcb.umpid=caller_pcb->umpid;
	 */
	/* commonwrap for nested socket calls, 
	 * nested_commonwrap sets errno, so the following code should not
	 * call any system call or errno must be saved*/
	callee_pcb.private_scno=sysno | ESCNO_VIRSC;
	rv=nested_commonwrap(sysno, &callee_pcb, nested_sockvirindex, nested_call_virsc, ht_virsyscall, virscmap);

	nrestoreargs(caller_pcb, &callee_pcb);
	set_pcb(caller_pcb);
#ifdef _NESTED_CALL_DEBUG_ 
	{ int errno_save=errno;
		printk("->(Sk) %ld: return value:%ld %p\n",
				sysno,rv,get_pcb());
		errno=errno_save;
	}
#endif
	return rv;
}

#if __NR_socketcall != __NR_doesnotexist
/* management of module generated socket calls */
static long int capture_nested_socketcall(long int sysno, ...){
	va_list ap;
	register int i;
	register int narg=NARGS(sockmap[sysno].nargx);
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
	printk("SkC=%ld - %p %lld %lld- args: %p %p %p %p %p %p\n",sysno,get_pcb(),callee_pcb.tst.epoch,callee_pcb.nestepoch,
					(void*)callee_pcb.sysargs[0],
					(void*)callee_pcb.sysargs[1],
					(void*)callee_pcb.sysargs[2],
					(void*)callee_pcb.sysargs[3],
					(void*)callee_pcb.sysargs[4],
					(void*)callee_pcb.sysargs[5]);
#endif
  /*
	 * UMPID4NESTED
	 * callee_pcb.umpid=caller_pcb->umpid;
	 */
	/* commonwrap for nested socket calls */
	callee_pcb.private_scno=sysno | ESCNO_SOCKET;
	rv=nested_commonwrap(sysno, &callee_pcb, nested_sockvirindex, nested_call_sockcall, ht_socketcall, sockmap);

	nrestoreargs(caller_pcb, &callee_pcb);
	set_pcb(caller_pcb);
#ifdef _NESTED_CALL_DEBUG_
	printk("->(Sk) %ld: return value:%ld %p\n",
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
	register int narg=NARGS(scmap[uscno(sysno)].nargx);
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
		if(i < narg) 
			callee_pcb.sysargs[i]=va_arg(ap,long int);
		else
			callee_pcb.sysargs[i]=0;
	}
	va_end(ap);
#ifdef _NESTED_CALL_DEBUG_
		printk("SyC=%ld - %s %p %lld %lld- args: %x %x %x %x %x %x\n",sysno,SYSCALLNAME(sysno),get_pcb(),callee_pcb.tst.epoch,callee_pcb.nestepoch,
					(void*)callee_pcb.sysargs[0],
					(void*)callee_pcb.sysargs[1],
					(void*)callee_pcb.sysargs[2],
					(void*)callee_pcb.sysargs[3],
					(void*)callee_pcb.sysargs[4],
					(void*)callee_pcb.sysargs[5]);
#endif
  /*
	 * UMPID4NESTED
   * callee_pcb.umpid=caller_pcb->umpid;
	 */
	/* commonwrap for nested calls */
	callee_pcb.private_scno = sysno;
	rv=nested_commonwrap(sysno, &callee_pcb, nested_sysindex, nested_call_syscall, ht_syscall, scmap);

	nrestoreargs(caller_pcb, &callee_pcb);
	set_pcb(caller_pcb);
#ifdef _NESTED_CALL_DEBUG_
		printk("-> %ld - %s: return value:%ld %p\n",
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
	/* inherit the current hash table element during clone*/
	npcb->hte=old->hte;
	/* timestamp the new thread with the current time (is it correct?) */
	//npcb->tst.epoch=npcb->nestepoch=get_epoch();
	/* XXX rd235 20090805 inherit the time of the creating thread */
	npcb->nestepoch=npcb->tst.epoch;
	//printk("new_npcb %lld\n",npcb->tst.epoch);
	npcb->ruid=old->ruid;
	npcb->euid=old->euid;
	npcb->suid=old->suid;
	npcb->fsuid=old->fsuid;
	npcb->rgid=old->rgid;
	npcb->egid=old->egid;
	npcb->sgid=old->sgid;
	npcb->fsgid=old->fsgid;
	npcb->grouplist=supgrp_get(old->grouplist);

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
