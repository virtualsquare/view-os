/*   This is iart of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   sctab.c: um-ViewOS interface to capture_*
 *   
 *   Copyright 2005 Renzo Davoli University of Bologna - Italy
 *   Modified 2005 Mattia Belletti, Ludovico Gardenghi, Andrea Gasparini
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
#include <sys/select.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sched.h>
#include <asm/ptrace.h>
#include <asm/unistd.h>
#include <linux/net.h>
#include <errno.h>
#include <limits.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#ifdef OLDVIRSC
#include <linux/sysctl.h>
#endif
#include <config.h>

#include "defs.h"
#include "umproc.h"
#include "services.h"
#include "um_services.h"
#include "sctab.h"
#include "um_select.h"
#include "scmap.h"
#include "utils.h"
#include "canonicalize.h"
#include "capture.h"
#include "capture_nested.h"
#include "hashtab.h"
#include "gdebug.h"

uid_t host_uid;
gid_t host_gid;

static const char *const _sys_sigabbrev[NSIG] =
{
#define init_sig(sig, abbrev, desc)   [sig] = abbrev,
#include <siglist.h>
#undef init_sig
};

/* set the errno */
void um_set_errno(struct pcb *pc,int i) {
	if (pc->flags && PCB_INUSE) 
		pc->erno=i;
	else {
		struct npcb *npc=(struct npcb *)pc;
		npc->erno=i;
	}
}

char *um_getroot(struct pcb *pc)
{
	if (pc->flags && PCB_INUSE) 
		return pc->fdfs->root;
	else
		/* nested chroot: TODO */
		return "/";
}

/* internal call: get the timestamp */
struct timestamp *um_x_gettst()
{
	struct pcb *pc=get_pcb();
	if (pc)
		return &(pc->tst);
	else
		return NULL;
}

/* set the epoch for nesting (further system calls)
 * this call returns the previous value.
 * If epoch == 0, the new epoch is not set */
epoch_t um_setnestepoch(epoch_t epoch)
{
	struct pcb *pc=get_pcb();
	epoch_t oldepoch=pc->nestepoch;
	if (epoch > 0)
		pc->nestepoch=epoch;
	return oldepoch;
}

/* internal call: load the stat info for a file */
int um_x_lstat64(char *filename, struct stat64 *buf, struct pcb *pc, int isdotdot)
{
	struct ht_elem *hte;
	int retval;
	long oldscno;
	epoch_t epoch;
	/* printk("-> um_lstat: %s %p %d\n",filename,pc->hte,isdotdot); */
	/* internal nested call save data */
	oldscno = pc->sysscno;
	pc->sysscno = NR64_lstat;
	epoch=pc->nestepoch;
	if ((hte=ht_check(CHECKPATH,filename,NULL,1)) == NULL) {
		if (pc->hte!=NULL && isdotdot) {
			pc->needs_path_rewrite=1;
			// printk("dotdot cage error %s %d\n",filename,pc->sysscno);
		}
		pc->hte=hte;
		retval = r_lstat64(filename,buf);
	} else {
		pc->hte=hte;
		retval = ht_syscall(hte,uscno(NR64_lstat))(filename,buf,-1);
	}
	/* internal nested call restore data */
	//printk("%s %lld->%lld\n",filename,epoch,pc->nestepoch);
	pc->sysscno = oldscno;
	pc->nestepoch=epoch;
	return retval;
}

static int um_stat2access(int mode, struct pcb *pc, 
		struct stat64 *stbuf, int real_uid)
{
	if (stbuf->st_mode == 0) {
		errno=ENOENT;
		return -1;
	} else if ((mode & W_OK) && (ht_get_mountflags(pc->hte) & MS_RDONLY)) {
		errno=EROFS;
		return -1;
	} else {
		uid_t uid;
		gid_t gid;
		if (pc->hte == NULL) {
			uid=host_uid;
			gid=host_gid;
		} else {
			uid=(real_uid)?pc->ruid:pc->fsuid;
			gid=(real_uid)?pc->rgid:pc->fsgid;
		}
		if (uid == 0 || secure == 0) {
			if ((mode & X_OK) && 
					!(stbuf->st_mode & (S_IXUSR | S_IXGRP | S_IXOTH))) {
				errno=EACCES;
				return -1;
			} else
				return 0;
		} else {
			if (uid == stbuf->st_uid &&
					(((stbuf->st_mode & S_IRWXU) >> 6) & mode) == mode)
				return 0;
			else if ((gid == stbuf->st_gid ||
						in_supgrplist(stbuf->st_gid, pc)) &&
					(((stbuf->st_mode & S_IRWXG) >> 3) & mode) == mode)
				return 0;
			else if ((stbuf->st_mode & S_IRWXO & mode) == mode)
				return 0;
			else {
				errno=EACCES;
				return -1;
			}
		}
	}
}

/* internal call: check the permissions for a file,
   search for module */
int um_xx_access(char *filename, int mode, struct pcb *pc)
{
	struct ht_elem *hte;
	int retval;
	long oldscno;
	epoch_t epoch;
	/* printk("-> um_xx_access: %s\n",filename); */
	/* internal nested call save data */
	oldscno = pc->sysscno;
	epoch=pc->nestepoch;
	pc->sysscno = __NR_access;
	if ((hte=ht_check(CHECKPATH,filename,NULL,1)) == NULL)
		retval = r_access(filename,mode);
	else{
		pc->hte=hte;
		retval = ht_syscall(hte,uscno(__NR_access))(filename,mode);
	}
	/* internal nested call restore data */
	pc->sysscno=oldscno;
	pc->nestepoch=epoch;
	return retval;
}
										 
int um_parentwaccess(char *filename, struct pcb *pc)
{
	int lastslash=strlen(filename)-1;
	char *parent=filename;
	struct ht_elem *hte;
	struct stat64 stbuf;
	long oldscno;
	int retval;
	epoch_t epoch,nestepoch;
	//printk("%s \n",filename);
	while ((parent[lastslash]!='/') && (lastslash>0)) 
		lastslash--;
	if (lastslash==0)
		parent="/";
	parent[lastslash]='\0';
	//printk("-> um_parentwaccess: %s\n",parent);
	/* internal nested call save data */
	oldscno = pc->sysscno;
	epoch=pc->tst.epoch;
	nestepoch=pc->nestepoch;
	pc->sysscno = NR64_lstat;
	pc->tst.epoch=pc->nestepoch=get_epoch();
	if ((hte=ht_check(CHECKPATH,parent,NULL,0)) == NULL) {
		retval = r_lstat64(filename,&stbuf);
	} else {
		struct ht_elem *oldhte=pc->hte;
		pc->hte=hte;
		retval = ht_syscall(hte,uscno(NR64_lstat))(filename,&stbuf,-1);
		pc->hte=oldhte;
	}
	pc->sysscno = oldscno;
	pc->tst.epoch=epoch;
	pc->nestepoch=nestepoch;
	filename[lastslash]='/';
	if (retval < 0) {
		errno=EIO;
		return -1;
	}
	else if (pc->suid == stbuf.st_uid && (stbuf.st_mode & S_IWUSR))
		return 0;
	else if ((stbuf.st_mode & S_IWGRP) && 
			(pc->sgid == stbuf.st_gid || in_supgrplist(stbuf.st_gid, pc)))
		return 0;
	else if (stbuf.st_mode & S_IWOTH)
		return 0;
	else {
		errno=EACCES;
		return -1;
	}
	return 0;
}

#define FASTACCESS
/* internal call: check the permissions for a file,
   this must follow a um_x_lstat64 */
#ifdef FASTACCESS
int um_x_access(char *filename, int mode, struct pcb *pc, struct stat64 *stbuf)
{
	return um_stat2access(mode, pc, stbuf, 0);
}
#else
int um_x_access(char *filename, int mode, struct pcb *pc, struct stat64 *stbuf)
{
	int retval;
	long oldscno;
	/* printk("-> um_x_access: %s %p\n",filename,pc->hte); */
	/* internal nested call save data */
	oldscno = pc->sysscno;
	pc->sysscno = __NR_access;
	if (pc->hte == NULL)
		retval = r_access(filename,mode);
	else {
		epoch_t epoch=pc->nestepoch;
		pc->nestepoch=ht_get_epoch(pc->hte);
		retval = ht_syscall(pc->hte,uscno(__NR_access))(filename,mode);
#if 0
		{
			int test;
			test=um_stat2access(mode, pc, stbuf, 0);
			if (test != retval) 
				printk("diff %s %d -> %d %d %o %s\n",filename, mode, retval, test, pc->pathstat.st_mode, strerror(errno));
		}
#endif
		pc->nestepoch=epoch;
	}
	/* internal nested call restore data */
	pc->sysscno=oldscno;
	return retval;
}
#endif
										 
/* internal call: read a symbolic link target 
   this must follow a um_x_lstat64 */
int um_x_readlink(char *path, char *buf, size_t bufsiz, struct pcb *pc)
{
	long oldscno = pc->sysscno;
	int retval;
	/* printk("-> um_x_readlink: %s %p\n",path,pc->hte); */
	oldscno = pc->sysscno;
	pc->sysscno = __NR_readlink;
	if (pc->hte == NULL)
		retval = r_readlink(path,buf,bufsiz);
	else {
		epoch_t epoch=pc->nestepoch;
		pc->nestepoch=ht_get_epoch(pc->hte);
		retval = ht_syscall(pc->hte,uscno(__NR_readlink))(path,buf,bufsiz);
		pc->nestepoch=epoch;
	}
	/* internal nested call restore data */
	pc->sysscno = oldscno;
	return retval;
}

/* rewrite the path argument of a call */
int um_x_rewritepath(struct pcb *pc, char *path, int arg, long offset)
{
	long sp=getsp(pc);
	int pathlen=WORDALIGN(strlen(path));
	long pos=sp-(pathlen+offset);
	ustoren(pc, pos, pathlen, path);
	pc->sysargs[arg]=pos;
	return offset+pathlen;
}

/* one word string used as a tag for mistaken paths */
char um_patherror[]="PE";

/* get a path (and strdup it) from the process address space */
char *um_getpath(long laddr,struct pcb *pc)
{
	char path[PATH_MAX];
	if (umovestr(pc,laddr,PATH_MAX,path) == 0)
		return strdup(path);
	else
		return um_patherror;
}

/* utimensat has a (crazy) behavior with filename==NULL */
static char *utimensat_nullpath(int dirfd,struct pcb *pc,struct stat64 *pst,int dontfollowlink)
{
	if (dirfd==AT_FDCWD) {
		pc->erno = EFAULT;
		return um_patherror;
	} else if (dontfollowlink) {
		pc->erno = EINVAL;
		return um_patherror;
	} else {
		char *path=fd_getpath(pc->fds,dirfd);
		if (path==NULL) {
			int rv;
			path=alloca(PATH_MAX);
			snprintf(path,PATH_MAX,"/proc/%d/fd/%d",pc->pid,dirfd);
			if ((rv=readlink(path,path,PATH_MAX)) < 0) {
				pc->erno = EBADF;
				return um_patherror;
			} else
				path[rv]=0;
		}
		return strdup(path);
	}
}

/* get a path, convert it as an absolute path (and strdup it) 
 * from the process address space */
char *um_abspath(int dirfd, long laddr,struct pcb *pc,struct stat64 *pst,int dontfollowlink)
{
	char path[PATH_MAX];
	if (umovestr(pc,laddr,PATH_MAX,path) == 0) {
		char newpath[PATH_MAX];
		char *cwd;
		char *root=um_getroot(pc);
		if (dirfd==AT_FDCWD)
			cwd=pc->fdfs->cwd;
		else {
			cwd=fd_getpath(pc->fds,dirfd);
			if (cwd==NULL) {
				int rv;
				cwd=alloca(PATH_MAX);
				snprintf(cwd,PATH_MAX,"/proc/%d/fd/%d",pc->pid,dirfd);
				if ((rv=readlink(cwd,cwd,PATH_MAX)) < 0) {
					pc->erno = EBADF;
					return um_patherror;
				} else 
					cwd[rv]=0;
			}
		}
		pc->hte=NULL;
		um_realpath(path,cwd,newpath,pst,dontfollowlink,pc);
		/* View-OS core chroot management: if root is not '/' always rewrite pathnames */
		if (root[1] != 0 && pc->hte == NULL)
			pc->needs_path_rewrite=1;
		/* printk("PATH %s (%s,%s) NEWPATH %s (%p,%d) %lld\n",path,um_getroot(pc),pc->fdfs->cwd,newpath,pc->hte,pc->erno,pc->nestepoch); */
		if (pc->erno)
			return um_patherror;	//error
		else
			return strdup(newpath);
	}
	else {
		pc->erno = EINVAL;
		return um_patherror;
	}
}

/* Common framework for the dsys_{megawrap,socketwrap,virscwrap,...} - they all
 * do the usual work, but with different parameter handling.
 * What a dsys_* function do is, in general, receiving the notification of an
 * IN/OUT phase of syscall about a certain process, and decide what to do. What
 * it has to do is to deliver the notification to the correct functions.
 * This common framework asks for three more parameters to make such a
 * decision:
 * - An argument parser function (dcpa): this function extracts the arguments
 *   from the process registers/memory into our data structures (usually
 *   arg{0,1,...}, but also others - e.g., sockregs).
 * - An index function (dcif): returns the index inside the system call table
 *   that regards the current system call.
 * - A service call function (sc): the service code and system call number is
 *   given to this function, and it must return the function of the
 *   module/service which manage the syscall
 * - A system call table (sm): this is a table of sc_map entries - look at that
 *   structure for more informations.
 */
typedef void (*dsys_commonwrap_parse_arguments)(struct pcb *pc, int scno);
typedef int (*dsys_commonwrap_index_function)(struct pcb *pc, int scno);
typedef sysfun (*service_call)(struct ht_elem *hte, int scno);
int dsys_commonwrap(int sc_number,int inout,struct pcb *pc,
		dsys_commonwrap_parse_arguments dcpa,
		dsys_commonwrap_index_function dcif,
		service_call sc,
		struct sc_map *sm)
{
	/* some tmp files must be removed at the next invocation (e.g.
	 * exec creates tmp files), here is the removal */
	if (__builtin_expect(pc->tmpfile2unlink_n_free!=NULL,0)) {
		r_unlink(pc->tmpfile2unlink_n_free);
		free(pc->tmpfile2unlink_n_free);
		pc->tmpfile2unlink_n_free=NULL;
	}
	/* -- IN phase -- */
	if (inout == IN) {
		struct ht_elem *hte;
		int index;
		puterrno0(pc);
		/* timestamp the call */
		pc->tst.epoch=pc->nestepoch=get_epoch();
		/* extract argument */
		dcpa(pc, sc_number);
		/* and get the index of the system call table
		 * regarding this syscall */
		index = dcif(pc, sc_number);
		/* dotdot cage: syscalls need path rewriting when leaving
			 a virtual area by a relative .. path */
		pc->needs_path_rewrite=0;
		//printk("nested_commonwrap %d -> %lld\n",sc_number,pc->tst.epoch);
		/* looks in the system call table what is the 'choice function'
		 * and ask it the service to manage */
		pc->hte=hte=sm[index].scchoice(sc_number,pc);
		/* something went wrong during a path lookup - fake the
		 * syscall, we do not want to make it run */
		if (pc->path == um_patherror) {
			pc->retval = -1;
			return SC_FAKE;
		}
#ifdef _UM_MMAP
		/* it returns EBADF when somebody tries to access 
		 * secret files (mmap_secret) */
		if (hte == HT_ERR) {
			pc->path = um_patherror;
			pc->erno = EBADF;
			pc->retval = -1;
			return SC_FAKE;
		}
#endif
		//printk("commonwrap choice %d -> %lld %x\n",sc_number,pc->tst.epoch,hte);
		/* if some service want to manage the syscall (or the ALWAYS
		 * flag is set), we process it */
		if (hte != NULL || (sm[index].flags & ALWAYS)) {
			/* suspend management:
			 * when howsusp has at least one bit set (CB_R, CB_W, CB_X) 
			 * the system checks with a select if the call is blocking or not.
			 * when the call would be blocking the process is suspended and an event
			 * event callback is loaded.
			 */
			int howsusp = sm[index].flags & 0x7;
			int what;
			errno=0;
			if (howsusp != 0 && (what=check_suspend_on(pc,  
							pc->sysargs[0],
							howsusp))!=STD_BEHAVIOR) {
				if (what == SC_CALLONXIT) {
					if (pc->path != NULL)
						free(pc->path);
					pc->path = um_patherror;
				}
				return what;
			}
			else
				/* normal management: call the wrapin function,
				 * with the correct service syscall function */
				return sm[index].wrapin(sc_number,pc,hte,sc(hte,index));
#if 0
			int retval;
			errno=0;
			retval=sm[index].wrapin(sc_number,pc,hte,sc(hte,index));
			if (pc->erno==EUMWOULDBLOCK)
				return SC_SUSPIN;
			else
				return retval;
#endif
		}
		else {
			int retval;
			if (__builtin_expect(pc->needs_path_rewrite,0)) {
				// printk("needs_path_rewrite %s %d\n",pc->path,pc->sysscno);
				if (ISPATHARG(sm[index].nargx))
					um_x_rewritepath(pc,pc->path,PATHARG(sm[index].nargx),0);
				retval=SC_MODICALL;
			} else
				retval=STD_BEHAVIOR;
			/* we do not want to manage the syscall: free the path
			 * field in case, since we do not need it, and ask for
			 * a standard behavior */
			if (pc->path != NULL)
				free(pc->path);
			return retval;
		}
	/* -- OUT phase -- */
	} else {
		if (pc->path != um_patherror) {
			/* ok, try to call the wrapout */
			int retval;
			/* and get the index of the system call table
			 * regarding this syscall */
			int index = dcif(pc, sc_number);
			errno=0;
			/* call the wrapout */
			retval=sm[index].wrapout(sc_number,pc);
			/* check if we can free the path (not NULL and not
			 * used) */
			if (pc->path != NULL && (retval & SC_SUSPENDED) == 0)
				free(pc->path);
			return retval;
		}
		else {
			/* during the IN phase path resolution something went wrong 
			 * simply pass return value and errno to the process */
			putrv(pc->retval,pc);
			puterrno(pc->erno,pc);
			return SC_MODICALL;
		}
	}
}

#if (__NR_socketcall != __NR_doesnotexist)
/* socketcall parse arguments, (only for architectures where there is
 * one shared socketcall system call). Args must be retrieved from the
 * caller process memory */
void dsys_socketwrap_parse_arguments(struct pcb *pc, int scno)
{
	pc->private_scno = pc->sysscno | ESCNO_SOCKET;
	pc->path = NULL;
}

/* sysargs[0] is the socketcall number */
int dsys_socketwrap_index_function(struct pcb *pc, int scno)
{
	return pc->sysscno;
}

/* megawrap call for socket calls (only for architectures where there is
 * one shared socketcall system call) */
int dsys_socketwrap(int sc_number,int inout,struct pcb *pc)
{
	return dsys_commonwrap(sc_number, inout, pc,
			dsys_socketwrap_parse_arguments,
			dsys_socketwrap_index_function, ht_socketcall,
			sockmap);
}
#endif

/* virsc argument parsing function */
#ifdef OLDVIRSC
void dsys_um_virsc_parse_arguments(struct pcb *pc, int scno)
{
	struct __sysctl_args sysctlargs;
	sysctlargs.name=NULL;
	sysctlargs.nlen=0;
	pc->path = NULL;
	umoven(pc,pc->sysargs[0],sizeof(sysctlargs),&sysctlargs);
	/* private system calls are encoded with name==NULL and nlen != 0
	 * (it is usually an error case for sysctl) */
	if (sysctlargs.name == NULL && sysctlargs.nlen != 0) {
		/* virtual system call */
		if (sysctlargs.newval != NULL && sysctlargs.newlen >0 &&
				sysctlargs.newlen <= 6)
			umoven(pc,(long)(sysctlargs.newval),sysctlargs.newlen * sizeof(long), pc->sysargs);
		/* the private system call number is encoded in the nlen field */
		pc->private_scno = sysctlargs.nlen | ESCNO_VIRSC;
	} else {
		/* real sysctl, mapped on 0 */
		pc->sysargs[1] = 0;
	}
}
#else
void dsys_um_virsc_parse_arguments(struct pcb *pc, int scno)
{
	if (pc->sysargs[0] == umNULL && pc->sysargs[1] <= 6) { /* virtual syscall */
		pc->private_scno = pc->sysargs[2] | ESCNO_VIRSC;
		umoven(pc,pc->sysargs[3], pc->sysargs[1] * sizeof(long), pc->sysargs);
	} else
		pc->private_scno = ESCNO_VIRSC;
}
#endif

/* index function for sysctl: parse args above puts the 
 * number of syscall in sysargs[1]*/
int dsys_um_virsc_index_function(struct pcb *pc, int scno)
{
	return (pc->private_scno & ESCNO_MASK);
}

/* megawrap for virsc */
int dsys_um_virsc(int sc_number,int inout,struct pcb *pc)
{
	return dsys_commonwrap(sc_number, inout, pc,
			dsys_um_virsc_parse_arguments,
			dsys_um_virsc_index_function, ht_virsyscall,
			virscmap);
}

/* just the function executed by the following function (iterator) */
static void _reg_processes(struct pcb *pc,char *destination)
{
	service_ctl(MC_PROC | MC_ADD, NULL, destination, pc->umpid, (pc->pp) ? pc->pp->umpid : -1, pcbtablesize());
}

/* when a new service gets registerd all the existing processes are added
 * as a whole to the private data structures of the module, if it asked for
 * them */
static int reg_processes(char *destination)
{
	forallpcbdo(_reg_processes, destination);
	return 0;
}

/* just the function executed by the following function (iterator) */
static void _dereg_processes(struct pcb *pc,char *destination)
{
	service_ctl(MC_PROC | MC_REM, NULL, destination, pc->umpid);
}

/* when a service gets deregistered, all the data structures managed by the
 * module related to the processes must be deleted (if the module asked for
 * the processes birth history upon insertion */
static int dereg_processes(char *destination)
{
	forallpcbdo(_dereg_processes, destination);
	return 0;
}

/* UM actions for a new process entering the game*/
static void um_proc_add(struct pcb *pc)
{
	GDEBUG(0, "calling service_ctl %d %d %d %d %d %d", MC_PROC|MC_ADD, UM_NONE, -1, pc->umpid, (pc->pp)?pc->pp->umpid:-1, pcbtablesize());
	service_ctl(MC_PROC | MC_ADD, NULL, NULL, pc->umpid, (pc->pp) ? pc->pp->umpid : -1, pcbtablesize());
}

/* UM actions for a terminated process */
static void um_proc_del(struct pcb *pc)
{
	service_ctl(MC_PROC | MC_REM, NULL, NULL, pc->umpid);
}

#if 0
static mode_t local_getumask(void) {
	mode_t mask = r_umask(0);
	r_umask(mask);
	return mask;
}
#endif

/* set up all the data of the extended pcb for a new process */
void pcb_plus(struct pcb *pc,int flags,int npcflag)
{
	pc->path=pc->tmpfile2unlink_n_free=NULL;
	if (!npcflag) {
		/* CLONE_PARENT = I'm not your child, I'm your brother. So, parent is
		 * different from what we thought */
		int rootprocess=(pc->pp == pc);
		if (flags & CLONE_PARENT)
			pc->pp=pc->pp->pp;
		/* CLONE_FS = share filesystem information */
		if (flags & CLONE_FS) {
			pc->fdfs = pc->pp->fdfs;
			pc->fdfs->count++;
		} else {
			pc->fdfs =  (struct pcb_fs *) malloc(sizeof (struct pcb_fs));
			pc->fdfs->count=1;
		/* ROOT process: the first one activated by umview */
			if (rootprocess) {
				char *path=malloc(PATH_MAX);
				r_getcwd(path,PATH_MAX);
				pc->fdfs->cwd=realloc(path,strlen(path)+1);
				pc->fdfs->root=strdup("/");
				/*pc->fdfs->mask=local_getumask();*/
				pc->fdfs->mask=r_umask(0);
			} else {
				pc->fdfs->cwd=strdup(pc->pp->fdfs->cwd);
				pc->fdfs->root=strdup(pc->pp->fdfs->root);
				pc->fdfs->mask=pc->pp->fdfs->mask;
			}
		}
		if (rootprocess) {
			int ngroups=r_getgroups(0,NULL);
			r_umask(pc->fdfs->mask);
			/* create the root of the treepoch */
			pc->tst=tst_newfork(NULL);
			/* set the initial uid */
			if (secure) {
				pc->ruid=pc->euid=pc->suid=0;
				pc->rgid=pc->egid=pc->sgid=0;
				r_getresuid(NULL,&host_uid,NULL);
				r_getresgid(NULL,&host_gid,NULL);
			} else {
				r_getresuid(&pc->ruid,&pc->euid,&pc->suid);
				r_getresgid(&pc->rgid,&pc->egid,&pc->sgid);
				host_uid=pc->euid;
				host_gid=pc->egid;
			}
			pc->fsuid=pc->euid;
			pc->fsgid=pc->egid;
			pc->hte=NULL;
			pc->grouplist=supgrp_create(ngroups);
			r_getgroups(ngroups,pc->grouplist->list);
		} else {
			pc->ruid=pc->pp->ruid;
			pc->euid=pc->fsuid=pc->pp->euid;
			pc->suid=pc->pp->suid;
			pc->rgid=pc->pp->rgid;
			pc->egid=pc->fsgid=pc->pp->egid;
			pc->sgid=pc->pp->sgid;
			pc->hte=pc->pp->hte;
			pc->grouplist=supgrp_get(pc->pp->grouplist);
		}
		pc->tst=tst_newproc(&(pc->pp->tst));
#if 0
		/* if CLONE_FILES, file descriptor table is shared */
		if (flags & CLONE_FILES)
			pc->fds = pc->pp->fds;
		lfd_addproc(&(pc->fds),flags);
#endif
		um_proc_add(pc);
	}
}

/* clean up all the data structure related to a terminated process */
void pcb_minus(struct pcb *pc,int flags,int npcbflag)
{
	if (!npcbflag) {
		//printk("pcb_desctructor %d\n",pc->pid);
#if 0
		/* delete all the file descriptors */
		lfd_delproc(pc->fds);
#endif
		/* notify services */
		um_proc_del(pc);
		assert (pc->fdfs != NULL);
		/* decrement the usage couter for shared info and clean up
		 * when there are no more processes sharing the data*/
		pc->fdfs->count--;
		if (pc->fdfs->count == 0) {
			free (pc->fdfs->cwd);
			free (pc->fdfs->root);
			free (pc->fdfs);
		}
		/* notify the treepoch */
		tst_delproc(&(pc->tst));
		/*if (pc->data != NULL) {
			free(pc->data->fdfs->cwd);
			free(pc->data);
			}*/
		supgrp_put(pc->grouplist);
	}
}

/* this is the root process of a new recursive invocation for umview */
/* the process already exists, the timestamp gets converted */
int pcb_newfork(struct pcb *pc)
{
	struct treepoch *te=pc->tst.treepoch;
	pc->tst=tst_newfork(&(pc->tst));
	return (te == pc->tst.treepoch)?-1:0;
}

void pcb_getviewinfo(struct pcb *pc,struct viewinfo *vi)
{
	char *viewname;
	uname(&(vi->uname));
	vi->serverid=r_getpid();
	vi->viewid=te_getviewid(pc->tst.treepoch);
	viewname=te_getviewname(pc->tst.treepoch);
	if (viewname != NULL)
		strncpy(vi->viewname,viewname,_UTSNAME_LENGTH-1);
	else
		vi->viewname[0]=0;
}

void pcb_setviewname(struct pcb *pc,char *name)
{
	te_setviewname(pc->tst.treepoch,name);
}

struct killstruct {
	int signo;
	struct treepoch *te;
};

static void killone(struct pcb *pc, struct killstruct *ks)
{
	if (te_sameview_or_next(ks->te,pc->tst.treepoch))
	  kill(pc->pid,ks->signo);
}

void killall(struct pcb *pc, int signo)
{
	struct killstruct ks={signo, pc->tst.treepoch};
	char *viewname=te_getviewname(pc->tst.treepoch);
	viewid_t viewid=te_getviewid(pc->tst.treepoch);
	
	if (viewname)
		printk("View %d (%s): Sending processes the %s signal\n",viewid,viewname,_sys_sigabbrev[signo]);
	else
		printk("View %d: Sending processes the %s signal\n",viewid,_sys_sigabbrev[signo]);
	forallpcbdo(killone,&ks);
}
	
#if 0
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
#endif

/* choice function for system calls using a file descriptor */
struct ht_elem *choice_fd(int sc_number,struct pcb *pc)
{
	int fd=pc->sysargs[0];
	return ht_fd(pc->fds,fd,1);
}

/* choice sd (just the system call number is the choice parameter) */
struct ht_elem *choice_sc(int sc_number,struct pcb *pc)
{
	return ht_check(CHECKSC,&sc_number,NULL,1);
}

/* choice mount (mount point must be defined + filesystemtype is used
 * instead of the pathname for service selection) */
struct ht_elem *choice_mount(int sc_number,struct pcb *pc)
{
	pc->path=um_abspath(AT_FDCWD,pc->sysargs[1],pc,&(pc->pathstat),0); 

	if (pc->path!=um_patherror) {
		char filesystemtype[PATH_MAX];
		unsigned long fstype=pc->sysargs[2];
		if (umovestr(pc,fstype,PATH_MAX,filesystemtype) == 0)
			return ht_check(CHECKFSTYPE,get_alias(CHECKFSALIAS,filesystemtype),NULL,0);
		else
			return NULL;
	} else
		return NULL;
}

/* choice path (filename must be defined) */
struct ht_elem *choice_path(int sc_number,struct pcb *pc)
{
	pc->path=um_abspath(AT_FDCWD,pc->sysargs[0],pc,&(pc->pathstat),0); 
	//printk("choice_path %d %s\n",sc_number,pc->path);

	if (pc->path==um_patherror){
		/*		char buff[PATH_MAX];
					umovestr(pc,pc->sysargs[0],PATH_MAX,buff);
					printk("um_patherror: %s",buff);*/
		return NULL;
	}
	else 
		return ht_check(CHECKPATH,pc->path,&(pc->pathstat),1);
}

struct ht_elem *choice_path_exact(int sc_number,struct pcb *pc)
{
	pc->path=um_abspath(AT_FDCWD,pc->sysargs[0],pc,&(pc->pathstat),1);
	//printk("choice_path_exact %d %s\n",sc_number,pc->path);
	if (pc->path==um_patherror){
		return NULL;
	}
	else if (strcmp(pc->path,"/")==0) 
		return ht_check(CHECKPATHEXACT,"",&(pc->pathstat),1);
	else
		return ht_check(CHECKPATHEXACT,pc->path,&(pc->pathstat),1);
}

/* choice pathat (filename must be defined) */
struct ht_elem *choice_pathat(int sc_number,struct pcb *pc)
{
	pc->path=um_abspath(pc->sysargs[0],pc->sysargs[1],pc,&(pc->pathstat),0);
	if (pc->path==um_patherror)
		return NULL;
	else 
		return ht_check(CHECKPATH,pc->path,&(pc->pathstat),1);
}

/* choice sockpath (filename can be NULL) */
struct ht_elem *choice_sockpath(int sc_number,struct pcb *pc)
{
	if (pc->sysargs[0] != 0) {
		pc->path=um_abspath(AT_FDCWD,pc->sysargs[0],pc,&(pc->pathstat),0); 

		if (pc->path==um_patherror){
			/*		char buff[PATH_MAX];
						umovestr(pc,pc->sysargs[0],PATH_MAX,buff);
						printk("um_patherror: %s",buff);*/
			return NULL;
		} else
			return ht_check(CHECKPATH,pc->path,&(pc->pathstat),1);
	} else
		return ht_check(CHECKSOCKET, &(pc->sysargs[1]),NULL,1);
}

/* choice link (dirname must be defined, basename can be non-existent) */
struct ht_elem *choice_link(int sc_number,struct pcb *pc)
{
	pc->path=um_abspath(AT_FDCWD,pc->sysargs[0],pc,&(pc->pathstat),1); 
	//printk("choice_path %d %s\n",sc_number,pc->path);
	if (pc->path==um_patherror)
		return NULL;
	else 
		return ht_check(CHECKPATH,pc->path,&(pc->pathstat),1);
}

/* choice linkat (dirname must be defined, basename can be non-existent) */
struct ht_elem *choice_linkat(int sc_number,struct pcb *pc)
{
	pc->path=um_abspath(pc->sysargs[0],pc->sysargs[1],pc,&(pc->pathstat),1);
	if (pc->path==um_patherror)
		return NULL;
	else
		return ht_check(CHECKPATH,pc->path,&(pc->pathstat),1);
}

/* choice unlinkat (unlink = rmdir or unlink depending on flag) */
struct ht_elem *choice_unlinkat(int sc_number,struct pcb *pc)
{
	pc->path=um_abspath(pc->sysargs[0],pc->sysargs[1],pc,&(pc->pathstat),
			!(pc->sysargs[2] & AT_REMOVEDIR));
	if (pc->path==um_patherror)
		return NULL;
	else 
		return ht_check(CHECKPATH,pc->path,&(pc->pathstat),1);
}

/* utimensat has a (crazy) behavior with filename==NULL */
struct ht_elem *choice_utimensat(int sc_number,struct pcb *pc)
{
	if (pc->sysargs[1] == umNULL)
		pc->path=utimensat_nullpath(pc->sysargs[0],pc,&(pc->pathstat),
				pc->sysargs[3] & AT_SYMLINK_NOFOLLOW);
	else
		pc->path=um_abspath(pc->sysargs[0],pc->sysargs[1],pc,&(pc->pathstat),
				pc->sysargs[3] & AT_SYMLINK_NOFOLLOW);
	if (pc->path==um_patherror)
		return NULL;
	else
		return ht_check(CHECKPATH,pc->path,&(pc->pathstat),1);
}

/* choice path or link at (filename must be defined or can be non-existent) */
/* depending on AT_SYMLINK_NOFOLLOW on the 4th parameter */
struct ht_elem *choice_pl4at(int sc_number,struct pcb *pc)
{
	pc->path=um_abspath(pc->sysargs[0],pc->sysargs[1],pc,&(pc->pathstat),
			pc->sysargs[3] & AT_SYMLINK_NOFOLLOW);
	if (pc->path==um_patherror)
		return NULL;
	else
		return ht_check(CHECKPATH,pc->path,&(pc->pathstat),1);
}

/* depending on AT_SYMLINK_NOFOLLOW on the 5th parameter */
struct ht_elem *choice_pl5at(int sc_number,struct pcb *pc)
{
	pc->path=um_abspath(pc->sysargs[0],pc->sysargs[1],pc,&(pc->pathstat),
			pc->sysargs[4] & AT_SYMLINK_NOFOLLOW);
	if (pc->path==um_patherror)
		return NULL;
	else
		return ht_check(CHECKPATH,pc->path,&(pc->pathstat),1);
}

/* choice link (dirname must be defined, basename can be non-existent second arg)*/
struct ht_elem *choice_link2(int sc_number,struct pcb *pc)
{
	pc->path=um_abspath(AT_FDCWD,pc->sysargs[1],pc,&(pc->pathstat),1); 
	//printk("choice_link2 %d %s\n",sc_number,pc->path);
	if (pc->path==um_patherror)
		return NULL;
	else {
		struct ht_elem *hte_new=ht_check(CHECKPATH,pc->path,&(pc->pathstat),1);
		/* if NEW is real and OLD is virtual ==> EXDEV */
		if (hte_new == NULL && sc_number != __NR_symlink) {
			struct stat64 oldstat;
			char *oldpath=um_abspath(AT_FDCWD,pc->sysargs[0],pc,&oldstat,1);
			if (oldpath != um_patherror) {
				struct ht_elem *hte_old=ht_check(CHECKPATH,oldpath,&oldstat,0);
				if (hte_old != NULL) {
					free(pc->path);
					pc->path = um_patherror;
					pc->erno = EXDEV;
				}
				free(oldpath);
			}
			return NULL;
		} else
			return hte_new;
	}
}

struct ht_elem *choice_link2at(int sc_number,struct pcb *pc)
{
	pc->path=um_abspath(pc->sysargs[1],pc->sysargs[2],pc,&(pc->pathstat),1); 
	//printk("choice_path %d %s\n",sc_number,pc->path);
	if (pc->path==um_patherror)
		return NULL;
	else
		return ht_check(CHECKPATH,pc->path,&(pc->pathstat),1);
}

struct ht_elem *choice_link3at(int sc_number,struct pcb *pc)
{
	pc->path=um_abspath(pc->sysargs[2],pc->sysargs[3],pc,&(pc->pathstat),1); 
	//printk("choice_path %d %s\n",sc_number,pc->path);
	if (pc->path==um_patherror)
		return NULL;
	else {
		struct ht_elem *hte_new=ht_check(CHECKPATH,pc->path,&(pc->pathstat),1);
		/* if NEW is real and OLD is virtual ==> EXDEV */
		if (hte_new == NULL) {
			struct stat64 oldstat;
			int dontfollowlink;
			char *oldpath;
			if (sc_number == __NR_linkat)
				dontfollowlink=!(pc->sysargs[4] & AT_SYMLINK_FOLLOW);
			else
				dontfollowlink=1;
			oldpath=um_abspath(pc->sysargs[0],pc->sysargs[1],pc,&oldstat,dontfollowlink);
			if (oldpath != um_patherror) {
				struct ht_elem *hte_old=ht_check(CHECKPATH,oldpath,&oldstat,0);
				if (hte_old != NULL) {
					free(pc->path);
					pc->path = um_patherror;
					pc->erno = EXDEV;
				}
				free(oldpath);
			}
			return NULL;
		} else
			return hte_new;
	}
}

/* choice function for 'socket', usually depends on the Protocol Family */
struct ht_elem *choice_socket(int sc_number,struct pcb *pc)
{
	return ht_check(CHECKSOCKET, &(pc->sysargs[0]),NULL,1);
}

/* choice function for mmap: only *non anonymous* mmap must be mapped
 * depending on the service responsible for the fd. */
struct ht_elem *choice_mmap(int sc_number,struct pcb *pc)
{
	long fd=pc->sysargs[4];
	long flags=pc->sysargs[3];

	if (flags & MAP_ANONYMOUS)
		return NULL;
	else
		return ht_fd(pc->fds,fd,1);
}

/* dummy choice function for unimplemented syscalls */
struct ht_elem *always_null(int sc_number,struct pcb *pc)
{
	return NULL;
}

/* dummy choice function for unimplemented syscalls */
char always_umnone(int sc_number,struct pcb *pc)
{
	return UM_NONE;
}

/* preload arguments: convert socket args in case socket calls are
 * ordinary system calls */
void dsys_megawrap_parse_arguments(struct pcb *pc, int scno)
{
	pc->private_scno = pc->sysscno;
	pc->path = NULL;
}

/* index function for system call: uscno gives the index */
int dsys_megawrap_index_function(struct pcb *pc, int scno)
{
	return uscno(scno);
}

/* system call megawrap */
int dsys_megawrap(int sc_number,int inout,struct pcb *pc)
{
	return dsys_commonwrap(sc_number, inout, pc,
			dsys_megawrap_parse_arguments,
			dsys_megawrap_index_function, ht_syscall, scmap);
}

/* for modules: get the caller pid */
int um_mod_getpid()
{
	struct pcb *pc=get_pcb();
	return ((pc && (pc->flags & PCB_INUSE))?pc->pid:0);
}

/* for modules: get data from the caller process */
void um_mod_set_hte(struct ht_elem *hte)
{
	struct pcb *pc=get_pcb();
	pc->hte=hte;
}

struct ht_elem *um_mod_get_hte(void)
{
	struct pcb *pc=get_pcb();
	return pc->hte;
}

int um_mod_umoven(long addr, int len, void *_laddr)
{
	struct pcb *pc=get_pcb();
	if (pc) {
		if (pc->flags && PCB_INUSE)
			return (umoven(pc,addr,len,_laddr));
		else {
			memcpy(_laddr,(void *)addr,len);
			return 0;
		}
	}
	else 
		return -1;
}

/* for modules: get string data from the caller process */
int um_mod_umovestr(long addr, int len, void *_laddr)
{
	struct pcb *pc=get_pcb();
	if (pc) {
		if (pc->flags && PCB_INUSE)
			return (umovestr(pc,addr,len,_laddr));
		else {
			strncpy((char *)_laddr,(char *)addr, len);
			return 0;
		}
	}
	else 
		return -1;
}

/* for modules: store data to the caller process memory */
int um_mod_ustoren(long addr, int len, void *_laddr)
{
	struct pcb *pc=get_pcb();
	if (pc) {
		if (pc->flags && PCB_INUSE)
			return (ustoren(pc,addr,len,_laddr));
		else {
			memcpy((void *)addr,_laddr,len);
			return 0;
		}
	}
	else 
		return -1;
}

/* for modules: store string data to the caller process memory */
int um_mod_ustorestr(long addr, int len, void *_laddr)
{
	struct pcb *pc=get_pcb();
	if (pc) {
		if (pc->flags && PCB_INUSE)
			return (ustorestr(pc,addr,len,_laddr));
		else {
			strncpy((char *)addr,(char *)_laddr,len);
			return 0;
		}
	}
	else 
		return -1;
}

/* for modules: get the syscall number */
int um_mod_getsyscallno(void)
{
	struct pcb *pc=get_pcb();
	if (pc) {
		if (pc->flags && PCB_INUSE)
			return (pc->private_scno);
		else {
			struct npcb *npc=(struct npcb *)pc;
			return (npc->private_scno);
		}
	} else 
		return 0;
}

/* for modules: get the syscall args */
unsigned long *um_mod_getargs(void)
{
	struct pcb *pc=get_pcb();
	if (pc) {
		if (pc->flags && PCB_INUSE)
			return (pc->sysargs);
		else {
			struct npcb *npc=(struct npcb *)pc;
			return (npc->sysargs);
		}
	} else{
		return NULL;
	}
}

/* for modules: get the user-mode process id (small integer,
 * suitable for storing private data into arrays) */
int um_mod_getumpid(void)
{
	struct pcb *pc=get_pcb();
	/* this returns 0 for nested calls */
	return ((pc && (pc->flags & PCB_INUSE))?pc->umpid:0);
	/* this returns the id of the caller process that originally made the
	 * call
	 * UMPID4NESTED
	 * return pc->umpid;
	 */
}

/* for modules: get the stat info for the current path */ 
struct stat64 *um_mod_getpathstat(void)
{
	struct pcb *pc=get_pcb();
	if (pc) {
		if (pc->pathstat.st_mode == 0)
			return NULL;
		else
			return &(pc->pathstat);
	}
	else
		return NULL;
}

/* for modules: get the absolute path*/ 
char *um_mod_getpath(void)
{
	struct pcb *pc=get_pcb();
	if (pc) 
		return pc->path;
	else
		return NULL;
}

int um_mod_getresuid(uid_t *ruid, uid_t *euid, uid_t *suid)
{
	struct pcb *pc=get_pcb();
	if (pc) {
		if (ruid) *ruid=pc->ruid;
		if (euid) *euid=pc->euid;
		if (suid) *suid=pc->suid;
		return 0;
	} else
		return -1;
}

int um_mod_getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid)
{
	struct pcb *pc=get_pcb();
	if (pc) {
		if (rgid) *rgid=pc->rgid;
		if (egid) *egid=pc->egid;
		if (sgid) *sgid=pc->sgid;
		return 0;
	} else
		return -1;
}

int um_mod_setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
	struct pcb *pc=get_pcb();
	if (pc) {
		if (ruid != -1) pc->ruid=ruid;
		if (euid != -1) pc->euid=euid;
		if (suid != -1) pc->suid=suid;
		return 0;
	} else
		return -1;
}

int um_mod_setresgid(gid_t rgid, gid_t egid, gid_t sgid)
{
	struct pcb *pc=get_pcb();
	if (pc) {
		if (rgid != -1) pc->rgid=rgid;
		if (egid != -1) pc->egid=egid;
		if (sgid != -1) pc->sgid=sgid;
		return 0;
	} else
		return -1;
}

int um_mod_getfs_uid_gid(uid_t *fsuid, gid_t *fsgid)
{
	struct pcb *pc=get_pcb();
	if (pc) {
		if (fsuid) *fsuid=pc->fsuid;
		if (fsgid) *fsgid=pc->fsgid;
		return 0;
	} else
		return -1;
}

int um_mod_setfs_uid_gid(uid_t fsuid, gid_t fsgid)
{
	struct pcb *pc=get_pcb();
	if (pc) {
		if (fsuid != -1) pc->fsuid=fsuid;
		if (fsgid != -1) pc->fsgid=fsgid;
		return 0;
	} else
		return -1;
}

/* for modules: get the system call type*/ 
int um_mod_getsyscalltype(int escno)
{
	return escmapentry(escno)->setofcall;
	/*
	int usc=uscno(scno);
	if (usc >= 0) 
		return USC_TYPE(usc);
	else
		return -1;*/
}

/* for modules: get the number of syscall for this architecture
 * (not all the archs define NR_SYSCALLS*/
int um_mod_nrsyscalls(void)
{
	return _UM_NR_syscalls;
}

int um_mod_capcheck(int capability)
{
	struct pcb *pc=get_pcb();
	if (secure && capcheck(capability,pc))
		return -1;
	else
		return 0;
}

int um_mod_secure(void) {
	return secure;
}

/* management of supplementary groups */

struct supgroups *supgrp_create(size_t size)
{
	struct supgroups *rv=malloc(sizeof(struct supgroups) + size*sizeof(gid_t));
	assert(rv != NULL);
	rv->size=size;
	rv->count=1;
	return rv;
}

/* atomic operations as different umview threads may have access to this */

struct supgroups *supgrp_get(struct supgroups *supgrp)
{
	__sync_fetch_and_add(&(supgrp->count),1);
	return supgrp;
}

void supgrp_put(struct supgroups *supgrp)
{
	int oldval = __sync_fetch_and_sub(&(supgrp->count),1);

	if (oldval == 1)
		free(supgrp);
}

int capcheck(int capability, struct pcb *pc)
{
	if (pc->euid == 0)
		return 0;
	else {
		return -1;
	}
}

/* for modules: management of module filetab. */
#define FILETABSTEP 4 /* must be a power of two */
#define FILETABSTEP_1 (FILETABSTEP-1)
static pthread_mutex_t g_filetab_mutex = PTHREAD_MUTEX_INITIALIZER;

static void **g_filetab=NULL;
static long g_filetabmax=0;
static long g_filetabsize=0;
static long g_filetabfree=-1;

int addfiletab(int size)
{
	int rv;
	pthread_mutex_lock( &g_filetab_mutex );
	if (g_filetabfree>=0) {
		rv=g_filetabfree;
		g_filetabfree=(long)(g_filetab[rv]);
	} else {
		rv=g_filetabmax++;
		if (rv>=g_filetabsize) {
			g_filetabsize=(rv + FILETABSTEP) & ~FILETABSTEP_1;
			g_filetab=realloc(g_filetab,g_filetabsize* sizeof(void *));
			assert(g_filetab);
		}
	}
	g_filetab[rv]=malloc(size);
	assert(g_filetab[rv]);
	pthread_mutex_unlock( &g_filetab_mutex );
	return rv;
}

void delfiletab(int i)
{
	free(g_filetab[i]);
	pthread_mutex_lock( &g_filetab_mutex );
	/* unused elements gets linked by re-using the void pointers
		 as the index of the next element */
	g_filetab[i]=(void *)g_filetabfree;
	g_filetabfree=i;
	pthread_mutex_unlock( &g_filetab_mutex );
}

void *getfiletab(int i)
{
	void *rv;
	pthread_mutex_lock( &g_filetab_mutex );
	rv=g_filetab[i];
	pthread_mutex_unlock( &g_filetab_mutex );
	return rv;
}

#ifdef _VIEWOS_KM
/* upcall: hashtable calls this function when an element gets added/deleted */
static void ht_zerovirt_upcall(int tag, unsigned char type,const void *obj,int objlen,long mountflags)
{
	/* ghost mount: this mount does not switch off/on zerovirt.
		 update the ghosthash table instead */
	if (type==CHECKPATH && (mountflags & MS_GHOST)) {
		switch (tag) {
			case HT_ADD: ghosthash_add(obj,objlen); break;
			case HT_DEL: ghosthash_del(obj,objlen); break;
		}
	} else {
		/* ht_count keeps track of the number of elements in the hashtable
			 for each tag*/
		static unsigned long ht_count[NCHECKS];
		int oldsum=ht_count[CHECKPATH] + ht_count[CHECKCHRDEVICE] + ht_count[CHECKBLKDEVICE];
		int newsum;
		switch (tag) {
			case HT_ADD: ht_count[type]++; break;
			case HT_DEL: ht_count[type]--; break;
		}
		newsum=ht_count[CHECKPATH] + ht_count[CHECKCHRDEVICE] + ht_count[CHECKBLKDEVICE];
		/* if this is the first (non ghost) element turn zerovirt off */
		if (oldsum == 0 && newsum == 1)
			capture_km_global_get_path_syscalls();
		/* if this is the last (non ghost) element turn zerovirt on */
		if (oldsum == 1 && newsum == 0)
			capture_km_global_skip_path_syscalls();
	}
}
#endif

/* scdtab: interface between capture_* and the wrapper (wrap-in/out)
 * implemented for each system call (see um_*.c files) */
/* capture_* call a "megawrap" that implements all the common code
 * and then forwards the call to the functions defined in scmap.c */
void scdtab_init()
{
	register int i;
	_service_init();
	/* init service management */
	service_addregfun(MC_PROC, (sysfun)reg_processes, (sysfun)dereg_processes);

#ifdef OLDVIRSC
	/* sysctl is used to define private system calls */
	scdtab[__NR__sysctl]=dsys_um_virsc;
	scdnarg[__NR__sysctl]=1;
#else
	/* pivot_root is used to define private system calls */
	scdtab[__NR_pivot_root]=dsys_um_virsc;
	scdnarg[__NR_pivot_root]=4;
#endif

	/* initialize scmap */
	init_scmap();

	/* define the megawrap for the syscalls defined in scmap */
	for (i=0; i<scmap_scmapsize; i++) {
		int scno=scmap[i].scno;
		if (scno >= 0)  {
			scdtab[scno]=dsys_megawrap;
			scdnarg[scno]=NARGS(scmap[i].nargx);
		}
	}

	/* linux has a single call for all the socket calls 
	 * in several architecture (i386, ppc), socket calls are standard
	 * system calls in others (x86_64) */
#if (__NR_socketcall != __NR_doesnotexist)
	for (i=1; i<scmap_sockmapsize; i++) 
		sockcdtab[i]=dsys_socketwrap;
#endif

	/* start umproc (file management) and define an atexit function for
	 * the final cleaning up */
	um_proc_open();
#ifdef _VIEWOS_KM
	ht_init(ht_zerovirt_upcall);
#endif
	atexit(um_proc_close);
	atexit(ht_terminate);
}
