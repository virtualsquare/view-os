/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   um_plusio: io wrappers (second part)
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
#include <sys/statfs.h>
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
#include "uid16to32.h"

#define umNULL ((long) NULL)

int wrap_in_mkdir(int sc_number,struct pcb *pc,
		service_t sercode, sysfun um_syscall)
{
	int mode;
#ifdef __NR_mkdirat
	if (sc_number == __NR_mkdirat)
		mode=pc->sysargs[2];
	else
#endif
		mode=pc->sysargs[1];
	if ((pc->retval = um_syscall(pc->path,mode & ~ (pc->fdfs->mask))) < 0)
		pc->erno=errno;
	return SC_FAKE;
}

int wrap_in_mknod(int sc_number,struct pcb *pc,
		service_t sercode, sysfun um_syscall)
{
	int mode;
	int dev;
#ifdef __NR_mknodat
	if (sc_number == __NR_mknodat) {
		mode=pc->sysargs[2];
		dev=pc->sysargs[3];
	} else
#endif
	{
		mode=pc->sysargs[1];
		dev=pc->sysargs[3];
	}
	if ((pc->retval = um_syscall(pc->path,mode & ~ (pc->fdfs->mask),dev)) < 0)
		pc->erno=errno;
	return SC_FAKE;
}

int wrap_in_unlink(int sc_number,struct pcb *pc,
		service_t sercode, sysfun um_syscall)
{
#ifdef __NR_unlinkat
	if (sc_number == __NR_unlinkat && (pc->sysargs[2] & AT_REMOVEDIR)) {
		 um_syscall=service_syscall(sercode,uscno(__NR_rmdir));
	} 
#endif
	if ((pc->retval = um_syscall(pc->path)) < 0)
		pc->erno=errno;
	return SC_FAKE;
}

int wrap_in_chown(int sc_number,struct pcb *pc,
		service_t sercode, sysfun um_syscall)
{
	unsigned int owner,group;
#ifdef __NR_fchownat
	if (sc_number == __NR_fchownat) {
		owner=pc->sysargs[2];
		group=pc->sysargs[3];
	} else
#endif
	{
		owner=pc->sysargs[1];
		group=pc->sysargs[2];
	}
#if __NR_chown != __NR_chown32
	if (sc_number == __NR_chown || sc_number == __NR_lchown) {
		owner=id16to32(owner);
		group=id16to32(group);
	}
#endif
	if ((pc->retval = um_syscall(pc->path,owner,group)) < 0)
		pc->erno=errno;
	return SC_FAKE;
}

int wrap_in_fchown(int sc_number,struct pcb *pc,
		service_t sercode, sysfun um_syscall)
{
	char *path=fd_getpath(pc->fds,pc->sysargs[0]);
	if (path==NULL) {
		pc->retval= -1;
		pc->erno= EBADF;
		return SC_FAKE;
	} else {
		unsigned int owner,group;
		owner=pc->sysargs[1];
		group=pc->sysargs[2];
#if __NR_fchown != __NR_fchown32
		if (sc_number == __NR_fchown) {
			owner=id16to32(owner);
			group=id16to32(group);
		}
#endif
		if ((pc->retval = um_syscall(path,owner,group)) < 0)
			pc->erno=errno;
		return SC_FAKE;
	}
}

int wrap_in_chmod(int sc_number,struct pcb *pc,
		service_t sercode, sysfun um_syscall)
{
	int mode;
#ifdef __NR_fchmodat
	if (sc_number == __NR_fchmodat)
		mode=pc->sysargs[2];
	else
#endif
		mode=pc->sysargs[1];
	if ((pc->retval = um_syscall(pc->path,mode)) < 0)
		pc->erno=errno;
	return SC_FAKE;
}

int wrap_in_fchmod(int sc_number,struct pcb *pc,
		service_t sercode, sysfun um_syscall)
{
	char *path =fd_getpath(pc->fds,pc->sysargs[0]);
	if (path==NULL) {
		pc->retval= -1;
		pc->erno= EBADF;
		return SC_FAKE;
	} else {
		int mode;
		mode=pc->sysargs[1];
		if ((pc->retval = um_syscall(path,mode)) < 0)
			pc->erno=errno;
		return SC_FAKE;
	}
}

/* DUP & DUP2.
 * Always processed in any case.
 * if the dup fd refers an open file it must be closed (if it is managed by a service 
 * module the close request must be forwarded to that module).
 */

/* DUP management: dup gets executed both by the process (the fifo is
 * dup-ped when the file is virtual) and umview records the operation 
 * DUP does not exist for modules */
int wrap_in_dup(int sc_number,struct pcb *pc,
		service_t sercode, sysfun um_syscall)
{
	int sfd;
	if (sc_number == __NR_dup) 
		pc->sysargs[1]= -1;
#ifdef __NR_dup3
	if (sc_number != __NR_dup3) 
#endif
		pc->sysargs[2]= 0;
	sfd=fd2sfd(pc->fds,pc->sysargs[0]);
	GDEBUG(4, "DUP %d %d sfd %d %s",pc->sysargs[0],pc->sysargs[1],sfd,fd_getpath(pc->fds,pc->sysargs[0]));
	if (pc->sysargs[1] == um_mmap_secret || (sfd < 0 && sercode != UM_NONE)) {
		pc->retval= -1;
		pc->erno= EBADF;
		return SC_FAKE;
	} else {
		pc->retval=fd2lfd(pc->fds,pc->sysargs[0]);
		pc->erno = 0;
		if (pc->retval >= 0)
			lfd_dup(pc->retval);
		return SC_CALLONXIT;
	}
}

int wrap_out_dup(int sc_number,struct pcb *pc)
{
	/* SC_CALLONXIT both for UM_NONE and module managed files.
	 * FAKE only when the module gave an error */
	if (pc->behavior == SC_CALLONXIT) {
		int fd=getrv(pc);
		if (fd >= 0 &&
				(pc->retval < 0
				 || lfd_getservice(pc->retval) == UM_NONE
				 || addfd(pc,fd) == 0)) {
			/* DUP2 case, the previous fd has been closed, umview must
			 * update its lfd table */
			if (pc->sysargs[1] != -1) {
				int oldfd=pc->sysargs[1];
				int oldlfd=fd2lfd(pc->fds,oldfd);
				if (oldlfd >= 0) /* socket and stdin/out/err are -1*/
				{
					if (lfd_getservice(oldlfd) != UM_NONE)
						delfd(pc,pc->sysargs[1]);
					lfd_deregister_n_close(pc->fds,oldfd);
				}
			}
			if (pc->retval >= 0)
				lfd_register(pc->fds,fd,pc->retval);
#ifdef __NR_dup3
			if (pc->sysargs[2] & O_CLOEXEC) {
				fd_setfdfl(pc->fds,fd,FD_CLOEXEC);
			}
#endif
		} else {
			lfd_close(pc->retval);
		}
	} else {
		putrv(pc->retval,pc);
		puterrno(pc->erno,pc);
	}
	return STD_BEHAVIOR;
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

static inline void get_flock64(struct pcb *pc,unsigned long addr,struct um_flock64 *fl)
{
	umoven(pc,addr,sizeof(struct um_flock64),fl);
}

static inline void put_flock64(struct pcb *pc,unsigned long addr,struct um_flock64 *fl)
{
	ustoren(pc,addr,sizeof(struct um_flock64),fl);
}

static inline void get_flock32(struct pcb *pc,unsigned long addr,struct um_flock64 *fl)
{
	struct um_flock32 fl32;
	umoven(pc,addr,sizeof(struct um_flock32),&fl32);
	fl->l_type=fl32.l_type;
	fl->l_whence=fl32.l_whence;
	fl->l_start=fl32.l_start;
	fl->l_len=fl32.l_len;
	fl->l_pid=fl32.l_pid;
}

static inline void put_flock32(struct pcb *pc,unsigned long addr,struct um_flock64 *fl)
{
	struct um_flock32 fl32;
	fl32.l_type=fl->l_type;
	fl32.l_whence=fl->l_whence;
	fl32.l_start=fl->l_start;
	fl32.l_len=fl->l_len;
	fl32.l_pid=fl->l_pid;
	ustoren(pc,addr,sizeof(struct um_flock32),&fl32);
}

int wrap_in_fcntl(int sc_number,struct pcb *pc,
		service_t sercode, sysfun um_syscall)
{
	int fd= pc->sysargs[0];
	int cmd= pc->sysargs[1];
	unsigned long arg=pc->sysargs[2];
	int sfd=fd2sfd(pc->fds,pc->sysargs[0]);
	//printf("wrap_in_fcntl %d %d %d %d \n",pc->sysargs[0],sfd,cmd,fd2lfd(pc->fds,pc->sysargs[0]));
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
		return SC_FAKE;
	} else {
		switch (cmd) {
			case F_DUPFD:
				pc->retval=fd2lfd(pc->fds,fd);
				if (pc->retval < 0)
					return STD_BEHAVIOR;
				else {
					lfd_dup(pc->retval);
					return SC_CALLONXIT;
				}
			case F_GETFD:
				if ((pc->retval=fd_getfdfl(pc->fds,fd)) < 0)
					pc->erno=EBADF;
				else
					pc->erno=0;
				break;
			case F_SETFD:
				if ((pc->retval=fd_setfdfl(pc->fds,fd,arg)) < 0)
					pc->erno=EBADF;
				else
					pc->erno=0;
				break;
			case F_GETLK:
			case F_SETLK:
			case F_SETLKW:
#ifdef F_GETLK64
			case F_GETLK64:
			case F_SETLK64:
			case F_SETLKW64:
#endif
				{
					struct um_flock64 flock;
#ifdef __NR_fcntl64
					if (sc_number == __NR_fcntl64 
#ifdef F_GETLK64
							|| cmd==F_GETLK64 || cmd==F_SETLK64 || cmd==F_SETLKW64
#endif
						 )
						get_flock64(pc,arg,&flock);
					else
						get_flock32(pc,arg,&flock);
#else
					get_flock64(pc,arg,&flock);
#endif
					if ((pc->retval = um_syscall(sfd,cmd,&flock)) == -1)
						pc->erno= errno;
					if (pc->retval < 0 && pc->erno == ENOSYS) { /* last chance */
						fprint2("Locking unsupported\n");
						pc->retval= -1;
						pc->erno= EBADF;
						return SC_FAKE;
					}
					if (cmd==F_GETLK
#ifdef F_GETLK64
							|| cmd==F_GETLK64
#endif
						 ) {
#ifdef __NR_fcntl64
						if (sc_number == __NR_fcntl64
#ifdef F_GETLK64
								|| cmd==F_GETLK64 || cmd==F_SETLK64 || cmd==F_SETLKW64
#endif
							 )
							put_flock64(pc,arg,&flock);
						else
							put_flock32(pc,arg,&flock);
#else
						put_flock64(pc,arg,&flock);
#endif
					}
					//fprint2("LOCK %d %d %d %d\n",sc_number,fd,cmd,pc->retval,pc->erno);
					break;
				}
			default:
				if ((pc->retval = um_syscall(sfd,cmd,arg)) == -1)
					pc->erno= errno;
				if (pc->retval < 0 && pc->erno == ENOSYS) { /* last chance */
					switch (cmd) {
						/* this is just a workaround for module that does not manage
						 * F_SETFL/F_GETFL */
						case F_GETFL:
							if ((pc->retval=fd_getflfl(pc->fds,fd)) < 0)
								pc->erno=EBADF;
							else
								pc->erno=0;
							break;
							/* F_SETFL is useless if the module does not change the flags
							 * effectively */
					}
				}
		}
		return SC_FAKE; /*except for DUP*/
	}
}

int wrap_out_fcntl(int sc_number,struct pcb *pc)
{
	int fd;
	switch (pc->sysargs[1]) {
		case F_DUPFD:
			fd=getrv(pc);
			//printf("F_DUPFD %d->%d\n",pc->retval,fd);
			if (fd>=0)
				lfd_register(pc->fds,fd,pc->retval);
			else
				lfd_close(pc->retval);
			return STD_BEHAVIOR;
			break;
		default:
			//printf("fcntl returns %d %d\n",pc->retval,pc->erno);
			putrv(pc->retval,pc);
			puterrno(pc->erno,pc);
			return SC_MODICALL;
			break;
	}
}

int wrap_in_fsync(int sc_number,struct pcb *pc,
		service_t sercode, sysfun um_syscall)
{
	int sfd=fd2sfd(pc->fds,pc->sysargs[0]);
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
		return SC_FAKE;
	} else {
		if ((pc->retval = um_syscall(sfd)) < 0)
			pc->erno=errno;
	}
	return SC_FAKE;
}

int wrap_in_link(int sc_number,struct pcb *pc,
		service_t sercode, sysfun um_syscall)
{
	struct stat64 sourcest;
	char *source;
	int olddirfd;
	long oldpath;

#ifdef __NR_linkat
	if (sc_number == __NR_linkat || sc_number == __NR_renameat) {
		olddirfd=pc->sysargs[0];
		oldpath=pc->sysargs[1];
	} else
#endif
	{
		olddirfd=AT_FDCWD;
		oldpath=pc->sysargs[0];
	} 

	source=um_abspath(olddirfd,oldpath,pc,&sourcest,0);

	if (source==um_patherror) {
		pc->retval= -1;
		pc->erno= ENOENT;
	} else {
		/* inter module file hard link are unsupported! */
		int ser2=service_check(CHECKPATH,source,0);
		if (ser2 != sercode) {
			pc->retval= -1;
			pc->erno= EXDEV;
		} else {
			if ((pc->retval=um_syscall(source,pc->path)) < 0)
				pc->erno= errno;
		}
		free(source);
	}
	return SC_FAKE;
}

int wrap_in_symlink(int sc_number,struct pcb *pc,
		service_t sercode, sysfun um_syscall)
{
	char *source;
	
	source=um_getpath(pc->sysargs[0],pc);

	if (source==um_patherror) {
		pc->retval= -1;
		pc->erno= ENOENT;
	} else {
		if ((pc->retval=um_syscall(source,pc->path)) < 0)
			pc->erno= errno;
		free(source);
	}
	return SC_FAKE;
}

/* UTIME & UTIMES wrap in function */
int wrap_in_utime(int sc_number,struct pcb *pc,
		service_t sercode, sysfun um_syscall)
{
	unsigned long argaddr;
	struct timeval tv[2];
	struct timeval *larg;
#ifdef __NR_futimesat
	if (sc_number == __NR_futimesat
#ifdef __NR_utimensat
			|| sc_number==__NR_utimensat
#endif
			)
		argaddr=pc->sysargs[2];
	else
#endif
		argaddr=pc->sysargs[1];
	if (argaddr == umNULL) 
		larg=NULL;
	else {
		if (sc_number == __NR_utime) {
			/* UTIME */
			struct utimbuf buf;
			umoven(pc,argaddr,sizeof(struct utimbuf),&buf);
			tv[0].tv_sec=buf.actime;
			tv[1].tv_sec=buf.modtime;
			tv[0].tv_usec=tv[1].tv_usec=0;
		} else
#ifdef __NR_utimensat
			if (sc_number == __NR_utimensat) {
				struct timespec times[2];
				umoven(pc,argaddr,2*sizeof(struct timespec),times);
				tv[0].tv_sec=times[0].tv_sec;
				tv[1].tv_sec=times[1].tv_sec;
				tv[0].tv_usec=times[0].tv_nsec/1000;
				tv[1].tv_usec=times[1].tv_nsec/1000;
			} else 
#endif
			/* UTIMES FUTIMESAT*/
			umoven(pc,argaddr,2*sizeof(struct timeval),tv);
		larg=tv;
	}
	if ((pc->retval = um_syscall(pc->path,larg)) < 0)
		pc->erno=errno;
	return SC_FAKE;
}

/* MOUNT */
int wrap_in_mount(int sc_number,struct pcb *pc,
		service_t sercode, sysfun um_syscall)
{
	char *source;
	char filesystemtype[PATH_MAX];
	char data[PATH_MAX];
	char *datax=data;
	unsigned long argaddr=pc->sysargs[0];
	unsigned int fstype=pc->sysargs[2];
	unsigned int mountflags=pc->sysargs[3];
	unsigned long pdata=pc->sysargs[4];
	struct stat64 imagestat;
	epoch_t nestepoch;
	umovestr(pc,fstype,PATH_MAX,filesystemtype);
	source = um_abspath(AT_FDCWD,argaddr,pc,&imagestat,0);
	nestepoch=um_setepoch(0);
	um_setepoch(nestepoch+1);
	/* maybe the source is not a path at all.
	 * source is not converted to an absolute path if it is not a path
	 * it is simply copied "as is" */
	if (source==um_patherror) {
		source=malloc(PATH_MAX);
		assert(source);
		umovestr(pc,argaddr,PATH_MAX,source);
	} 
	if (pdata != umNULL)
		umovestr(pc,pdata,PATH_MAX,data);
	else
		datax=NULL;
	if ((pc->retval = um_syscall(source,pc->path,filesystemtype,mountflags,datax)) < 0)
		pc->erno=errno;
	free(source);
	um_setepoch(nestepoch);
	return SC_FAKE;
}

int wrap_in_umount(int sc_number,struct pcb *pc,
		service_t sercode, sysfun um_syscall)
{
	unsigned int flags=0;
	if ((pc->retval = um_syscall(pc->path,flags)) < 0)
		pc->erno=errno;
	return SC_FAKE;
}

int wrap_in_umount2(int sc_number,struct pcb *pc,
		service_t sercode, sysfun um_syscall)
{
	unsigned int flags=0;
	// flags is defined as int in umount manpage.
	flags= (int) pc->sysargs[1];
	if ((pc->retval = um_syscall(pc->path,flags)) < 0)
		pc->erno=errno;
	return SC_FAKE;
}

#if (defined(__powerpc__) && !defined(__powerpc64__)) || (defined (MIPS) && !defined(__mips64))
#define PALIGN 1
#else
#define PALIGN 0
#endif

int wrap_in_truncate(int sc_number,struct pcb *pc,
		service_t sercode, sysfun um_syscall)
{
	__off64_t off;
#if (__NR_truncate64 != __NR_doesnotexist)
	if (sc_number == __NR_truncate64) 
		off=LONG_LONG(pc->sysargs[1+PALIGN], pc->sysargs[2+PALIGN]);
	else
#endif
		off=pc->sysargs[1];
	if ((pc->retval=um_syscall(pc->path,off)) < 0)
		pc->erno=errno;
	return SC_FAKE;
}

int wrap_in_ftruncate(int sc_number,struct pcb *pc,
		service_t sercode, sysfun um_syscall)
{
	__off64_t off;
	int sfd=fd2sfd(pc->fds,pc->sysargs[0]);
#if (__NR_ftruncate64 != __NR_doesnotexist)
	if (sc_number == __NR_ftruncate64) 
		off=LONG_LONG(pc->sysargs[1+PALIGN], pc->sysargs[2+PALIGN]);
	else
#endif
		off=pc->sysargs[1];
	if ((pc->retval = um_syscall(sfd,off)) < 0)
		pc->erno=errno;
	return SC_FAKE;
}

static void statfs264(struct statfs *fs,struct statfs64 *fs64)
{
	fs->f_type = fs64->f_type;
	fs->f_bsize = fs64->f_bsize;
	fs->f_blocks = fs64->f_blocks;
	fs->f_bfree = fs64->f_bfree;
	fs->f_bavail = fs64->f_bavail;
	fs->f_files = fs64->f_files;
	fs->f_ffree = fs64->f_ffree;
	fs->f_fsid = fs64->f_fsid;
	fs->f_namelen = fs64->f_namelen;
	fs->f_frsize = fs64->f_frsize;
}

int wrap_in_statfs(int sc_number,struct pcb *pc,
		service_t sercode, sysfun um_syscall)
{
	struct statfs64 sfs64;
	long pbuf=pc->sysargs[1];

	if ((pc->retval = um_syscall(pc->path,&sfs64)) >= 0) {
		struct statfs sfs;
		statfs264(&sfs,&sfs64);
		ustoren(pc,pbuf,sizeof(struct statfs),(char *)&sfs);
	}
	else
		pc->erno=errno;
	return SC_FAKE;
}

int wrap_in_fstatfs(int sc_number,struct pcb *pc,
		service_t sercode, sysfun um_syscall)
{
	struct statfs64 sfs64;
	long pbuf=pc->sysargs[1];
	char *path =fd_getpath(pc->fds,pc->sysargs[0]);
	if (path==NULL) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else {
		if ((pc->retval = um_syscall(path,&sfs64)) >= 0) {
			struct statfs sfs;
			statfs264(&sfs,&sfs64);
			ustoren(pc,pbuf,sizeof(struct statfs),(char *)&sfs);
		}
		else
			pc->erno=errno;
	}
	return SC_FAKE;
}

#if (__NR_statfs64 != __NR_doesnotexist)
int wrap_in_statfs64(int sc_number,struct pcb *pc,
		service_t sercode, sysfun um_syscall)
{
	struct statfs64 sfs64;
	long size=pc->sysargs[1];
	long pbuf=pc->sysargs[2];

	if (size != sizeof(sfs64)) {
		pc->retval= -1;
		pc->erno= EINVAL;
	}
	else {
		if ((pc->retval = um_syscall(pc->path,&sfs64)) >= 0)
			ustoren(pc,pbuf,sizeof(struct statfs64),(char *)&sfs64);
		else
			pc->erno=errno;
	}
	return SC_FAKE;
}

int wrap_in_fstatfs64(int sc_number,struct pcb *pc,
		service_t sercode, sysfun um_syscall)
{
	struct statfs64 sfs64;
	long size=pc->sysargs[1];
	long pbuf=pc->sysargs[2];
	char *path=fd_getpath(pc->fds,pc->sysargs[0]);

	if (path==NULL) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else if (size != sizeof(sfs64)) {
		pc->retval= -1;
		pc->erno= EINVAL;
	} else {
		if ((pc->retval = um_syscall(path,&sfs64)) >= 0)
			ustoren(pc,pbuf,sizeof(struct statfs64),(char *)&sfs64);
		else
			pc->erno=errno;
	}
	return SC_FAKE;
}
#endif
