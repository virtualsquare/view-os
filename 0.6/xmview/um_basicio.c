/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   um_basicio: io wrappers
 *   
 *   Copyright 2005 Renzo Davoli University of Bologna - Italy
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
#include <sys/types.h>
#include <sys/uio.h>
#include <asm/ptrace.h>
#include <asm/unistd.h>
#include <linux/net.h>
#include <errno.h>
#include <limits.h>
#include <alloca.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <linux/types.h>
#include <linux_dirent.h>
#include <config.h>
#include "defs.h"
#include "umproc.h"
#include "services.h"
#include "um_services.h"
#include "sctab.h"
#include "scmap.h"
#include "utils.h"

#include "gdebug.h"

/* OPEN & CREAT wrapper "in" phase 
 * always called (also when service == UM_NONE)*/
int wrap_in_open(int sc_number,struct pcb *pc,
		service_t sercode, sysfun um_syscall)
{
	int mode,flags;
	if (sc_number== __NR_open) {
		flags=pc->sysargs[1];
		mode=pc->sysargs[2];
#ifdef __NR_openat
	} else if (sc_number == __NR_openat) {
		flags=pc->sysargs[2];
		mode=pc->sysargs[3];
#endif
	} else {
		flags=O_CREAT|O_WRONLY|O_TRUNC;
		mode=pc->sysargs[1];
	}
	if (sercode != UM_NONE) {
		/* call the module's open */
		if ((pc->retval = um_syscall(pc->path,flags,mode & ~(pc->fdfs->mask))) < 0)
			pc->erno = errno;
		//printf("open exit a %d %d %s\n",pc->retval,pc->erno,pc->path);
		if (pc->retval >= 0 && 
				(pc->retval=lfd_open(sercode,pc->retval,pc->path,flags,0)) >= 0) {
			/* change the syscall parms, open the fifo instead of the file */
			char *filename=lfd_getfilename(pc->retval);
			int filenamelen=WORDALIGN(strlen(filename));
			long sp=getsp(pc);
			ustoren(pc,sp-filenamelen,filenamelen,filename);
			putscno(__NR_open,pc);
			pc->sysargs[0]=sp-filenamelen;
			pc->sysargs[1]=O_RDONLY;
			return SC_CALLONXIT;
		} else
			return SC_FAKE;
	} else {
#if 0
		/* load the complete path (to avoid border effects -- like open(..) */
		/* open problem: all the paths should be rewritten on borders
		 * not only for "open" */
		int filenamelen=WORDALIGN(strlen(pc->path));
		long sp=getsp(pc);
		ustoren(pc,sp-filenamelen,filenamelen,pc->path);
#ifdef __NR_openat
		if (sc_number == __NR_openat) 
			pc->sysargs[1]=sp-filenamelen;
		else 
#endif
			pc->sysargs[0]=sp-filenamelen;
		/* keep track of the open file */
		pc->retval=lfd_open(sercode,-1,pc->path,flags,0);
		return SC_CALLONXIT;
#endif
		pc->retval=lfd_open(sercode,-1,pc->path,flags,0);
		return SC_TRACEONLY;
	}
}

/* OPEN & CREAT wrapper: "out" phase */
int wrap_out_open(int sc_number,struct pcb *pc) {
	/* user mode open succeeded */
	if (pc->retval >= 0) {
		int fd=getrv(pc);	
		//printf("open: true return value: %d  %d %d\n", fd,pc->retval,getscno(pc));
		/* process syscall succeeded, too */
		if (fd >= 0 &&
				(lfd_getservice(pc->retval) == UM_NONE
				 || addfd(pc,fd) == 0)) {
			/* update open file table*/
			lfd_register(pc->fds,fd,pc->retval);
		} else 
			lfd_close(pc->retval);
	} else {
		putrv(pc->retval,pc);
		puterrno(pc->erno,pc);
	}
	GDEBUG(3, "end of wrap_out: retval %d errno %d", pc->retval, pc->erno);
	return SC_MODICALL;
}

/* CLOSE wrapper: "in" phase ALWAYS called*/
int wrap_in_close(int sc_number,struct pcb *pc,
		                service_t sercode, sysfun um_syscall)
{
	//printf("wrap in close %d\n", pc->sysargs[0]);
	if (sercode != UM_NONE) {
		int sfd=fd2sfd(pc->fds,pc->sysargs[0]);
		int lfd=fd2lfd(pc->fds,pc->sysargs[0]);
		//printf("UM_SERVICE close %d %d %d\n",pc->sysargs[0],lfd,sfd);
		if (sfd < 0) {
			pc->retval= -1;
			pc->erno= EBADF;
		} else {
			if (lfd>=0 && lfd_getcount(lfd) <= 1) { 
			/* no more opened lfd on this file: */
				pc->retval = um_syscall(sfd);
				pc->erno=errno;
				/* nullify sfd to avoid double close */
				if (pc->retval >= 0) 
					lfd_nullsfd(lfd);
			} else
				pc->retval = pc ->erno = 0;
		} 
		return SC_CALLONXIT;
	} 
	else
		return SC_TRACEONLY;
}

/* CLOSE wrapper: "out" phase */
int wrap_out_close(int sc_number,struct pcb *pc) 
{
	int lfd=fd2lfd(pc->fds,pc->sysargs[0]);
	//printf("close %d ->%d\n",pc->sysargs[0],lfd);
	/* delete the lfd table element */
	if (lfd>=0) {
		int service=lfd_getservice(lfd);
		lfd_deregister_n_close(pc->fds,pc->sysargs[0]);
		if (service != UM_NONE) {
			delfd(pc,pc->sysargs[0]);
			putrv(pc->retval,pc);
			puterrno(pc->erno,pc);
		}
	}
	return SC_MODICALL;
}

/* wrap_out for all standard i/o calls.
 * The process level syscall is faked (or skipped when ptrace_sysvm exists
 * and the module return value/errno must be returned */
int wrap_out_std(int sc_number,struct pcb *pc) 
{
	putrv(pc->retval,pc);
	if (pc->retval<0)
		puterrno(pc->erno,pc);
	return SC_MODICALL;
}

int wrap_in_read(int sc_number,struct pcb *pc,
		                service_t sercode, sysfun um_syscall)
{
	unsigned long pbuf=pc->sysargs[1];
	unsigned long count=pc->sysargs[2];
	int sfd=fd2sfd(pc->fds,pc->sysargs[0]);
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else {
		char *lbuf=(char *)alloca(count);
		if ((pc->retval = um_syscall(sfd,lbuf,count)) < 0)
			pc->erno=errno;
		if (pc->retval > 0)
			ustoren(pc,pbuf,pc->retval,lbuf);
	}
	return SC_FAKE;
}

int wrap_in_write(int sc_number,struct pcb *pc,
		                service_t sercode, sysfun um_syscall)
{
	unsigned long pbuf=pc->sysargs[1];
	unsigned long count=pc->sysargs[2];
	int sfd=fd2sfd(pc->fds,pc->sysargs[0]);
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else {
		char *lbuf=(char *)alloca(count);
		umoven(pc,pbuf,count,lbuf);
		if ((pc->retval = um_syscall(sfd,lbuf,count)) < 0)
			pc->erno=errno;
	}
	return SC_FAKE;
}


/* there is a memory alignment problem in these architectures */
#if (defined(__powerpc__) && !defined(__powerpc64__)) || (defined (MIPS) && !defined(__mips64))
#define PALIGN 1
#else
#define PALIGN 0
#endif

int wrap_in_pread(int sc_number,struct pcb *pc,
		                service_t sercode, sysfun um_syscall)
{
	unsigned long pbuf=pc->sysargs[1];
	unsigned long count=pc->sysargs[2];
	unsigned long long offset;
	int sfd=fd2sfd(pc->fds,pc->sysargs[0]);
#ifdef __NR_pread64
	offset=LONG_LONG(pc->sysargs[3+PALIGN],pc->sysargs[4+PALIGN]);
#else
	offset=pc->sysargs[3];
#endif
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else {
		char *lbuf=(char *)alloca(count);
		if ((pc->retval = um_syscall(sfd,lbuf,count,offset)) < 0)
			pc->erno=errno;
		if (pc->retval > 0)
			ustoren(pc,pbuf,pc->retval,lbuf);
	}
	return SC_FAKE;
}

int wrap_in_pwrite(int sc_number,struct pcb *pc,
		                service_t sercode, sysfun um_syscall)
{
	unsigned long pbuf=pc->sysargs[1];
	unsigned long count=pc->sysargs[2];
	unsigned long long offset;
	int sfd=fd2sfd(pc->fds,pc->sysargs[0]);
#ifdef __NR_pwrite64
	offset=LONG_LONG(pc->sysargs[3+PALIGN],pc->sysargs[4+PALIGN]);
#else
	offset=pc->sysargs[3];
#endif
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else {
		char *lbuf=(char *)alloca(count);
		umoven(pc,pbuf,count,lbuf);
		if ((pc->retval = um_syscall(sfd,lbuf,count,offset)) < 0)
			pc->erno=errno;
	}
	return SC_FAKE;
}
#undef PALIGN

/* DAMNED! the kernel stat are different! so glibc converts the 
 * kernel structure. We have to make the reverse conversion! */
#ifdef __powerpc__
struct kstat {
	unsigned        kst_dev;
	ino_t           kst_ino;
	mode_t          kst_mode;
	nlink_t         kst_nlink;
	uid_t           kst_uid;
	gid_t           kst_gid;
	unsigned        kst_rdev;
	off_t           kst_size;
	unsigned long   kst_blksize;
	unsigned long   kst_blocks;
	unsigned long   kst_atime;
	unsigned long   kst_atime_nsec;
	unsigned long   kst_mtime;
	unsigned long   kst_mtime_nsec;
	unsigned long   kst_ctime;
	unsigned long   kst_ctime_nsec;
	unsigned long   k__unused4;
	unsigned long   k__unused5;
};
#endif
#ifdef __i386__
struct kstat {
	unsigned short kst_dev;
	unsigned short k__pad1;
	unsigned long  kst_ino;
	unsigned short kst_mode;
	unsigned short kst_nlink;
	unsigned short kst_uid;
	unsigned short kst_gid;
	unsigned short kst_rdev;
	unsigned short k__pad2;
	unsigned long  kst_size;
	unsigned long  kst_blksize;
	unsigned long  kst_blocks;
	unsigned long  kst_atime;
	unsigned long  k__unused1;
	unsigned long  kst_mtime;
	unsigned long  k__unused2;
	unsigned long  kst_ctime;
	unsigned long  k__unused3;
	unsigned long  k__unused4;
	unsigned long  k__unused5;
};
#endif

#if ! defined(__x86_64__)
#if 0
struct kstat {
		unsigned long	kst_dev;
		unsigned long   kst_ino;
		unsigned long    kst_nlink;

		unsigned int    kst_mode;
		unsigned int	kst_uid;
		unsigned int	kst_gid;
		unsigned int	k__pad0;

		unsigned long	kst_rdev;

		long			kst_size;
		long			kst_blksize;
		long			kst_blocks;  /* Number 512-byte blocks allocated. */

		unsigned long   kst_atime;
		unsigned long   kst_atime_nsec;
		unsigned long   kst_mtime;
		unsigned long   kst_mtime_nsec;
		unsigned long   kst_ctime;
		unsigned long   kst_ctime_nsec;

		long  k__unused[3];
};
#else


static void stat64_2kstat(struct stat64 *buf,struct kstat *kbuf)
{
	kbuf->kst_dev	= (unsigned short) buf->st_dev;
	kbuf->kst_ino	= (unsigned long)  buf->st_ino;
	kbuf->kst_mode	= (unsigned short) buf->st_mode;
	kbuf->kst_nlink	= (unsigned short) buf->st_nlink;
	kbuf->kst_uid	= (unsigned short) buf->st_uid;
	kbuf->kst_gid	= (unsigned short) buf->st_gid;
	kbuf->kst_rdev	= (unsigned short) buf->st_rdev;
	kbuf->kst_size	= (unsigned long)  buf->st_size;
	kbuf->kst_blksize	= (unsigned long) buf->st_blksize;
	kbuf->kst_blocks	= (unsigned long) buf->st_blocks;
	kbuf->kst_atime	= (unsigned long)  buf->st_atime;
	kbuf->kst_mtime	= (unsigned long)  buf->st_mtime;
	kbuf->kst_ctime	= (unsigned long)  buf->st_ctime;
}
#endif // if not defined _x86_64

int wrap_in_stat(int sc_number,struct pcb *pc,
		service_t sercode, sysfun um_syscall)
{
	long pbuf=pc->sysargs[1];
	struct stat64 buf64;

	pc->retval = um_syscall(pc->path,&buf64);
	if (pc->retval >= 0) {
		struct kstat kbuf;
		stat64_2kstat(&buf64,&kbuf);
		ustoren(pc,pbuf,sizeof(struct kstat),(char *)&kbuf);
	} else
		pc->erno=errno;
	return SC_FAKE;
}

int wrap_in_fstat(int sc_number,struct pcb *pc,
		                service_t sercode, sysfun um_syscall)
{
	long pbuf=pc->sysargs[1];
	char *path =fd_getpath(pc->fds,pc->sysargs[0]);
	if (path == NULL) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else {
		struct stat64 buf64;
		if ((pc->retval = um_syscall(path,&buf64)) >= 0) {
			struct kstat kbuf;
			stat64_2kstat(&buf64,&kbuf);
			ustoren(pc,pbuf,sizeof(struct kstat),(char *)&kbuf);
		}
		else
			pc->erno=errno;
	}
	return SC_FAKE;
}
#endif // if not defined _x86_64

int wrap_in_stat64(int sc_number,struct pcb *pc,
		                service_t sercode, sysfun um_syscall)
{
	long pbuf;
	struct stat64 buf;
#if defined(__NR_fstatat64) || defined(__NR_newfstatat)
	if (sc_number == 
#ifdef __NR_fstatat64
			__NR_fstatat64
#else
			__NR_newfstatat
#endif
		 ) {
		pbuf=pc->sysargs[2];
		if (pc->sysargs[3] & AT_SYMLINK_NOFOLLOW) 
			um_syscall=service_syscall(sercode,uscno(NR64_lstat));
	} else
#endif
	pbuf=pc->sysargs[1];
	if ((pc->retval = um_syscall(pc->path,&buf)) >= 0)
		ustoren(pc,pbuf,sizeof(struct stat64),&buf);
	else
		pc->erno=errno;
	return SC_FAKE;
}

int wrap_in_fstat64(int sc_number,struct pcb *pc,
		                service_t sercode, sysfun um_syscall)
{
	long pbuf=pc->sysargs[1];
	char *path=fd_getpath(pc->fds,pc->sysargs[0]);
	/*fprint2("wrap_in_fstat: %d\n",sfd);*/
	if (path==NULL) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else {
		struct stat64 buf;
		if ((pc->retval = um_syscall(path,&buf)) >= 0)
			ustoren(pc,pbuf,sizeof(struct stat64),&buf);
		else
			pc->erno=errno;
	}
	return SC_FAKE;
}

int wrap_in_getxattr(int sc_number, struct pcb *pc,
		service_t sercode, sysfun um_syscall)
{
	char *name = (char *)(pc->sysargs[1]);
	long pbuf = pc->sysargs[2];
	size_t size = pc->sysargs[3];
	char *buf = alloca(size);

	if ((pc->retval = um_syscall(pc->path, name, buf, size)) >= 0)
		ustoren(pc, pbuf, size, buf);
	else
		pc->erno = errno;

	return SC_FAKE;
}

int wrap_in_readlink(int sc_number,struct pcb *pc,
		                service_t sercode, sysfun um_syscall)
{
	unsigned long pbuf;
	unsigned long bufsiz;
	char *lbuf;
#ifdef __NR_readlinkat
	if (sc_number == __NR_readlinkat) {
		pbuf=pc->sysargs[2];
		bufsiz=pc->sysargs[3];
	} else 
#endif 
	{
		pbuf=pc->sysargs[1];
		bufsiz=pc->sysargs[2];
	}
	lbuf=(char *)alloca(bufsiz);
	if ((pc->retval = (long) um_syscall(pc->path,lbuf,bufsiz)) >= 0)
		ustoren(pc,pbuf,pc->retval,lbuf);
	else
		pc->erno=errno;
	GDEBUG(10,"wrap_in_readlink - rv=%ld\n",pc->retval);
	return SC_FAKE;
}

/******************************************************************/
/* DIRENTS STRUCTS */

void dents64_to_dents(void* buf,int count){
	struct dirent *dirp=buf;
	struct dirent64 *dirp64=buf;
	int counter=0;
	unsigned short int buf_len;
	
	for( counter=0; counter<count ; ){
		GDEBUG(10,"dirent64: ino:%lld - off:%lld - reclen:%d - name:%s",dirp64->d_ino,dirp64->d_off,dirp64->d_reclen,&(dirp64->d_name));
		dirp->d_ino = (unsigned long) dirp64->d_ino;
		dirp->d_off = (unsigned long) dirp64->d_off;
		buf_len = dirp->d_reclen = dirp64->d_reclen;
		strcpy(dirp->d_name,dirp64->d_name);
		counter= counter + dirp->d_reclen; //bad...
		GDEBUG(10,"dirent: ino:%ld - off:%ld - reclen:%d - name:%s",dirp->d_ino,dirp->d_off,dirp->d_reclen,(dirp->d_name));
		GDEBUG(10,"counter: %d count: %d ",counter,count);
		dirp = (struct dirent*) ((char*)dirp + buf_len);
		dirp64 = (struct dirent64*) ((char*)dirp64 + buf_len);
	}
}

int wrap_in_getdents(int sc_number,struct pcb *pc,
		                service_t sercode, sysfun um_syscall)
{
	long pbuf=pc->sysargs[1];
	unsigned long bufsiz=pc->sysargs[2];
	int sfd=fd2sfd(pc->fds,pc->sysargs[0]);
	//printf("wrap_in_getdents(sc:%d ,pc,sercode:%d,syscall);\n",sc_number,sercode);
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else {
		char *lbuf=(char *)alloca(bufsiz);
		if ((pc->retval = um_syscall(sfd,lbuf,bufsiz)) >= 0) {
			dents64_to_dents(lbuf,pc->retval);
			ustoren(pc,pbuf,pc->retval,lbuf);
		}
		else
			pc->erno=errno;
	}
	return SC_FAKE;
}

int wrap_in_getdents64(int sc_number,struct pcb *pc,
		                service_t sercode, sysfun um_syscall)
{
	long pbuf=pc->sysargs[1];
	unsigned long bufsiz=pc->sysargs[2];
	int sfd=fd2sfd(pc->fds,pc->sysargs[0]);
	//printf("wrap_in_getdents(sc:%d ,pc,sercode:%d,syscall);\n",sc_number,sercode);
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else {
		char *lbuf=(char *)alloca(bufsiz);
		if ((pc->retval = um_syscall(sfd,lbuf,bufsiz)) >= 0)
			ustoren(pc,pbuf,pc->retval,lbuf);
		else
			pc->erno=errno;
	}
	return SC_FAKE;
}

int wrap_in_access(int sc_number,struct pcb *pc,
		                service_t sercode, sysfun um_syscall)
{
	unsigned long mode;
	long flags;
#ifdef __NR_faccessat
	if (sc_number == __NR_faccessat) {
		mode=pc->sysargs[2];
		flags=pc->sysargs[3];
	}
	else
#endif
	{
		mode=pc->sysargs[1];
		flags=0;
	}
	if ((pc->retval = um_syscall(pc->path,mode,flags)) < 0)
		pc->erno=errno;
	return SC_FAKE;
}

int wrap_in_lseek(int sc_number,struct pcb *pc,
		                service_t sercode, sysfun um_syscall)
{
	int sfd=fd2sfd(pc->fds,pc->sysargs[0]);
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else {
		long offset =pc->sysargs[1];
		long whence =pc->sysargs[2];
		if ((pc->retval = um_syscall(sfd,offset,whence)) == -1)
			pc->erno=errno;
	}
	return SC_FAKE;
}

int wrap_in_llseek(int sc_number,struct pcb *pc,
		                service_t sercode, sysfun um_syscall)
{
	int sfd=fd2sfd(pc->fds,pc->sysargs[0]);
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else {
		unsigned long offhi=pc->sysargs[1];
		unsigned long offlo=pc->sysargs[2];
		unsigned long result=pc->sysargs[3];
		unsigned int whence=pc->sysargs[4];
		loff_t lresult;
		if (!isnosys(um_syscall)) {
			if ((pc->retval = um_syscall(sfd,offhi,offlo,&lresult,whence))< 0)
				pc->erno=errno;
			else
				ustoren(pc,result,sizeof(loff_t),(char *)&lresult);
		} else {/* backup solution translate it to lseek when possible */
			if ((offhi==0 && !(offlo & 1<<31)) || ((offhi == ~0 && (offlo & 1<<31)))) {
				long shortresult;
				um_syscall=service_syscall(sercode,uscno(__NR_lseek));
				if ((shortresult=um_syscall(sfd,offlo,whence)) == -1) {
					pc->retval=-1;
					pc->erno=errno;
				} else {
					lresult=result;
					pc->retval=0;
					ustoren(pc,result,sizeof(loff_t),(char *)&lresult);
				}
			} else {
				pc->retval=-1;
				pc->erno=EFAULT;
			}
		}
	}
	return SC_FAKE;
}

int wrap_in_notsupp(int sc_number,struct pcb *pc,
		                service_t sercode, sysfun um_syscall)
{
	//printf("wrap_in_notsupp %d\n",sc_number);
	pc->retval= -1;
	pc->erno= EOPNOTSUPP;
	return SC_FAKE;
}

int wrap_in_readv(int sc_number,struct pcb *pc,
		                service_t sercode, sysfun um_syscall)
{
	int sfd=fd2sfd(pc->fds,pc->sysargs[0]);
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else {
		unsigned long vecp=pc->sysargs[1];
		unsigned long count=pc->sysargs[2];
		unsigned long i,totalsize,size;
		struct iovec *iovec=(struct iovec *)alloca(count * sizeof(struct iovec));
		char *lbuf;
		umoven(pc,vecp,count * sizeof(struct iovec),(char *)iovec);
		for (i=0,totalsize=0;i<count;i++)
			totalsize += iovec[i].iov_len;
		lbuf=(char *)alloca(totalsize);
		/* READV is mapped onto READ */
		if ((size=pc->retval = um_syscall(sfd,lbuf,totalsize)) >= 0) {
			for (i=0;i<count && size>0;i++) {
				long qty=(size > iovec[i].iov_len)?iovec[i].iov_len:size;
				ustoren(pc,(long)iovec[i].iov_base,qty,lbuf);
				lbuf += qty;
				size -= qty;
			}
		}
		else
			pc->erno=errno;
	}
	return SC_FAKE;
}

int wrap_in_writev(int sc_number,struct pcb *pc,
		                service_t sercode, sysfun um_syscall)
{
	int sfd=fd2sfd(pc->fds,pc->sysargs[0]);
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else {
		unsigned long vecp=pc->sysargs[1];
		unsigned long count=pc->sysargs[2];
		unsigned long i,totalsize;
		struct iovec *iovec=(struct iovec *)alloca(count * sizeof(struct iovec));
		char *lbuf, *p;
		umoven(pc,vecp,count * sizeof(struct iovec),(char *)iovec);
		for (i=0,totalsize=0;i<count;i++)
			totalsize += iovec[i].iov_len;
		lbuf=(char *)alloca(totalsize);
		p=lbuf;
		for (i=0;i<count;i++) {
			long qty=iovec[i].iov_len;
			umoven(pc,(long)iovec[i].iov_base,qty,p);
			p += qty;
		}
		/* WRITEV is mapped onto WRITE */
		if ((pc->retval = um_syscall(sfd,lbuf,totalsize)) < 0)
			pc->erno=errno;
	}
	return SC_FAKE;
}
