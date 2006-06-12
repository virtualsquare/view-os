/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   um_basicio: io wrappers
 *   
 *   Copyright 2005 Renzo Davoli University of Bologna - Italy
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
#include <linux/dirent.h>
#include "defs.h"
#include "umproc.h"
#include "services.h"
#include "um_services.h"
#include "sctab.h"
#include "scmap.h"
#include "utils.h"

#include "gdebug.h"

int wrap_in_open(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		service_t sercode, sysfun um_syscall)
{
	int mode,flags;
	if (sc_number== __NR_open) {
		pc->arg1=flags=getargn(1,pc);
		mode=getargn(2,pc);
	} else {
		flags=O_CREAT|O_WRONLY|O_TRUNC;
		pc->arg1=mode=getargn(1,pc);
	}
	//fprint2("open %s %x %o %o\n",pcdata->path,flags,mode,pcdata->fdfs->mask);
	if (sercode != UM_NONE) {
		pc->retval = um_syscall(pcdata->path,flags,mode & ~(pcdata->fdfs->mask));
		pc->erno = errno;
		//printf("open exit a %d %d %s\n",pc->retval,pc->erno,pcdata->path);
		if (pc->retval >= 0 && (pc->retval=lfd_open(sercode,pc->retval,pcdata->path,0)) >= 0) {
			char *filename=lfd_getfilename(pc->retval);
			int filenamelen=WORDALIGN(strlen(filename));
			long sp=getsp(pc);

			//printf("open exit b %d %d\n",pc->retval,pc->erno);
			//printf("real filename: %s\n",filename);
			
			ustorestr(pc,sp-filenamelen,filenamelen,filename);
			putscno(__NR_open,pc);
			putargn(0,sp-filenamelen,pc);
			putargn(1,O_RDONLY,pc);
			return SC_CALLONXIT;
		} else
			return SC_FAKE;
	} else {
		pc->retval=lfd_open(sercode,-1,pcdata->path,0);
		return SC_CALLONXIT;
		//return STD_BEHAVIOR;
	}
}

int wrap_out_open(int sc_number,struct pcb *pc,struct pcb_ext *pcdata) {
	if (pc->retval >= 0) {
		int fd=getrv(pc);	
		//printf("open: true return value: %d  %d %d\n", fd,pc->retval,getscno(pc));
		if (fd >= 0) {
			/* update open file table*/
			lfd_register(pcdata->fds,fd,pc->retval);
			/* restore parms*/
			if (lfd_getservice(pc->retval) != UM_NONE) {
				putscno(pc->scno,pc);
				putargn(0,pc->arg0,pc);
				putargn(1,pc->arg1,pc);
				putrv(fd,pc);
			}
		} else {
			if (lfd_getservice(pc->retval) != UM_NONE) {
				putrv(pc->retval,pc);
				if (pc->retval<0)
					puterrno(pc->erno,pc);
			}
			lfd_close(pc->retval);
		}
	} else {
		putrv(pc->retval,pc);
		puterrno(pc->erno,pc);
	}
	return STD_BEHAVIOR;
}

int wrap_in_close(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		                service_t sercode, sysfun um_syscall)
{
	//printf("wrap in close %d\n", pc->arg0);
	if (sercode != UM_NONE) {
		int sfd=fd2sfd(pcdata->fds,pc->arg0);
		int lfd=fd2lfd(pcdata->fds,pc->arg0);
		//printf("UM_SERVICE close %d %d %d\n",pc->arg0,lfd,sfd);
		if (sfd < 0) {
			pc->retval= -1;
			pc->erno= EBADF;
		} else {
			if (lfd>=0 && lfd_getcount(lfd) <= 1) { //no more opened lfd on this file:
				pc->retval = um_syscall(sfd);
				pc->erno=errno;
				if (pc->retval >= 0) 
					lfd_nullsfd(lfd);
			} else
				pc->retval = pc ->erno = 0;
		} 
	} 
	return SC_CALLONXIT;
}

int wrap_out_close(int sc_number,struct pcb *pc,struct pcb_ext *pcdata) 
{
	int lfd=fd2lfd(pcdata->fds,pc->arg0);
	//printf("close %d ->%d\n",pc->arg0,lfd);
	if (lfd>=0) {
		int service=lfd_getservice(lfd);
		lfd_deregister_n_close(pcdata->fds,pc->arg0);
		if (service != UM_NONE) {
			putrv(pc->retval,pc);
			puterrno(pc->erno,pc);
		}
	}
	return STD_BEHAVIOR;
}

int wrap_out_std(int sc_number,struct pcb *pc,struct pcb_ext *pcdata) 
{
	putrv(pc->retval,pc);
	if (pc->retval<0)
		puterrno(pc->erno,pc);
	return STD_BEHAVIOR;
}

int wrap_in_read(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		                service_t sercode, sysfun um_syscall)
{
	unsigned long pbuf=getargn(1,pc);
	unsigned long count=getargn(2,pc);
	int sfd=fd2sfd(pcdata->fds,pc->arg0);
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else {
		char *lbuf=(char *)alloca(count);
		pc->retval = um_syscall(sfd,lbuf,count);
		pc->erno=errno;
		if (pc->retval > 0)
			ustoren(pc,pbuf,pc->retval,lbuf);
	}
	return SC_FAKE;
}

int wrap_in_write(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		                service_t sercode, sysfun um_syscall)
{
	unsigned long pbuf=getargn(1,pc);
	unsigned long count=getargn(2,pc);
	int sfd=fd2sfd(pcdata->fds,pc->arg0);
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else {
		char *lbuf=(char *)alloca(count);
		umoven(pc,pbuf,count,lbuf);
		pc->retval = um_syscall(sfd,lbuf,count);
		pc->erno=errno;
	}
	return SC_FAKE;
}


#if (defined(__powerpc__) && !defined(__powerpc64__)) || (defined (MIPS) && !defined(__mips64))
#define PALIGN 1
#else
#define PALIGN 0
#endif

int wrap_in_pread(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		                service_t sercode, sysfun um_syscall)
{
	unsigned long pbuf=getargn(1,pc);
	unsigned long count=getargn(2,pc);
	unsigned long long offset;
	int sfd=fd2sfd(pcdata->fds,pc->arg0);
#ifdef __NR_pread64
	offset=LONG_LONG(getargn(3+PALIGN,pc),getargn(4+PALIGN,pc));
#else
	offset=getargn(3,pc);
#endif
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else {
		char *lbuf=(char *)alloca(count);
		pc->retval = um_syscall(sfd,lbuf,count,offset);
		pc->erno=errno;
		if (pc->retval > 0)
			ustoren(pc,pbuf,pc->retval,lbuf);
	}
	return SC_FAKE;
}

int wrap_in_pwrite(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		                service_t sercode, sysfun um_syscall)
{
	unsigned long pbuf=getargn(1,pc);
	unsigned long count=getargn(2,pc);
	unsigned long long offset;
	int sfd=fd2sfd(pcdata->fds,pc->arg0);
#ifdef __NR_pwrite64
	offset=LONG_LONG(getargn(3+PALIGN,pc),getargn(4+PALIGN,pc));
#else
	offset=getargn(3,pc);
#endif
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else {
		char *lbuf=(char *)alloca(count);
		umoven(pc,pbuf,count,lbuf);
		pc->retval = um_syscall(sfd,lbuf,count,offset);
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

int wrap_in_stat(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		service_t sercode, sysfun um_syscall)
{
	long pbuf=getargn(1,pc);
	struct stat64 buf64;

	pc->retval = um_syscall(pcdata->path,&buf64);
	pc->erno=errno;
	if (pc->retval >= 0) {
		struct kstat kbuf;
		stat64_2kstat(&buf64,&kbuf);
		ustoren(pc,pbuf,sizeof(struct kstat),(char *)&kbuf);
	}
	return SC_FAKE;
}

int wrap_in_fstat(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		                service_t sercode, sysfun um_syscall)
{
	long pbuf=getargn(1,pc);
	int sfd=fd2sfd(pcdata->fds,pc->arg0);
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else {
		struct stat64 buf64;
		pc->retval = um_syscall(sfd,&buf64);
		pc->erno=errno;
		if (pc->retval >= 0) {
			struct kstat kbuf;
			stat64_2kstat(&buf64,&kbuf);
			ustoren(pc,pbuf,sizeof(struct kstat),(char *)&kbuf);
		}
	}
	return SC_FAKE;
}
#endif // if not defined _x86_64

int wrap_in_stat64(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		                service_t sercode, sysfun um_syscall)
{
	long pbuf=getargn(1,pc);
	struct stat64 buf;
	pc->retval = um_syscall(pcdata->path,&buf);
	pc->erno=errno;
	if (pc->retval >= 0)
		ustoren(pc,pbuf,sizeof(struct stat64),&buf);
	return SC_FAKE;
}

int wrap_in_fstat64(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		                service_t sercode, sysfun um_syscall)
{
	long pbuf=getargn(1,pc);
	int sfd=fd2sfd(pcdata->fds,pc->arg0);
	//printf("wrap_in_fstat: %d",sfd);
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else {
		struct stat64 buf;
		pc->retval = um_syscall(sfd,&buf);
		pc->erno=(pc->retval<0)?errno:0;
		//pc->erno=errno;
		if (pc->retval >= 0)
			ustoren(pc,pbuf,sizeof(struct stat64),&buf);
	}
	return SC_FAKE;
}

int wrap_in_getxattr(int sc_number, struct pcb *pc, struct pcb_ext *pcdata,
		service_t sercode, sysfun um_syscall)
{
	char *name = (char *)getargn(1, pc);
	long pbuf = getargn(2, pc);
	size_t size = getargn(3, pc);
	char *buf = alloca(size);

	pc->retval = um_syscall(pcdata->path, name, buf, size);
	pc->erno = errno;

	if (pc->retval >= 0)
		ustoren(pc, pbuf, size, buf);

	return SC_FAKE;
}

int wrap_in_readlink(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		                service_t sercode, sysfun um_syscall)
{
	unsigned long pbuf=getargn(1,pc);
	unsigned long bufsiz=getargn(2,pc);
	char *lbuf=(char *)alloca(bufsiz);
	pc->retval = (long) um_syscall(pcdata->path,lbuf,bufsiz);
	GDEBUG(10,"wrap_in_readlink - rv=%ld\n",pc->retval);
	pc->erno=errno;
	if (pc->retval > 0)
		ustoren(pc,pbuf,pc->retval,lbuf);
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

int wrap_in_getdents(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		                service_t sercode, sysfun um_syscall)
{
	long pbuf=getargn(1,pc);
	unsigned long bufsiz=getargn(2,pc);
	int sfd=fd2sfd(pcdata->fds,pc->arg0);
	//printf("wrap_in_getdents(sc:%d ,pc,pcdata,sercode:%d,syscall);\n",sc_number,sercode);
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else {
		char *lbuf=(char *)alloca(bufsiz);
		pc->retval = um_syscall(sfd,lbuf,bufsiz);
		//pc->erno=(pc->retval<0)?errno:0;
		pc->erno=errno;
		if (pc->retval > 0){
			dents64_to_dents(lbuf,pc->retval);
			ustoren(pc,pbuf,pc->retval,lbuf);
		}
	}
	return SC_FAKE;
}

int wrap_in_getdents64(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		                service_t sercode, sysfun um_syscall)
{
	long pbuf=getargn(1,pc);
	unsigned long bufsiz=getargn(2,pc);
	int sfd=fd2sfd(pcdata->fds,pc->arg0);
	//printf("wrap_in_getdents(sc:%d ,pc,pcdata,sercode:%d,syscall);\n",sc_number,sercode);
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else {
		char *lbuf=(char *)alloca(bufsiz);
		pc->retval = um_syscall(sfd,lbuf,bufsiz);
		//pc->erno=(pc->retval<0)?errno:0;
		pc->erno=errno;
		if (pc->retval > 0){
			ustoren(pc,pbuf,pc->retval,lbuf);
		}
	}
	return SC_FAKE;
}

int wrap_in_access(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		                service_t sercode, sysfun um_syscall)
{
	unsigned long mode=getargn(1,pc);
	pc->retval = um_syscall(pcdata->path,mode);
	pc->erno=errno;
	return SC_FAKE;
}


int wrap_in_lseek(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		                service_t sercode, sysfun um_syscall)
{
	int sfd=fd2sfd(pcdata->fds,pc->arg0);
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else {
		long offset =getargn(1,pc);
		long whence =getargn(2,pc);
		pc->retval = um_syscall(sfd,offset,whence);
		pc->erno=errno;
	}
	return SC_FAKE;
}

int wrap_in_llseek(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		                service_t sercode, sysfun um_syscall)
{
	int sfd=fd2sfd(pcdata->fds,pc->arg0);
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else {
		unsigned long offhi=getargn(1,pc);
		unsigned long offlo=getargn(2,pc);
		unsigned long result=getargn(3,pc);
		unsigned int whence=getargn(4,pc);
		loff_t lresult;
		pc->retval = um_syscall(sfd,offhi,offlo,&lresult,whence);
		pc->erno=errno;
		if (pc->retval >= 0) 
			ustoren(pc,result,sizeof(loff_t),(char *)&lresult);
	}
	return SC_FAKE;
}

int wrap_in_notsupp(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		                service_t sercode, sysfun um_syscall)
{
	//printf("wrap_in_notsupp %d\n",sc_number);
	pc->retval= -1;
	pc->erno= EOPNOTSUPP;
	return SC_FAKE;
}

int wrap_in_readv(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		                service_t sercode, sysfun um_syscall)
{
	int sfd=fd2sfd(pcdata->fds,pc->arg0);
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else {
		unsigned long vecp=getargn(1,pc);
		unsigned long count=getargn(2,pc);
		unsigned long i,totalsize,size;
		struct iovec *iovec=(struct iovec *)alloca(count * sizeof(struct iovec));
		struct iovec liovec;
		umoven(pc,vecp,count * sizeof(struct iovec),(char *)iovec);
		for (i=0,totalsize=0;i<count;i++)
			totalsize += iovec[i].iov_len;
		char *lbuf=(char *)alloca(totalsize);
		liovec.iov_base=lbuf;
		liovec.iov_len=totalsize;
		size=pc->retval = um_syscall(sfd,&liovec,1);
		pc->erno=errno;
		if (size > 0) {
			for (i=0;i<count && size>0;i++) {
				long qty=(size > iovec[i].iov_len)?iovec[i].iov_len:size;
				ustoren(pc,(long)iovec[i].iov_base,qty,lbuf);
				lbuf += qty;
				size -= qty;
			}
		}
	}
	return SC_FAKE;
}

int wrap_in_writev(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		                service_t sercode, sysfun um_syscall)
{
	int sfd=fd2sfd(pcdata->fds,pc->arg0);
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else {
		unsigned long vecp=getargn(1,pc);
		unsigned long count=getargn(2,pc);
		unsigned long i,totalsize;
		struct iovec *iovec=(struct iovec *)alloca(count * sizeof(struct iovec));
		struct iovec liovec;
		umoven(pc,vecp,count * sizeof(struct iovec),(char *)iovec);
		for (i=0,totalsize=0;i<count;i++)
			totalsize += iovec[i].iov_len;
		char *lbuf=(char *)alloca(totalsize);
		char *p=lbuf;
		for (i=0;i<count;i++) {
			long qty=iovec[i].iov_len;
			umoven(pc,(long)iovec[i].iov_base,qty,p);
			p += qty;
		}
		liovec.iov_base=lbuf;
		liovec.iov_len=totalsize;
		pc->retval = um_syscall(sfd,&liovec,1);
		pc->erno=errno;
	}
	return SC_FAKE;
}
