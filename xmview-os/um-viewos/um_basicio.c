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
#include "defs.h"
#include "umproc.h"
#include "services.h"
#include "um_services.h"
#include "sctab.h"
#include "scmap.h"
#include "utils.h"

int wrap_in_open(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		service_t sercode, intfun syscall)
{
	int mode,flags;
	if (sc_number== __NR_open) {
		pc->arg1=flags=getargn(1,pc);
		mode=getargn(2,pc);
	} else {
		flags=O_CREAT|O_WRONLY|O_TRUNC;
		pc->arg1=mode=getargn(1,pc);
	}
	//printf("open %s %x %o %o\n",pcdata->path,flags,mode,pcdata->fdfs->mask);
	if (sercode != UM_NONE) {
		pc->retval = syscall(pcdata->path,flags,mode & ~(pcdata->fdfs->mask));
		pc->erno = errno;
		//printf("open exit a %d %d\n",pc->retval,pc->erno);
		if (pc->retval >= 0 && (pc->retval=lfd_open(sercode,pc->retval,pcdata->path)) >= 0) {
			char *filename=lfd_getfilename(pc->retval);
			int filenamelen=(strlen(filename) + 4) & (~3);
			int sp=getsp(pc);

			//printf("open exit b %d %d\n",pc->retval,pc->erno);
			//printf("real filename: %s\n",filename);
			
			ustorestr(pc->pid,sp-filenamelen,filenamelen,filename);
			putscno(__NR_open,pc);
			putargn(0,sp-filenamelen,pc);
			putarg0orig(sp-filenamelen,pc);
			putargn(1,O_RDONLY,pc);
			return SC_CALLONXIT;
		} else
			return SC_FAKE;
	} else {
		pc->retval=lfd_open(sercode,-1,pcdata->path);
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
				putarg0orig(pc->arg0,pc);
				putargn(1,pc->arg1,pc);
				putrv(fd,pc);
			}
		} else {
			if (lfd_getservice(pc->retval) != UM_NONE) {
				putrv(pc->retval,pc);
				pc->retval<0?puterrno(pc->erno,pc):0;
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
		                service_t sercode, intfun syscall)
{
	if (sercode != UM_NONE) {
		int sfd=fd2sfd(pcdata->fds,pc->arg0);
		int lfd=fd2lfd(pcdata->fds,pc->arg0);
		if (sfd < 0) {
			pc->retval= -1;
			pc->erno= EBADF;
		} else {
			if (lfd>=0 && lfd_getcount(lfd) <= 1) {
				pc->retval = syscall(sfd);
				pc->erno=errno;
				/*if (pc->retval >= 0) 
					lfd_nullsfd(sfd);*/
			} else
				pc->retval = pc ->erno = 0;
		} 
		return SC_FAKE;
	} else
		return SC_CALLONXIT;
		//return STD_BEHAVIOR;
}

int wrap_out_close(int sc_number,struct pcb *pc,struct pcb_ext *pcdata) 
{
	int lfd=fd2lfd(pcdata->fds,pc->arg0);
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
	pc->retval<0?puterrno(pc->erno,pc):0;
/*  err=puterrno(pc->erno,pc);*/
	return STD_BEHAVIOR;
}

int wrap_in_read(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		                service_t sercode, intfun syscall)
{
	unsigned int pbuf=getargn(1,pc);
	unsigned int count=getargn(2,pc);
	int sfd=fd2sfd(pcdata->fds,pc->arg0);
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else {
		char *lbuf=(char *)alloca(count);
		pc->retval = syscall(sfd,lbuf,count);
		pc->erno=errno;
		if (pc->retval > 0)
			ustoren(pc->pid,pbuf,pc->retval,lbuf);
	}
	return SC_FAKE;
}

int wrap_in_write(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		                service_t sercode, intfun syscall)
{
	unsigned int pbuf=getargn(1,pc);
	unsigned int count=getargn(2,pc);
	int sfd=fd2sfd(pcdata->fds,pc->arg0);
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else {
		char *lbuf=(char *)alloca(count);
		umoven(pc->pid,pbuf,count,lbuf);
		pc->retval = syscall(sfd,lbuf,count);
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
		                service_t sercode, intfun syscall)
{
	unsigned int pbuf=getargn(1,pc);
	unsigned int count=getargn(2,pc);
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
		pc->retval = syscall(sfd,lbuf,count,offset);
		pc->erno=errno;
		if (pc->retval > 0)
			ustoren(pc->pid,pbuf,pc->retval,lbuf);
	}
	return SC_FAKE;
}

int wrap_in_pwrite(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		                service_t sercode, intfun syscall)
{
	unsigned int pbuf=getargn(1,pc);
	unsigned int count=getargn(2,pc);
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
		umoven(pc->pid,pbuf,count,lbuf);
		pc->retval = syscall(sfd,lbuf,count,offset);
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

static void stat2kstat(struct stat *buf,struct kstat *kbuf)
{
	kbuf->kst_dev= buf->st_dev;
	kbuf->kst_ino= buf->st_ino;
	kbuf->kst_mode= buf->st_mode;
	kbuf->kst_nlink= buf->st_nlink;
	kbuf->kst_uid= buf->st_uid;
	kbuf->kst_gid= buf->st_gid;
	kbuf->kst_rdev= buf->st_rdev;
	kbuf->kst_size= buf->st_size;
	kbuf->kst_blksize= buf->st_blksize;
	kbuf->kst_blocks= buf->st_blocks;
	kbuf->kst_atime= buf->st_atime;
	kbuf->kst_mtime= buf->st_mtime;
	kbuf->kst_ctime= buf->st_ctime;
}

int wrap_in_stat(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		service_t sercode, intfun syscall)
{
	int pbuf=getargn(1,pc);
	struct stat buf;
	pc->retval = syscall(pcdata->path,&buf);
	pc->erno=errno;
	if (pc->retval >= 0) {
		struct kstat kbuf;
		stat2kstat(&buf,&kbuf);
		ustoren(pc->pid,pbuf,sizeof(struct kstat),(char *)&kbuf);
	}
	return SC_FAKE;
}

int wrap_in_fstat(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		                service_t sercode, intfun syscall)
{
	int pbuf=getargn(1,pc);
	int sfd=fd2sfd(pcdata->fds,pc->arg0);
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else {
		struct stat buf;
		pc->retval = syscall(sfd,&buf);
		pc->erno=errno;
		if (pc->retval >= 0) {
			struct kstat kbuf;
			stat2kstat(&buf,&kbuf);
			ustoren(pc->pid,pbuf,sizeof(struct kstat),(char *)&kbuf);
		}
	}
	return SC_FAKE;
}

int wrap_in_stat64(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		                service_t sercode, intfun syscall)
{
	int pbuf=getargn(1,pc);
	struct stat64 buf;
	pc->retval = syscall(pcdata->path,&buf);
	pc->erno=errno;
	if (pc->retval >= 0)
		ustoren(pc->pid,pbuf,sizeof(struct stat64),&buf);
	return SC_FAKE;
}

int wrap_in_fstat64(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		                service_t sercode, intfun syscall)
{
	int pbuf=getargn(1,pc);
	int sfd=fd2sfd(pcdata->fds,pc->arg0);
	//printf("wrap_in_fstat: %d",sfd);
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else {
		struct stat64 buf;
		pc->retval = syscall(sfd,&buf);
		pc->erno=(pc->retval<0)?errno:0;
		//pc->erno=errno;
		if (pc->retval >= 0)
			ustoren(pc->pid,pbuf,sizeof(struct stat64),&buf);
	}
	return SC_FAKE;
}

int wrap_in_readlink(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		                service_t sercode, intfun syscall)
{
	unsigned int pbuf=getargn(1,pc);
	unsigned int bufsiz=getargn(2,pc);
	char *lbuf=(char *)alloca(bufsiz);
	pc->retval = syscall(pcdata->path,lbuf,bufsiz);
	pc->erno=errno;
	if (pc->retval > 0)
		ustoren(pc->pid,pbuf,pc->retval,lbuf);
	return SC_FAKE;
}

int wrap_in_getdents(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		                service_t sercode, intfun syscall)
{
	int pbuf=getargn(1,pc);
	unsigned int bufsiz=getargn(2,pc);
	int sfd=fd2sfd(pcdata->fds,pc->arg0);
	//printf("wrap_in_getdents(sc:%d ,pc,pcdata,sercode:%d,syscall);\n",sc_number,sercode);
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else {
		char *lbuf=(char *)alloca(bufsiz);
		pc->retval = syscall(sfd,lbuf,bufsiz);
		//pc->erno=(pc->retval<0)?errno:0;
		pc->erno=errno;
		if (pc->retval > 0)
			ustoren(pc->pid,pbuf,pc->retval,lbuf);
	}
	return SC_FAKE;
}

int wrap_in_access(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		                service_t sercode, intfun syscall)
{
	unsigned int mode=getargn(1,pc);
	pc->retval = syscall(pcdata->path,mode);
	pc->erno=errno;
	return SC_FAKE;
}


int wrap_in_lseek(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		                service_t sercode, intfun syscall)
{
	int sfd=fd2sfd(pcdata->fds,pc->arg0);
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else {
		int offset =getargn(1,pc);
		int whence =getargn(2,pc);
		pc->retval = syscall(sfd,offset,whence);
		pc->erno=errno;
	}
	return SC_FAKE;
}

int wrap_in_llseek(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		                service_t sercode, intfun syscall)
{
	unsigned int offhi=getargn(1,pc);
	unsigned int offlo=getargn(2,pc);
	unsigned int result=getargn(3,pc);
	unsigned int whence=getargn(4,pc);
	int sfd=fd2sfd(pcdata->fds,pc->arg0);
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else {
		pc->retval = syscall(sfd,offhi,offlo,result,whence);
		pc->erno=errno;
	}
	return SC_FAKE;
}

int wrap_in_notsupp(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		                service_t sercode, intfun syscall)
{
	//printf("wrap_in_notsupp %d\n",sc_number);
	pc->retval= -1;
	pc->erno= EOPNOTSUPP;
	return SC_FAKE;
}

int wrap_in_readv(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		                service_t sercode, intfun syscall)
{
	int sfd=fd2sfd(pcdata->fds,pc->arg0);
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else {
		unsigned int vecp=getargn(1,pc);
		unsigned int count=getargn(2,pc);
		unsigned int i,totalsize,size;
		struct iovec *iovec=(struct iovec *)alloca(count * sizeof(struct iovec));
		struct iovec liovec;
		umoven(pc->pid,vecp,count * sizeof(struct iovec),(char *)iovec);
		for (i=0,totalsize=0;i<count;i++)
			totalsize += iovec[i].iov_len;
		char *lbuf=(char *)alloca(totalsize);
		liovec.iov_base=lbuf;
		liovec.iov_len=totalsize;
		pc->retval = syscall(sfd,&liovec,1);
		pc->erno=errno;
		if (size > 0) {
			for (i=0;i<count && size>0;i++) {
				int qty=(size > iovec[i].iov_len)?iovec[i].iov_len:size;
				ustoren(pc->pid,(long)iovec[i].iov_base,qty,lbuf);
				lbuf += qty;
				size -= qty;
			}
		}
	}
	return SC_FAKE;
}

int wrap_in_writev(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		                service_t sercode, intfun syscall)
{
	int sfd=fd2sfd(pcdata->fds,pc->arg0);
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else {
		unsigned int vecp=getargn(1,pc);
		unsigned int count=getargn(2,pc);
		unsigned int i,totalsize,size;
		struct iovec *iovec=(struct iovec *)alloca(count * sizeof(struct iovec));
		struct iovec liovec;
		umoven(pc->pid,vecp,count * sizeof(struct iovec),(char *)iovec);
		for (i=0,totalsize=0;i<count;i++)
			totalsize += iovec[i].iov_len;
		char *lbuf=(char *)alloca(totalsize);
		char *p=lbuf;
		for (i=0;i<count && size>0;i++) {
			int qty=(size > iovec[i].iov_len)?iovec[i].iov_len:size;
			umoven(pc->pid,(long)iovec[i].iov_base,qty,p);
			p += qty;
			size -= qty;
		}
		liovec.iov_base=lbuf;
		liovec.iov_len=totalsize;
		pc->retval = syscall(sfd,&liovec,1);
		pc->erno=errno;
	}
	return SC_FAKE;
}
