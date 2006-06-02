/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   um_socket: socketcall wrappers
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
#include <asm/ptrace.h>
#include <asm/unistd.h>
#include <linux/net.h>
#include <sys/uio.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <alloca.h>
#include "defs.h"
#include "umproc.h"
#include "services.h"
#include "um_services.h"
#include "sctab.h"
#include "scmap.h"
#include "utils.h"

#define umNULL ((int) NULL)

int wrap_in_socket(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		service_t sercode, intfun um_syscall)
{
	int domain  =pc->arg2;
	int type    =pcdata->sockregs[1];
	int protocol=pcdata->sockregs[2];

	//printf("fake socket %d %d %d\n",domain,type,protocol);
	pc->retval = um_syscall(domain,type,protocol);
	pc->erno = errno;
	//printf("socket exit %d %d\n",pc->retval,pc->erno);
	if (pc->retval >= 0 && (pc->retval=lfd_open(sercode,pc->retval,NULL,0)) >= 0) {
		char *filename=lfd_getfilename(pc->retval);
		int filenamelen=WORDALIGN(strlen(filename));
		long sp=getsp(pc);
		ustorestr(pc,sp-filenamelen,filenamelen,filename); /*socket?*/
		putscno(__NR_open,pc);
		putargn(0,sp-filenamelen,pc);
		putargn(1,O_RDONLY,pc);
		return SC_CALLONXIT;
	} else
		return SC_FAKE;
}

/* accept creates a new fd! */
int wrap_in_accept(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		service_t sercode, intfun um_syscall)
{
	int sfd=fd2sfd(pcdata->fds,pc->arg2);
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else {
		long sock_addr=pcdata->sockregs[1];
		long sock_plen=pcdata->sockregs[2];
		int sock_len;
		if (sock_plen != umNULL)
			umoven(pc,sock_plen,4,&sock_len);
		char *sock=(char *)alloca(sock_len);
		umoven(pc,sock_addr,sock_len,sock);
		pc->retval = um_syscall(sfd,sock,&sock_len);
		pc->erno=errno;
		if (pc->erno == 0) {
			if (sock_addr != umNULL)
				ustoren(pc,sock_addr,sock_len,sock);
			if (sock_plen != umNULL)
				umoven(pc,sock_plen,4,&sock_len);
		}
		if (pc->retval >= 0 && (pc->retval=lfd_open(sercode,pc->retval,NULL,0)) >= 0) {
			char *filename=lfd_getfilename(pc->retval);
			int filenamelen=WORDALIGN(strlen(filename));
			int sp=getsp(pc);
			ustorestr(pc,sp-filenamelen,filenamelen,filename); /*socket?*/
			putscno(__NR_open,pc);
			putargn(0,sp-filenamelen,pc);
			putargn(1,O_RDONLY,pc);
			return SC_CALLONXIT;
		} else
			return SC_FAKE;
	}
	return SC_FAKE;
}

int wrap_out_socket(int sc_number,struct pcb *pc,struct pcb_ext *pcdata) {
	/*int lerno=errno;*/
	if (pc->retval >= 0) {
		int fd=getrv(pc);	
		if (fd >= 0) {
			/* update open file table*/
			lfd_register(pcdata->fds,fd,pc->retval);
			/* restore parms*/
			putscno(pc->scno,pc);
			putargn(0,pc->arg0,pc);
			putargn(1,pc->arg1,pc);
			putrv(fd,pc);
		} else {
			putrv(pc->retval,pc);
			puterrno(pc->erno,pc);
			lfd_close(pc->retval);
		}
	} else {
		putrv(pc->retval,pc);
		puterrno(pc->erno,pc);
	}
	return STD_BEHAVIOR;
}

int wrap_in_bind_connect(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		service_t sercode, intfun um_syscall)
{
	int sfd=fd2sfd(pcdata->fds,pc->arg2);
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else {
		long sock_addr=pcdata->sockregs[1];
		long sock_len=pcdata->sockregs[2];
		char *sock=(char *)alloca(sock_len);
		umoven(pc,sock_addr,sock_len,sock);
		pc->retval = um_syscall(sfd,sock,sock_len);
		pc->erno=errno;
	}
	return SC_FAKE;
}

int wrap_in_listen(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		service_t sercode, intfun um_syscall)
{
	int sfd=fd2sfd(pcdata->fds,pc->arg2);
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else {
		int backlog=pcdata->sockregs[1];
		pc->retval=um_syscall(sfd,backlog);
		pc->erno=errno;
	}
	return SC_FAKE;
}

int wrap_in_getsock(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		service_t sercode, intfun um_syscall)
{
	int sfd=fd2sfd(pcdata->fds,pc->arg2);
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else {
		long sock_addr=pcdata->sockregs[1];
		long sock_plen=pcdata->sockregs[2];
		int sock_len;
		if (sock_plen != umNULL)
			umoven(pc,sock_plen,4,&sock_len);
		char *sock=(char *)alloca(sock_len);
		umoven(pc,sock_addr,sock_len,sock);
		pc->retval = um_syscall(sfd,sock,&sock_len);
		pc->erno=errno;
		if (pc->erno == 0) {
			if (sock_addr != umNULL)
				ustoren(pc,sock_addr,sock_len,sock);
			if (sock_plen != umNULL)
				umoven(pc,sock_plen,4,&sock_len);
		}
	}
	return SC_FAKE;
}

int wrap_in_send(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		service_t sercode, intfun um_syscall)
{
	int sfd=fd2sfd(pcdata->fds,pc->arg2);
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else {
		long buf=pcdata->sockregs[1];
		int len=pcdata->sockregs[2];
		int flags=pcdata->sockregs[3];
		char *lbuf=(char *)alloca(len); 
		umoven(pc,buf,len,lbuf);
		pc->retval=um_syscall(sfd,lbuf,len,flags);
		pc->erno=errno;
	}
	return SC_FAKE;
}

int wrap_in_recv(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		service_t sercode, intfun um_syscall)
{
	int sfd=fd2sfd(pcdata->fds,pc->arg2);
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else {
		long buf=pcdata->sockregs[1];
		int len=pcdata->sockregs[2];
		int flags=pcdata->sockregs[3];
		char *lbuf=(char *)alloca(len);
		pc->retval=um_syscall(sfd,lbuf,len,flags);
		pc->erno=errno;
		if (pc->retval > 0)
			ustoren(pc,buf,pc->retval,lbuf);
	}
	return SC_FAKE;
}

int wrap_in_sendto(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		service_t sercode, intfun um_syscall)
{
	int sfd=fd2sfd(pcdata->fds,pc->arg2);
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else {
		long buf=pcdata->sockregs[1];
		int len=pcdata->sockregs[2];
		int flags=pcdata->sockregs[3];
		long pto=pcdata->sockregs[4];
		int tolen=pcdata->sockregs[5];
		char *lbuf=(char *)alloca(len); 
		char *tosock=NULL;
		umoven(pc,buf,len,lbuf);
		if (pto != umNULL) {
			tosock=alloca(tolen);
			umoven(pc,pto,tolen,tosock);
		}
		pc->retval=um_syscall(sfd,lbuf,len,flags,tosock,tolen);
		pc->erno=errno;
	}
	return SC_FAKE;
}

int wrap_in_recvfrom(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		service_t sercode, intfun um_syscall)
{
	int sfd=fd2sfd(pcdata->fds,pc->arg2);
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else {
		long buf=pcdata->sockregs[1];
		int len=pcdata->sockregs[2];
		int flags=pcdata->sockregs[3];
		long pfrom=pcdata->sockregs[4];
		long pfromlen=pcdata->sockregs[5];
		int fromlen=0;
		char *lbuf=(char *)alloca(len);
		char *fromsock=NULL;
		if (pfromlen != umNULL) {
			umoven(pc,pfromlen,4,(char *)&fromlen);
			if (pfrom != umNULL && fromlen != 0) {
				fromsock=alloca(fromlen);
				umoven(pc,pfrom,fromlen,fromsock);
			}
		}
		pc->retval=um_syscall(sfd,lbuf,len,flags,fromsock,&fromlen);
		pc->erno=errno;
		if (pc->retval > 0) {
			ustoren(pc,buf,pc->retval,lbuf);
			if (pfrom != umNULL)
				ustoren(pc,pfrom,fromlen,fromsock);
			if (pfromlen != umNULL)
				ustoren(pc,pfromlen,4,&fromlen);
		}
	}
	return SC_FAKE;
}

int wrap_in_shutdown(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		service_t sercode, intfun um_syscall)
{
	int sfd=fd2sfd(pcdata->fds,pc->arg2);
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else {
		int how=pcdata->sockregs[1];
		pc->retval=um_syscall(sfd,how);
		pc->erno=errno;
	}
	return SC_FAKE;
}

int wrap_in_getsockopt(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		service_t sercode, intfun um_syscall)
{
	int sfd=fd2sfd(pcdata->fds,pc->arg2);
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else {
		int level=pcdata->sockregs[1];
		int optname=pcdata->sockregs[2];
		long poptval=pcdata->sockregs[3];
		long poptlen=pcdata->sockregs[4];
		int optlen;
		void *optval;
		if (poptlen != umNULL) {
			umoven(pc,poptlen,4,(char *)&optlen);
			optval=(optlen > 0)?alloca(optlen):NULL;
		} else {
			optlen=0;
			optval=NULL;
		}
		pc->retval=um_syscall(sfd,level,optname,optval,&optlen);
		pc->erno=errno;
		if (poptlen != umNULL)
			ustoren(pc,poptlen,4,&optlen);
		if (poptval != umNULL)
			ustoren(pc,poptval,optlen,optval);
	}
	return SC_FAKE;
}

int wrap_in_setsockopt(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		service_t sercode, intfun um_syscall)
{
	int sfd=fd2sfd(pcdata->fds,pc->arg2);
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else {
		int level=pcdata->sockregs[1];
		int optname=pcdata->sockregs[2];
		long poptval=pcdata->sockregs[3];
		int optlen=pcdata->sockregs[4];
		void *optval;
		//printf("setsockopt fd %d level %d optname %d poptval %x optlen %d\n",pc->arg2,level,optname,poptval,optlen);
		if (optlen > 0 && poptval != umNULL) { 
			optval=alloca(optlen);
			umoven(pc,poptval,optlen,optval);
		} else
			optval=NULL;
		pc->retval=um_syscall(sfd,level,optname,optval,optlen);
		pc->erno=errno;
		/*if (optval != NULL)
			ustoren(pc,poptval,optlen,optval);*/
	}
	return SC_FAKE;
}

int wrap_in_recvmsg(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		service_t sercode, intfun um_syscall)
{
	int sfd=fd2sfd(pcdata->fds,pc->arg2);
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else {
		long pmsg=pcdata->sockregs[1];
		int flags=pcdata->sockregs[2];
		struct msghdr msg;
		struct msghdr lmsg;
		struct iovec liovec;
		struct iovec *iovec;
		umoven(pc,pmsg,sizeof(struct msghdr),&msg);
		lmsg=msg;
		if (msg.msg_namelen > 0 && msg.msg_name != NULL) {
			lmsg.msg_name=alloca(msg.msg_namelen);
			umoven(pc,(long)msg.msg_name,msg.msg_namelen,lmsg.msg_name);
		}
		if (msg.msg_iovlen > 0 && msg.msg_iov != NULL) {
			iovec=alloca(msg.msg_iovlen * sizeof(struct iovec));
			umoven(pc,(long)msg.msg_iov,msg.msg_iovlen * sizeof(struct iovec),iovec);
		} else {
			iovec=NULL;
			msg.msg_iovlen = 0;
		}
		if (msg.msg_controllen > 0 && msg.msg_control != NULL) {
			lmsg.msg_control=alloca(msg.msg_controllen);
			umoven(pc,(long)msg.msg_control,msg.msg_controllen,lmsg.msg_control);
		}
		{
			unsigned int i,totalsize,size;
			char *lbuf;
			for (i=0,totalsize=0;i<msg.msg_iovlen;i++)
				totalsize += iovec[i].iov_len;
			lbuf=(char *)alloca(totalsize);
			//printf("RECVMSG fd %d namesize %d msg_iovlen %d msg_controllen %d total %d\n",
			//		pc->arg2,msg.msg_namelen, msg.msg_iovlen, msg.msg_controllen, totalsize);
			liovec.iov_base=lbuf;
			liovec.iov_len=totalsize;
			lmsg.msg_iov=&liovec;
			lmsg.msg_iovlen=1;
			size=pc->retval = um_syscall(sfd,&lmsg,flags);
			//printf("%d size->%d\n",sfd,size);

			pc->erno=errno;
			if (size > 0) {
				for (i=0;i<msg.msg_iovlen && size>0;i++) {
					int qty=(size > iovec[i].iov_len)?iovec[i].iov_len:size;
					ustoren(pc,(long)iovec[i].iov_base,qty,lbuf);
					lbuf += qty;
					size -= qty;
				}
			}
			if (msg.msg_namelen > 0 && msg.msg_name != NULL) {
				msg.msg_namelen=lmsg.msg_namelen;
				ustoren(pc,(long)msg.msg_name,msg.msg_namelen,lmsg.msg_name);
			}
			if (msg.msg_controllen > 0 && msg.msg_control != NULL) {
				msg.msg_controllen=lmsg.msg_controllen;
				ustoren(pc,(long)msg.msg_control,msg.msg_controllen,lmsg.msg_control);
			}
			msg.msg_flags=lmsg.msg_flags;
			ustoren(pc,pmsg,sizeof(struct msghdr),&msg);
		}
	}
	return SC_FAKE;
}

int wrap_in_sendmsg(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		service_t sercode, intfun um_syscall)
{
	int sfd=fd2sfd(pcdata->fds,pc->arg2);
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else {
		long pmsg=pcdata->sockregs[1];
		int flags=pcdata->sockregs[2];
		struct msghdr msg;
		struct msghdr lmsg;
		umoven(pc,pmsg,sizeof(struct msghdr),&msg);
		lmsg=msg;
		struct iovec liovec;
		struct iovec *iovec;
		if (msg.msg_namelen > 0 && msg.msg_name != NULL) {
			lmsg.msg_name=alloca(msg.msg_namelen);
			umoven(pc,(long)msg.msg_name,msg.msg_namelen,lmsg.msg_name);
		}
		if (msg.msg_iovlen > 0 && msg.msg_iov != NULL) {
			iovec=alloca(msg.msg_iovlen * sizeof(struct iovec));
			umoven(pc,(long)msg.msg_iov,msg.msg_iovlen * sizeof(struct iovec),iovec);
		} else {
			iovec=NULL;
			msg.msg_iovlen = 0;
		}
		if (msg.msg_controllen > 0 && msg.msg_control != NULL) {
			lmsg.msg_control=alloca(msg.msg_controllen);
			umoven(pc,(long)msg.msg_control,msg.msg_controllen,lmsg.msg_control);
		}
		{
			unsigned int i,totalsize,size;
			char *lbuf;
			for (i=0,totalsize=0;i<msg.msg_iovlen;i++)
				totalsize += iovec[i].iov_len;
			lbuf=(char *)alloca(totalsize);
			liovec.iov_base=lbuf;
			liovec.iov_len=totalsize;
			lmsg.msg_iov=&liovec;
			lmsg.msg_iovlen=1;
			char *p=lbuf;
			//printf("SNDMSG fd %d namesize %d msg_iovlen %d msg_controllen %d total %d\n",
			//		pc->arg2, msg.msg_namelen, msg.msg_iovlen, msg.msg_controllen, totalsize);
			for (i=0;i<msg.msg_iovlen;i++) {
				int qty=iovec[i].iov_len;
				umoven(pc,(long)iovec[i].iov_base,qty,p);
				p += qty;
			}
			size=pc->retval = um_syscall(sfd,&lmsg,flags);
			//printf("%d size->%d\n",sfd,size);
			pc->erno=errno;
		}
	}
	return SC_FAKE;
}
