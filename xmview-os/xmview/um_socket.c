/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   um_socket: socketcall wrappers
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
#include <asm/ptrace.h>
#include <asm/unistd.h>
#include <linux/net.h>
#include <sys/uio.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <alloca.h>
#include <config.h>
#include "defs.h"
#include "umproc.h"
#include "services.h"
#include "hashtab.h"
#include "um_services.h"
#include "sctab.h"
#include "scmap.h"
#include "utils.h"

#define SOCK_DEFAULT 0

/* SOCKET & MSOCKET call management (IN) */

int wrap_in_msocket(int sc_number,struct pcb *pc,
		struct ht_elem *hte, sysfun um_syscall)
{
	/* path = pc->sysarg[0] = pc->path */
	int domain  =pc->sysargs[1];
	int type    =pc->sysargs[2];
	int protocol=pc->sysargs[3];
	/* msocket is ALWAYS called: msocket(NULL...) calls must be converted
	 * into socket(...) syscalls */
	if (hte != NULL) {
		if (type == SOCK_DEFAULT) {
			if (pc->path == NULL) {
				pc->retval = -1;
				pc->erno = EINVAL;
			} else {
				if ((pc->retval = um_syscall(pc->path,domain,type,protocol)) < 0) {
					pc->erno = errno;
				}
				//printk("SOCK_DEFAULT %s %d\n",pc->path,domain);
			}
			return SC_FAKE;
		} else {
			if ((pc->retval = um_syscall(pc->path,domain,type,protocol)) < 0) {
				if (errno == ENOSYS && pc->path==NULL) {
					/* backward compatibility:
					 * modules implementing only "socket". 
					 * the code reaches this case only from wrap_in_socket */
#if (__NR_socketcall != __NR_doesnotexist)
					um_syscall=ht_socketcall(hte,SYS_SOCKET);
#else
					um_syscall=ht_syscall(hte,uscno(__NR_socket));
#endif
					if ((pc->retval = um_syscall(domain,type,protocol)) < 0) {
						pc->erno = errno;
					}
				} else
					pc->erno = errno;
			}
			/* create the comm fifo with the user process */
			if (pc->retval >= 0 &&
					(pc->retval=lfd_open(hte,pc->retval,NULL,O_RDWR,0)) >= 0) {
				char *filename=lfd_getfilename(pc->retval);
				int filenamelen=WORDALIGN(strlen(filename));
				long sp=getsp(pc);
				/* change the system call arguments (open the fifo) */
				/* could give some trouble if a process tests the
				 * "type" of the file connected to the fd and the
				 * module does not give the right answer!*/
				ustoren(pc,sp-filenamelen,filenamelen,filename); /*socket?*/
				putscno(__NR_open,pc);
				pc->sysargs[0]=sp-filenamelen;
				pc->sysargs[1]=O_RDONLY;
				return SC_CALLONXIT;
			} else
				return SC_FAKE;
		} 
	} else {
		/* msocket -> socket translation for native system calls
		 * just for the case path=NULL */
		if (pc->sysargs[0]==umNULL) {
#if (__NR_socketcall != __NR_doesnotexist)
			struct {
				long domain;
				long type;
				long protocol;
			} socketcallparms = {domain,type,protocol};
			long sp=getsp(pc);
			ustoren(pc,sp-sizeof(socketcallparms),
					sizeof(socketcallparms),&socketcallparms);
			pc->sysargs[0]=SYS_SOCKET;
			pc->sysargs[1]=sp-sizeof(socketcallparms);
			putscno(__NR_socketcall,pc);
			return SC_MODICALL;
#else
			pc->sysargs[0]=domain;
			pc->sysargs[1]=type;
			pc->sysargs[2]=protocol;
			putscno(__NR_socket,pc);
			return SC_MODICALL;
#endif
		} else {
			pc->retval = -1;
			pc->erno = ENOTSUP;
			return SC_FAKE;
		}
	}
}

int wrap_in_socket(int sc_number,struct pcb *pc,
		struct ht_elem *hte, sysfun um_syscall)
{
	pc->sysargs[3]=pc->sysargs[2];
	pc->sysargs[2]=pc->sysargs[1];
	pc->sysargs[1]=pc->sysargs[0];
	pc->sysargs[0]=umNULL;
	pc->path=NULL;
	return wrap_in_msocket(__NR_msocket,pc,hte,
			ht_virsyscall(hte,VIRSYS_MSOCKET));
}

#define MAX_SOCKLEN 1024
/* accept creates a new fd! */
int wrap_in_accept(int sc_number,struct pcb *pc,
		struct ht_elem *hte, sysfun um_syscall)
{
	int sfd=fd2sfd(pc->fds,pc->sysargs[0]);
	/* the virtual file does not exist */
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else {
		/* get the system call args */
		long sock_plen=pc->sysargs[2];
		int sock_len;
		if (sock_plen != umNULL)
			umoven(pc,sock_plen,4,&sock_len);
		/* safety check for sock */
		if (sock_len == 0 || sock_len > MAX_SOCKLEN) {
			pc->retval= -1;
			pc->erno= EINVAL;
		} else {
			long sock_addr=pc->sysargs[1];
			char *sock;
			if (__builtin_expect((sock_len > MAX_SOCKET_NAME),0)) 
				sock_len=MAX_SOCKET_NAME;
			sock=(char *)alloca(sock_len);
			/* get the sock_addr */
				umoven(pc,sock_addr,sock_len,sock);
				/* virtual syscall */
			if ((pc->retval = um_syscall(sfd,sock,&sock_len)) < 0)
				pc->erno=errno;
			else {
			/* store the results (if the call was successful) */
				if (sock_addr != umNULL)
					ustoren(pc,sock_addr,sock_len,sock);
				if (sock_plen != umNULL)
					umoven(pc,sock_plen,4,&sock_len);
			}
		}
		/* open the new fifo, (accept creates a new fd) */
		if (pc->retval >= 0 && 
				(pc->retval=lfd_open(hte,pc->retval,NULL,O_RDWR,0)) >= 0) {
			char *filename=lfd_getfilename(pc->retval);
			int filenamelen=WORDALIGN(strlen(filename));
			int sp=getsp(pc);
			ustorestr(pc,sp-filenamelen,filenamelen,filename); /*socket?*/
			putscno(__NR_open,pc);
			pc->sysargs[0]=sp-filenamelen;
			pc->sysargs[1]=O_RDONLY;
			return SC_CALLONXIT;
		} else
			return SC_FAKE;
	}
	return SC_FAKE;
}

/* SOCKET & MSOCKET & ACCEPT wrap out */
int wrap_out_socket(int sc_number,struct pcb *pc) {
	/*int lerno=errno;*/
	//printk("wrap_out_socket %d %d\n",pc->behavior,SC_FAKE);
	/* if everything was okay for the virtual call */
	if (pc->behavior==SC_CALLONXIT && pc->retval >= 0) {
		int fd=getrv(pc);	
		/* if the syscall issued by the process was also okay */
		if (fd >= 0 && addfd(pc,fd) == 0) {
			/* update open file table*/
			lfd_register(pc->fds,fd,pc->retval);
#ifdef __NR_accept4
			if (sc_number == __NR_accept4) {
				int flags = pc->sysargs[3];
				if (flags & SOCK_CLOEXEC) 
					fd_setfdfl(pc->fds,fd,FD_CLOEXEC);
			}
#endif
		} else {
			putrv(pc->retval,pc);
			puterrno(pc->erno,pc);
			//printk("wrap_out_socket!!\n");
			lfd_close(pc->retval);
		}
	} else {
		putrv(pc->retval,pc);
		puterrno(pc->erno,pc);
	}
	return SC_MODICALL;
}

int wrap_in_bind_connect(int sc_number,struct pcb *pc,
		struct ht_elem *hte, sysfun um_syscall)
{
	int sfd=fd2sfd(pc->fds,pc->sysargs[0]);
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else {
		long sock_addr=pc->sysargs[1];
		long sock_len=pc->sysargs[2];
		char *sock;
		if (__builtin_expect((sock_len > MAX_SOCKET_NAME),0)) 
			sock_len=MAX_SOCKET_NAME;
		sock=(char *)alloca(sock_len);
		umoven(pc,sock_addr,sock_len,sock);
		if ((pc->retval = um_syscall(sfd,sock,sock_len)) < 0)
			pc->erno=errno;
	}
	return SC_FAKE;
}

int wrap_in_listen(int sc_number,struct pcb *pc,
		struct ht_elem *hte, sysfun um_syscall)
{
	int sfd=fd2sfd(pc->fds,pc->sysargs[0]);
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else {
		int backlog=pc->sysargs[1];
		if ((pc->retval=um_syscall(sfd,backlog)) < 0)
			pc->erno=errno;
	}
	return SC_FAKE;
}

int wrap_in_getsock(int sc_number,struct pcb *pc,
		struct ht_elem *hte, sysfun um_syscall)
{
	int sfd=fd2sfd(pc->fds,pc->sysargs[0]);
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else {
		long sock_addr=pc->sysargs[1];
		long sock_plen=pc->sysargs[2];
		int sock_len;
		if (sock_plen != umNULL)
			umoven(pc,sock_plen,4,&sock_len);
		char *sock;
		if (__builtin_expect((sock_len > MAX_SOCKET_NAME),0)) 
			sock_len=MAX_SOCKET_NAME;
		sock=(char *)alloca(sock_len);
		umoven(pc,sock_addr,sock_len,sock);
		if ((pc->retval = um_syscall(sfd,sock,&sock_len)) < 0)
			pc->erno=errno;
		else {
			if (sock_addr != umNULL)
				ustoren(pc,sock_addr,sock_len,sock);
			if (sock_plen != umNULL)
				umoven(pc,sock_plen,4,&sock_len);
		}
	}
	return SC_FAKE;
}

int wrap_in_send(int sc_number,struct pcb *pc,
		struct ht_elem *hte, sysfun um_syscall)
{
	int sfd=fd2sfd(pc->fds,pc->sysargs[0]);
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else 
	{
		long buf=pc->sysargs[1];
		int len=pc->sysargs[2];
		int flags=pc->sysargs[3];
		char *lbuf=(char *)lalloca(len); 
#ifdef SNDRCVMSGUNIFY
		struct iovec iov = {lbuf,len};
		struct msghdr msg = {
			.msg_name=NULL,
			.msg_namelen=0,
			.msg_iov=&iov,
			.msg_iovlen=1,
			.msg_control=NULL,
			.msg_controllen=0,
			.msg_flags=flags};
#endif
		umoven(pc,buf,len,lbuf);
#ifdef SNDRCVMSGUNIFY
		if ((pc->retval=um_syscall(sfd,&msg,flags)) < 0)
			pc->erno=errno;
#else
		if ((pc->retval=um_syscall(sfd,lbuf,len,flags)) < 0)
			pc->erno=errno;
#endif
		lfree(lbuf,len);
	}
	return SC_FAKE;
}

int wrap_in_recv(int sc_number,struct pcb *pc,
		struct ht_elem *hte, sysfun um_syscall)
{
	int sfd=fd2sfd(pc->fds,pc->sysargs[0]);
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else {
		long buf=pc->sysargs[1];
		int len=pc->sysargs[2];
		int flags=pc->sysargs[3];
		char *lbuf=(char *)lalloca(len);
#ifdef SNDRCVMSGUNIFY
		struct iovec iov = {lbuf,len};
		struct msghdr msg = {
			.msg_name=NULL,
			.msg_namelen=0,
			.msg_iov=&iov,
			.msg_iovlen=1,
			.msg_control=NULL,
			.msg_controllen=0,
			.msg_flags=flags};
		if ((pc->retval=um_syscall(sfd,&msg,flags)) < 0)
			pc->erno=errno;
#else
		if ((pc->retval=um_syscall(sfd,lbuf,len,flags)) < 0)
			pc->erno=errno;
#endif
		if (pc->retval > 0)
			ustoren(pc,buf,pc->retval,lbuf);
		lfree(lbuf,len);
	}
	return SC_FAKE;
}

int wrap_in_sendto(int sc_number,struct pcb *pc,
		struct ht_elem *hte, sysfun um_syscall)
{
	int sfd=fd2sfd(pc->fds,pc->sysargs[0]);
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else {
		long buf=pc->sysargs[1];
		int len=pc->sysargs[2];
		int flags=pc->sysargs[3];
		long pto=pc->sysargs[4];
		int tolen=pc->sysargs[5];
		char *lbuf=(char *)lalloca(len); 
		char *tosock=NULL;
#ifdef SNDRCVMSGUNIFY
		struct iovec iov = {lbuf,len};
		struct msghdr msg = {
			.msg_name=NULL,
			.msg_namelen=0,
			.msg_iov=&iov,
			.msg_iovlen=1,
			.msg_control=NULL,
			.msg_controllen=0,
			.msg_flags=flags};
#endif
		umoven(pc,buf,len,lbuf);
		if (pto != umNULL) {
			if (__builtin_expect((tolen > MAX_SOCKET_NAME),0)) 
				tolen=MAX_SOCKET_NAME;
			tosock=alloca(tolen);
			umoven(pc,pto,tolen,tosock);
#ifdef SNDRCVMSGUNIFY
			msg.msg_name=tosock;
			msg.msg_namelen=tolen;
#endif
		}
#ifdef SNDRCVMSGUNIFY
		if ((pc->retval=um_syscall(sfd,&msg,flags)) < 0)
			pc->erno=errno;
#else
		if ((pc->retval=um_syscall(sfd,lbuf,len,flags,tosock,tolen)) < 0)
			pc->erno=errno;
#endif
		lfree(lbuf,len);
	}
	return SC_FAKE;
}

int wrap_in_recvfrom(int sc_number,struct pcb *pc,
		struct ht_elem *hte, sysfun um_syscall)
{
	int sfd=fd2sfd(pc->fds,pc->sysargs[0]);
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else {
		long buf=pc->sysargs[1];
		int len=pc->sysargs[2];
		int flags=pc->sysargs[3];
		long pfrom=pc->sysargs[4];
		long pfromlen=pc->sysargs[5];
		int fromlen=0;
		char *lbuf=(char *)lalloca(len);
		char *fromsock=NULL;
#ifdef SNDRCVMSGUNIFY
		struct iovec iov = {lbuf,len};
		struct msghdr msg = {
			.msg_name=NULL,
			.msg_namelen=0,
			.msg_iov=&iov,
			.msg_iovlen=1,
			.msg_control=NULL,
			.msg_controllen=0,
			.msg_flags=flags};
#endif
		if (pfromlen != umNULL) {
			umoven(pc,pfromlen,4,(char *)&fromlen);
			if (pfrom != umNULL && fromlen != 0) {
				if (__builtin_expect((fromlen > MAX_SOCKET_NAME),0)) 
					fromlen=MAX_SOCKET_NAME;
				fromsock=alloca(fromlen);
				umoven(pc,pfrom,fromlen,fromsock);
			}
#ifdef SNDRCVMSGUNIFY
			msg.msg_name=fromsock;
			msg.msg_namelen=pfromlen;
#endif
		}
#ifdef SNDRCVMSGUNIFY
		if ((pc->retval=um_syscall(sfd,&msg,flags)) < 0)
			pc->erno=errno;
#else
		if ((pc->retval=um_syscall(sfd,lbuf,len,flags,fromsock,&fromlen)) < 0)
			pc->erno=errno;
#endif
		if (pc->retval > 0) {
			ustoren(pc,buf,pc->retval,lbuf);
			if (pfrom != umNULL)
				ustoren(pc,pfrom,fromlen,fromsock);
			if (pfromlen != umNULL)
				ustoren(pc,pfromlen,4,&fromlen);
		}
		lfree(lbuf,len);
	}
	return SC_FAKE;
}

int wrap_in_shutdown(int sc_number,struct pcb *pc,
		struct ht_elem *hte, sysfun um_syscall)
{
	int sfd=fd2sfd(pc->fds,pc->sysargs[0]);
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else {
		int how=pc->sysargs[1];
		if ((pc->retval=um_syscall(sfd,how)) < 0)
			pc->erno=errno;
	}
	return SC_FAKE;
}

int wrap_in_getsockopt(int sc_number,struct pcb *pc,
		struct ht_elem *hte, sysfun um_syscall)
{
	int sfd=fd2sfd(pc->fds,pc->sysargs[0]);
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else {
		int level=pc->sysargs[1];
		int optname=pc->sysargs[2];
		long poptval=pc->sysargs[3];
		long poptlen=pc->sysargs[4];
		int optlen;
		void *optval;
		if (poptlen != umNULL) {
			umoven(pc,poptlen,4,(char *)&optlen);
			if (__builtin_expect((optlen > MAX_SOCKOPT_LEN),0))
				optlen=MAX_SOCKOPT_LEN;
			optval=(optlen > 0)?alloca(optlen):NULL;
		} else {
			optlen=0;
			optval=NULL;
		}
		if ((pc->retval=um_syscall(sfd,level,optname,optval,&optlen)) < 0)
			pc->erno=errno;
		if (poptlen != umNULL)
			ustoren(pc,poptlen,4,&optlen);
		if (poptval != umNULL)
			ustoren(pc,poptval,optlen,optval);
	}
	return SC_FAKE;
}

int wrap_in_setsockopt(int sc_number,struct pcb *pc,
		struct ht_elem *hte, sysfun um_syscall)
{
	int sfd=fd2sfd(pc->fds,pc->sysargs[0]);
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else {
		int level=pc->sysargs[1];
		int optname=pc->sysargs[2];
		long poptval=pc->sysargs[3];
		int optlen=pc->sysargs[4];
		void *optval;
		//printf("setsockopt fd %d level %d optname %d poptval %x optlen %d\n",pc->sysargs[0],level,optname,poptval,optlen);
		if (optlen > 0 && poptval != umNULL) { 
			if (__builtin_expect((optlen > MAX_SOCKOPT_LEN),0))
				optlen=MAX_SOCKOPT_LEN;
			optval=alloca(optlen);
			umoven(pc,poptval,optlen,optval);
		} else
			optval=NULL;
		if ((pc->retval=um_syscall(sfd,level,optname,optval,optlen)) < 0)
			pc->erno=errno;
		/*if (optval != NULL)
			ustoren(pc,poptval,optlen,optval);*/
	}
	return SC_FAKE;
}
/* sendmsg and recvmsg have more complex arguments */
int wrap_in_recvmsg(int sc_number,struct pcb *pc,
		struct ht_elem *hte, sysfun um_syscall)
{
	int sfd=fd2sfd(pc->fds,pc->sysargs[0]);
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else {
		long pmsg=pc->sysargs[1];
		int flags=pc->sysargs[2];
		struct msghdr msg;
		struct msghdr lmsg;
		struct iovec liovec;
		struct iovec *iovec;
		umoven(pc,pmsg,sizeof(struct msghdr),&msg);
		lmsg=msg;
		if (msg.msg_namelen > 0 && msg.msg_name != NULL) {
			if (__builtin_expect((msg.msg_namelen > MAX_SOCKET_NAME),0)) 
				msg.msg_namelen=MAX_SOCKET_NAME;
			lmsg.msg_name=alloca(msg.msg_namelen);
			umoven(pc,(long)msg.msg_name,msg.msg_namelen,lmsg.msg_name);
		}
		if (msg.msg_iovlen > 0 && msg.msg_iov != NULL) {
			if (__builtin_expect((msg.msg_iovlen > IOV_MAX),0)) msg.msg_iovlen=IOV_MAX;
			iovec=alloca(msg.msg_iovlen * sizeof(struct iovec));
			umoven(pc,(long)msg.msg_iov,msg.msg_iovlen * sizeof(struct iovec),iovec);
		} else {
			iovec=NULL;
			msg.msg_iovlen = 0;
		}
		if (msg.msg_controllen > 0 && msg.msg_control != NULL) {
			if (__builtin_expect((msg.msg_controllen > MAX_SOCK_CONTROLLEN),0))
				msg.msg_controllen=MAX_SOCK_CONTROLLEN;
			lmsg.msg_control=alloca(msg.msg_controllen);
			umoven(pc,(long)msg.msg_control,msg.msg_controllen,lmsg.msg_control);
		}
		{
			unsigned int i,totalsize,size;
			char *lbuf;
			for (i=0,totalsize=0;i<msg.msg_iovlen;i++)
				totalsize += iovec[i].iov_len;
			lbuf=(char *)lalloca(totalsize);
			//printk("RECVMSG fd %d namesize %d msg_iovlen %d msg_controllen %d total %d\n",
			//		pc->sysargs[0],msg.msg_namelen, msg.msg_iovlen, msg.msg_controllen, totalsize);
			liovec.iov_base=lbuf;
			liovec.iov_len=totalsize;
			lmsg.msg_iov=&liovec;
			lmsg.msg_iovlen=1;
			//printk("%d size->%d\n",sfd,size);
			if ((size=pc->retval = um_syscall(sfd,&lmsg,flags)) < 0)
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
			lfree(lbuf,totalsize);
		}
	}
	return SC_FAKE;
}

int wrap_in_sendmsg(int sc_number,struct pcb *pc,
		struct ht_elem *hte, sysfun um_syscall)
{
	int sfd=fd2sfd(pc->fds,pc->sysargs[0]);
	if (sfd < 0) {
		pc->retval= -1;
		pc->erno= EBADF;
	} else {
		long pmsg=pc->sysargs[1];
		int flags=pc->sysargs[2];
		struct msghdr msg;
		struct msghdr lmsg;
		umoven(pc,pmsg,sizeof(struct msghdr),&msg);
		lmsg=msg;
		struct iovec liovec;
		struct iovec *iovec;
		if (msg.msg_namelen > 0 && msg.msg_name != NULL) {
			if (__builtin_expect((msg.msg_namelen > MAX_SOCKET_NAME),0)) 
				msg.msg_namelen=MAX_SOCKET_NAME;
			lmsg.msg_name=alloca(msg.msg_namelen);
			umoven(pc,(long)msg.msg_name,msg.msg_namelen,lmsg.msg_name);
		}
		if (msg.msg_iovlen > 0 && msg.msg_iov != NULL) {
			if (__builtin_expect((msg.msg_iovlen > IOV_MAX),0)) msg.msg_iovlen=IOV_MAX;
			iovec=alloca(msg.msg_iovlen * sizeof(struct iovec));
			umoven(pc,(long)msg.msg_iov,msg.msg_iovlen * sizeof(struct iovec),iovec);
		} else {
			iovec=NULL;
			msg.msg_iovlen = 0;
		}
		if (msg.msg_controllen > 0 && msg.msg_control != NULL) {
			if (__builtin_expect((msg.msg_controllen > MAX_SOCK_CONTROLLEN),0))
				msg.msg_controllen=MAX_SOCK_CONTROLLEN;
			lmsg.msg_control=alloca(msg.msg_controllen);
			umoven(pc,(long)msg.msg_control,msg.msg_controllen,lmsg.msg_control);
		}
		{
			unsigned int i,totalsize,size;
			char *lbuf;
			for (i=0,totalsize=0;i<msg.msg_iovlen;i++)
				totalsize += iovec[i].iov_len;
			lbuf=(char *)lalloca(totalsize);
			liovec.iov_base=lbuf;
			liovec.iov_len=totalsize;
			lmsg.msg_iov=&liovec;
			lmsg.msg_iovlen=1;
			char *p=lbuf;
			//printf("SNDMSG fd %d namesize %d msg_iovlen %d msg_controllen %d total %d\n",
			//		pc->sysargs[0], msg.msg_namelen, msg.msg_iovlen, msg.msg_controllen, totalsize);
			for (i=0;i<msg.msg_iovlen;i++) {
				int qty=iovec[i].iov_len;
				umoven(pc,(long)iovec[i].iov_base,qty,p);
				p += qty;
			}
			if ((size=pc->retval = um_syscall(sfd,&lmsg,flags)) < 0)
				pc->erno=errno;
			//printf("%d size->%d\n",sfd,size);
			lfree(lbuf,totalsize);
		}
	}
	return SC_FAKE;
}
