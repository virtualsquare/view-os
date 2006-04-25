/* This is part of pure_libc (a project related to ViewOS and Virtual Square)
 * 
 * socketcall.c: socketcall mgmt
 * 
 * Copyright 2006 Renzo Davoli University of Bologna - Italy
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License a
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */ 

#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <linux/net.h>
#include "pure_libc.h"
#include <alloca.h>

static long int pure_int_socketcall(long int sysno, ...);
sfun _pure_socketcall=pure_int_socketcall;

static int sockargc[]={0,3,3,3,2,3,3,3,4,4,4,6,6,2,5,5,3,3};
static long int pure_int_socketcall(long int sysno, ...){
	va_list ap;
	register int i;
	register int narg=sockargc[sysno];
	long int *args;
	args=alloca(narg*sizeof(long int));
	va_start(ap, sysno);
	for (i=0; i<narg;i++)
		args[i]=va_arg(ap,long int);
	va_end(ap);
	return _pure_syscall(__NR_socketcall,sysno,args);
}

int socket(int domain, int type, int protocol){
	return _pure_socketcall(SYS_SOCKET,domain,type,protocol);
}
int bind(int sockfd, const struct sockaddr *my_addr, socklen_t addrlen){
	return _pure_socketcall(SYS_BIND,sockfd,my_addr,addrlen);
}
int connect(int sockfd, const struct sockaddr *serv_addr, socklen_t addrlen){
	return _pure_socketcall(SYS_CONNECT,sockfd,serv_addr,addrlen);
}
int listen(int sockfd, int backlog){
	return _pure_socketcall(SYS_LISTEN,sockfd,backlog);
}
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen){
	return _pure_socketcall(SYS_ACCEPT,sockfd,addr,addrlen);
}
int getsockname(int s, struct sockaddr *name, socklen_t *namelen){
	return _pure_socketcall(SYS_GETSOCKNAME,s,name,namelen);
}
int getpeername(int s, struct sockaddr *name, socklen_t *namelen){
	return _pure_socketcall(SYS_GETPEERNAME,s,name,namelen);
}
int socketpair(int d, int type, int protocol, int sv[2]){
	return _pure_socketcall(SYS_SOCKETPAIR,d,type,protocol,sv);
}
ssize_t send(int s, const void *buf, size_t len, int flags){
	return _pure_socketcall(SYS_SEND,s,buf,len,flags);
}
ssize_t recv(int s, void *buf, size_t len, int flags){
	return _pure_socketcall(SYS_RECV,s,buf,len,flags);
}
ssize_t sendto(int s, const void *buf, size_t len, int flags, const
		struct sockaddr *to, socklen_t tolen){
	return _pure_socketcall(SYS_SENDTO,s,buf,len,flags,to,tolen);
}
ssize_t recvfrom(int s, void *buf, size_t len, int flags, 
		struct sockaddr *from, socklen_t *fromlen){
	return _pure_socketcall(SYS_RECVFROM,s,buf,len,flags,from,fromlen);
}
int shutdown(int s, int how){
	return _pure_socketcall(SYS_SHUTDOWN,s,how);
}
int setsockopt(int s, int level, int optname, const void *optval,
		socklen_t optlen){
	return _pure_socketcall(SYS_SETSOCKOPT,s,level,optname,optval,optlen);
}
int getsockopt(int s, int level, int optname, void *optval, socklen_t *optlen){
	return _pure_socketcall(SYS_GETSOCKOPT,s,level,optname,optval,optlen);
}
ssize_t sendmsg(int s, const struct msghdr *msg, int flags){
	return _pure_socketcall(SYS_SENDMSG,s,msg,flags);
}
ssize_t recvmsg(int s, struct msghdr *msg, int flags){
	return _pure_socketcall(SYS_RECVMSG,s,msg,flags);
}
