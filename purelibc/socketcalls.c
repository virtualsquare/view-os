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
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */ 

#include <config.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <linux/net.h>
#include "purelibc.h"
#include <alloca.h>

static long int pure_int_socketcall(long int, ...);
sfun _pure_socketcall=pure_int_socketcall;
extern sfun _pure_syscall;
static char sockargc[]={0,3,3,3,2,3,3,3,4,4,4,6,6,2,5,5,3,3};

#if defined(__x86_64__) || defined(__ia64__) || defined(__alpha__) || defined(__hppa__) || defined(__arm__)

static int sock64_map[] = {
	/* 0 */ 0,
	/* 1 SYS_SOCKET */		__NR_socket,
	/* 2 SYS_BIND */		__NR_bind,
	/* 3 SYS_CONNECT */		__NR_connect,
	/* 4 SYS_LISTEN */		__NR_listen,
	/* 5 SYS_ACCEPT */		__NR_accept,
	/* 6 SYS_GETSOCKNAME */	__NR_getsockname,
	/* 7 SYS_GETPEERNAME */	__NR_getpeername,
	/* 8 SYS_SOCKETPAIR */	__NR_socketpair,
	/* 9 SYS_SEND */	__NR_sendto, // not used, converted to sendto
	/*10 SYS_RECV */	__NR_recvfrom, //converted to recvfrom
	/*11 SYS_SENDTO */		__NR_sendto,
	/*12 SYS_RECVFROM */	__NR_recvfrom,
	/*13 SYS_SHUTDOWN */		__NR_shutdown,
	/*14 SYS_SETSOCKOPT */	__NR_setsockopt,
	/*15 SYS_GETSOCKOPT */	__NR_getsockopt,
	/*16 SYS_SENDMSG */		__NR_sendmsg,
	/*17 SYS_RECVMSG */		__NR_recvmsg,
#ifdef __NR_accept4
	/*18 SYS_ACCEPT4 */		__NR_accept4,
#endif
};

static long int pure_int_socketcall(long int sockcallno, ...){
	va_list ap;
	register int i;
	register int narg = sockargc[sockcallno];
	int sysno = sock64_map[sockcallno];
	long int args[6];
	va_start(ap, sockcallno);
	for (i=0; i<narg;i++)
		args[i]=va_arg(ap,long int);
	va_end(ap);
	return _pure_syscall(sysno,args[0],args[1],args[2],args[3],args[4],args[5]);
}
#else
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
#endif

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
#if defined(SYS_ACCEPT4) || defined(__NR_accept4)
int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen,int flags){
	return _pure_socketcall(SYS_ACCEPT4,sockfd,addr,addrlen,flags);
}
#endif
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
#if defined(__x86_64__) || defined(__ia64__) || defined(__alpha__) || defined(__hppa__) || defined(__arm__)
	return sendto(s,buf,len,flags,NULL,0);
#else
	return _pure_socketcall(SYS_SEND,s,buf,len,flags);
#endif
}
ssize_t recv(int s, void *buf, size_t len, int flags){
#if defined(__x86_64__) || defined(__ia64__) || defined(__alpha__) || defined(__hppa__) || defined(__arm__)
	return recvfrom(s,buf,len,flags,NULL,0);
#else
	return _pure_socketcall(SYS_RECV,s,buf,len,flags);
#endif
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
