/*
 * xlocal.c - a simple, local x forward
 * Copyright 2010 Renzo Davoli
 * 
 * This file is part of SlirpVde6.
 *   
 * SlirpVde6 is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by 
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *        
 * SlirpVde6 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *           
 * You should have received a copy of the GNU General Public License
 * along with SlirpVde6.  If not, see <http://www.gnu.org/licenses/>.
 */            

#include <time.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include "dnsforward.h"
#include "slirpvde6.h"

static void xlocal_close(int fdin, int fdout) {
	slirpoll_delfd(fdin);
	slirpoll_delfd(fdout);
	lwip_close(fdin);
	close(fdout);
}

static void xlocal_inout(int fdin, void *arg) {
	int fdout = (int) arg;
	char buf[1500];
	int n=lwip_read(fdin,buf,sizeof(buf));
	if (n==0)
		xlocal_close(fdin,fdout);
	else
		write(fdout,buf,n);
}

static void xlocal_outin(int fdout, void *arg) {
	int fdin = (int) arg;
	char buf[1500];
	int n=read(fdout,buf,sizeof(buf));
	if (n==0)
		xlocal_close(fdin,fdout);
	else
		lwip_write(fdin,buf,n);
}

static void xlocal_accept(int fd, void *arg)
{
	struct sockaddr_in6 addr;
	int addrlen=sizeof(addr);
	int fdin=lwip_accept(fd,(struct sockaddr *) &addr,&addrlen);
	if (fdin >= 0) {
		char *sockname=arg;
		struct sockaddr_un addrun;
		addrun.sun_family=AF_UNIX;
		strncpy(addrun.sun_path, sockname, sizeof(addrun.sun_path));
		int fdout=socket(AF_UNIX,SOCK_STREAM,0);
		if (fdout >= 0 &&
				connect(fdout, (struct sockaddr *)&addrun, sizeof(addrun)) >= 0) {
			slirpoll_addfd(fdin,xlocal_inout,(void *)fdout, POLLIN);
			slirpoll_addfd(fdout,xlocal_outin,(void *)fdin, POLLIN);
		} else {
			if (fdout >= 0)
				close(fdout);
			close(fdin);
		}
	}
}

int xlocal_add(struct stack *stack, int port, char *sockname)
{
	struct sockaddr_in6 saddr;
	int xlocalfd;
	saddr.sin6_family = AF_INET6;
	saddr.sin6_port = htons(port);
	saddr.sin6_addr = in6addr_any;
	if ((xlocalfd=lwip_msocket(stack, PF_INET6, SOCK_STREAM, IPPROTO_TCP)) < 0 ||
			lwip_bind(xlocalfd, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in6)) < 0 ||
			lwip_listen(xlocalfd,5) < 0)
			return -1;
	slirpoll_addfd(xlocalfd,xlocal_accept,sockname, POLLIN);
	return 0;
}
