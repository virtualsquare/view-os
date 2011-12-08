/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   umbinwrap.c: monitoring console 
 * 
 *   Copyright 2011 Renzo Davoli University of Bologna - Italy
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
 */

#include <config.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <errno.h>
#include <stdlib.h>
#include <poll.h>
#include <string.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <sys/un.h>

#define LINELENGTH 128
static char lastline[LINELENGTH+1];
static int lastlinepos;
#define LINEBUF 25
static char *linebuf[LINEBUF]={lastline};
static int curline;

void lb_add(char *buf, int len)
{
	int from,to;
	for (from=to=0;to<len;to++) {
		lastline[lastlinepos++]=buf[to];
		lastline[lastlinepos]=0;
		if (buf[to] == '\n' || lastlinepos>=LINELENGTH) {
			linebuf[curline]=strdup(lastline);
			curline= (curline+1) % LINEBUF;
			if (linebuf[curline]) free (linebuf[curline]);
			lastlinepos=0;
			lastline[lastlinepos]=0;
			linebuf[curline]=lastline;
		}
	}
}

void lb_send(int fd)
{
	int i;
	for (i=0;i<LINEBUF;i++) {
		int this=(i+curline+1)%LINEBUF;
		if (linebuf[this])
			write(fd,linebuf[this],strlen(linebuf[this]));
	}
}

int main(int argc, char *argv[])
{
	int stat;
	char buf[128];
	int pty=atoi(argv[2]);
	int quiet=0;
	//fprintf(stderr,"DAEMON %s %d\n",argv[1],pty);
	struct pollfd fds[10]={{0,POLLIN,0},{pty,POLLIN,0}};
	int nfds=2;
	int conn=socket(PF_UNIX, SOCK_STREAM, 0);
	struct sockaddr_un sun;
	int i,j;
	close(0);
	if (argv[2][strlen(argv[2])-1]=='q') {
		quiet=1;
		close(1);
	}
	sun.sun_family = PF_UNIX;
	snprintf(sun.sun_path,sizeof(sun.sun_path),argv[1]);
	bind(conn, (struct sockaddr *) &sun, sizeof(sun));
	listen(conn,5);
	//printf("mainpoll enter %d\n",conn);
	fds[0].fd=conn;
	while (1) {
		int nfd=poll(fds,nfds,-1);
		//printf("mainpoll step %d\n",nfd);
		if (fds[0].revents) {
			struct sockaddr addr;
			int new;
			socklen_t len;
			len = sizeof(addr);
			//printf("accept\n");
			new=accept(conn,&addr,&len);
			//printf("accept %d\n",new);
			if (new>=0) {
				if (nfds<10) {
					fds[nfds].fd=new;
					fds[nfds].events=POLLIN;
					lb_send(new);
					nfds++;
				} else
					close(new);
			}
		}
		if (fds[1].revents) {
			int n=read(pty,buf,128);
			//printf("mainpoll out %d\n",n);
			if (n<0) break;
			lb_add(buf,n);
			for (i=2; i<nfds; i++)
				write(fds[i].fd,buf,n);
			if (!quiet)
				write(1,buf,n);
		}
		for (i=2; i<nfds; i++) {
			if (fds[i].revents) {
				int n=read(fds[i].fd,buf,128);
				if (n <= 0 || buf[0]=='\004' ) {
					write(fds[i].fd,"\r\n",2);
					close(fds[i].fd);
					fds[i].fd=-1;
				} else {
					//printf("mainpoll out (%d) %d\n",i,n);
					write(pty,buf,n);
				}
			}
		}
		for (i=j=2; i<nfds; i++) {
			fds[j].fd=fds[i].fd;
			if (fds[j].fd >= 0) j++;
		}
		nfds=j;
	}
	unlink(argv[1]);
	int pid=waitpid(-1,&stat,WNOHANG);
	if (pid>0) exit(WEXITSTATUS(stat));
}
