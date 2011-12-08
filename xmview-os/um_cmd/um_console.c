/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   umviewname.c 
 *   uname extension to view-os (umview)
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
 *   $Id: vuname.c 970 2011-08-03 14:37:34Z rd235 $
 *
 */   
#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <config.h>
#include <termios.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <um_lib.h>

void usage(int inside_viewos)
{
	if (inside_viewos) 
		fprintf(stderr, 
				"Usage: umconsole [pid]\n"
				"\n");
	else
		fprintf(stderr, 
				"Usage: umconsole pid\n"
				"   (pid can be omitted only inside a View-OS machine)\n"
				"\n");
	exit(1);
}

static int term_setraw()
{
	static int status=0;
	static struct termios oflags;
	struct termios nflags;
	if (status) {
		if (tcsetattr(fileno(stdin), TCSANOW, &oflags) != 0) {
			perror("tcsetattr");
			exit(1);
		}
	} else {
		tcgetattr(fileno(stdin), &oflags);
		nflags = oflags;
		nflags.c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP
				| INLCR | IGNCR | ICRNL | IXON);
		nflags.c_oflag &= ~OPOST;
		nflags.c_lflag &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
		nflags.c_cflag &= ~(CSIZE | PARENB);
		nflags.c_cflag |= CS8;
		if (tcsetattr(fileno(stdin), TCSANOW, &nflags) != 0) {
			perror("tcsetattr");
			exit(1);
		}
	}
	status = 1-status;
	return status;
}

void console_connect(int pid)
{
	int conn=socket(PF_UNIX, SOCK_STREAM, 0);
	struct sockaddr_un sun;
	int rv;
	char buf[128];
	struct pollfd fds[]={{0,POLLIN,0},{conn,POLLIN,0}};
	memset(&sun,0,sizeof(sun));
	sun.sun_family = PF_UNIX;
	fds[1].fd=conn;
	snprintf(sun.sun_path,sizeof(sun.sun_path),"/tmp/.umview-console%d",pid);
	if (connect(conn,(struct sockaddr *) &sun, sizeof(sun)) < 0) {
		perror("Connecting to console");
		return;
	}
	while (1) {
		int nfd=poll(fds,2,-1);
		//printf("%x %x %d\n",nfd,fds[0].revents,fds[1].revents);
		if (fds[0].revents) {
			int n=read(0,buf,128);
			if (n<=0) break;
			write(conn,buf,n);
		}
		if (fds[1].revents) {
			int n=read(conn,buf,128);
			if (n<=0) break;
			write(1,buf,n);
		}
	}
	close(conn);
}

int main(int argc, char *argv[])
{
	struct viewinfo vi;
	int c=um_view_getinfo(&vi);
	int pid;
	if (argc < 3) {
		if (argc == 1) {
			if (c < 0) 
				usage(c==0);
			pid=vi.serverid;
		} else
			pid=atoi(argv[1]);
		term_setraw();
		/* do the job! */
		console_connect(pid);
		term_setraw();
		printf("\n");
	} else {
		usage(c==0);
	}
	return 0;
}
