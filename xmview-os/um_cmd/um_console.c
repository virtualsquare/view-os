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
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <config.h>
#include <termios.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <um_lib.h>
#include <dirent.h>
#include <pwd.h>

#define CONSOLE_DIR "/tmp"
#define CONSOLE_PREFIX ".umview-console"

void usage(void)
{
	fprintf(stderr, 
			"Usage: umconsole [pid]\n"
			"\n");
	exit(1);
}

void pidlist(void)
{
	int fd=open(CONSOLE_DIR,O_RDONLY|O_DIRECTORY);
	DIR *dp=fdopendir(fd);
	struct dirent *de;
	uid_t me=geteuid();
	int count=0;
	if (!dp) usage();
	while ((de=readdir(dp))!=NULL) {
		if (strncmp(de->d_name,CONSOLE_PREFIX,strlen(CONSOLE_PREFIX))==0) {
			struct stat sbuf;
			if (fstatat(fd,de->d_name,&sbuf,AT_SYMLINK_NOFOLLOW) == 0) {
				if (S_ISSOCK(sbuf.st_mode) && fstatat(fd,de->d_name,&sbuf,AT_SYMLINK_NOFOLLOW) == 0
						&& faccessat(fd,de->d_name,R_OK|W_OK|X_OK,AT_SYMLINK_NOFOLLOW)==0) {
					if (count++ == 0)
						fprintf(stderr, "List of available View-OS consoles:\n");
					if (sbuf.st_uid == me) 
						fprintf(stderr,"%5s\n",de->d_name+strlen(CONSOLE_PREFIX));
					else {
						struct passwd *pwd=getpwuid(sbuf.st_uid);
						fprintf(stderr,"%5s (%s)\n",de->d_name+strlen(CONSOLE_PREFIX),pwd->pw_name);
					}
				}
				//fprintf(stderr,"PID %5d: user %d\n",de->d_name+strlen(CONSOLE_PREFIX),sbuf.st_uid);
			}
		}
	}
	closedir(dp); 
	close(fd);
	if (count == 0)
		fprintf(stderr, "There are no console sessions available\n");
	exit(1);
}

int uniquepid(void)
{
	int fd=open(CONSOLE_DIR,O_RDONLY|O_DIRECTORY);
	DIR *dp=fdopendir(fd);
	struct dirent *de;
	uid_t me=geteuid();
	int pid=0;
	if (!dp) usage();
	while ((de=readdir(dp))!=NULL) {
		if (strncmp(de->d_name,CONSOLE_PREFIX,strlen(CONSOLE_PREFIX))==0) {
			struct stat sbuf;
			if (fstatat(fd,de->d_name,&sbuf,AT_SYMLINK_NOFOLLOW) == 0) {
				if (S_ISSOCK(sbuf.st_mode) && sbuf.st_uid == me && 
						faccessat(fd,de->d_name,R_OK|W_OK|X_OK,AT_SYMLINK_NOFOLLOW)==0) {
					if (pid == 0)
						pid = atoi(de->d_name+strlen(CONSOLE_PREFIX));
					else {
						pid=0;
						break;
					}
				}
			}
		}
	}
	closedir(dp); 
	close(fd);
	return pid;
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
	snprintf(sun.sun_path,sizeof(sun.sun_path),"%s/%s%d",CONSOLE_DIR,CONSOLE_PREFIX,pid);
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
			if (c < 0) {
				if ((pid=uniquepid())==0) 
					pidlist();
			} else
				pid=vi.serverid;
		} else {
			if (strcmp(argv[1],"-l")==0)
				pidlist();
			else
				pid=atoi(argv[1]);
		}
		term_setraw();
		/* do the job! */
		console_connect(pid);
		term_setraw();
		printf("\n");
	} else {
		usage();
	}
	return 0;
}
