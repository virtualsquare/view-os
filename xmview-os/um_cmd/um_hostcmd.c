/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   um_hostcmd run a command on the hosting machine
 *   
 *   Copyright 2011 Renzo Davoli University of Bologna - Italy
 *   Some ideas and code taken from reptyr Copyright (C) 2011 by Nelson Elhage
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
 *   $Id: um_add_service.c 362 2007-06-08 14:31:54Z rd235 $
 *
 */   
#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <config.h>
#include <um_lib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <termios.h>
#include <signal.h>

void _debug(const char *pfx, const char *msg, va_list ap) {

	if (pfx)
		fprintf(stderr, "%s", pfx);
	vfprintf(stderr, msg, ap);
	fprintf(stderr, "\n");
}

void die(const char *msg, ...) {
	va_list ap;
	va_start(ap, msg);
	_debug("[!] ", msg, ap);
	va_end(ap);

	exit(1);
}

void setup_raw(struct termios *save) {
	struct termios set;
	if (tcgetattr(0, save) < 0)
		die("Unable to read terminal attributes: %m");
	set = *save;
	cfmakeraw(&set);
	if (tcsetattr(0, TCSANOW, &set) < 0)
		die("Unable to set terminal attributes: %m");
}

void resize_pty(int pty) {
	struct winsize sz;
	if (ioctl(0, TIOCGWINSZ, &sz) < 0)
		return;
	ioctl(pty, TIOCSWINSZ, &sz);
}

int writeall(int fd, const void *buf, ssize_t count) {
	ssize_t rv;
	while (count > 0) {
		rv = write(fd, buf, count);
		if (rv < 0)
			return rv;
		count -= rv;
		buf += rv;
	}
	return 0;
}

int winch_happened = 0;

void do_winch(int signal) {
	winch_happened = 1;
}

void do_proxy(int pty) {
	char buf[4096];
	ssize_t count;
	struct pollfd fds[]={{0,POLLIN,0},{pty,POLLIN,0}};
	while (1) {
		if (winch_happened) {
			resize_pty(pty);
			/* FIXME: racy against a second resize */
			winch_happened = 0;
		}
		if (poll(fds,2,-1) < 0) {
			if (errno == EINTR)
				continue;
			fprintf(stderr, "poll: %m");
			return;
		}
		if (fds[0].revents) {
			count = read(0, buf, sizeof buf);
			if (count <= 0)
				return;
			writeall(pty, buf, count);
		}
		if (fds[1].revents) {
			count = read(pty, buf, sizeof buf);
			if (count <= 0)
				return;
			writeall(1, buf, count);
		}
	}
}

void usage()
{
	fprintf(stderr, "Usage:\n\tum_hostcmd cmd args\n");
}



int main(int argc, char *argv[])
{
	struct sigaction act;
	struct termios saved_termios;
	int pty;
	char pts_name[256];
	char password[64]="";

	if ((pty = um_open("/dev/ptmx", O_RDWR|O_NOCTTY, 0, NULL)) < 0) {
		if (errno==EPERM) {
			struct termios oflags, nflags;
			tcgetattr(fileno(stdin), &oflags);
			nflags = oflags;
			nflags.c_lflag &= ~ECHO;
			nflags.c_lflag |= ECHONL;

			if (tcsetattr(fileno(stdin), TCSANOW, &nflags) != 0) {
				perror("tcsetattr");
				return 1;
			}
			printf("view-os host password: ");
			fgets(password, sizeof(password), stdin);
			password[strlen(password) - 1] = 0;
			/* restore terminal */
			if (tcsetattr(fileno(stdin), TCSANOW, &oflags) != 0) {
				perror("tcsetattr");
				return 1;
			}
			if ((pty = um_open("/dev/ptmx", O_RDWR|O_NOCTTY, 0, password)) < 0) 
				die("View-OS host command: %m");
		} else
			die("Unable to open /dev/ptmx: %m");
	}
	if (unlockpt(pty) < 0)
		die("Unable to unlockpt: %m");
	ptsname_r(pty,pts_name,256);
	//printf("Opened a new pty: %s\n", pts_name);

	sigaction(SIGWINCH, &act, NULL);
	setup_raw(&saved_termios);
	resize_pty(pty);
	memset(&act, 0, sizeof act);
	act.sa_handler = do_winch;
	act.sa_flags   = 0;
	if (um_cmd(argv[1],argv+1,pts_name,password) == 0) {
		do_proxy(pty);
		tcsetattr(0, TCSANOW, &saved_termios);
		exit(0);
	}
	tcsetattr(0, TCSANOW, &saved_termios);
	perror("um_hostcmd");
	exit(0);
}
