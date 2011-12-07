/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   um_passwd change passwd
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
#include <termios.h>
#include <string.h>

void usage()
{
	fprintf(stderr, "Usage:\n\tum_passwd [passwd hash]\n");
}

static void getpwd(char *prompt, char *pwd, int size)
{
	struct termios oflags, nflags;

	/* disabling echo */
	tcgetattr(fileno(stdin), &oflags);
	nflags = oflags;
	nflags.c_lflag &= ~ECHO;
	nflags.c_lflag |= ECHONL;

	if (tcsetattr(fileno(stdin), TCSANOW, &nflags) != 0) {
		perror("tcsetattr");
		exit(1);                         
	}                                         
	printf("%s: ",prompt);                     
	fgets(pwd, size, stdin);
	pwd[strlen(pwd) - 1] = 0; 
	/* restore terminal */
	if (tcsetattr(fileno(stdin), TCSANOW, &oflags) != 0) {
		perror("tcsetattr");
		exit(1);                         
	}
}

int main(int argc, char *argv[])
{
	char old[256];
	char new[256];
	char chk[256];
	if (argc == 2) {
		if (strcmp(argv[1],"-e")==0) {
			getpwd("password",old,sizeof(old));
			if (um_pwd(UM_PWD_OP_ENCODE,old,new) >= 0)
				printf("%s\n",new);
			else {
				perror("um_passwd");
				return 1;
			}
		} else {
			if (um_pwd(UM_PWD_OP_SET,"",argv[1]) < 0) {
				perror("um_passwd");
				return 1;
			}
		}
	} else {
		getpwd("old password",old,sizeof(old));
		getpwd("new password",new,sizeof(new));
		getpwd("retype new password",chk,sizeof(chk));

		if (strcmp(new,chk) != 0) {
			fprintf(stderr, "new password mismatch\n");
			return 1;
		}

		if (um_pwd(UM_PWD_OP_CHANGE,old,new) < 0) {
			perror("um_passwd");
			return 1;
		}
	}
	return 0;
}

