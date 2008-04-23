/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   mstack: default stack choice
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
 *   $Id: um_add_service.c 362 2007-06-08 14:31:54Z rd235 $
 *
 */   
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <config.h>
#include <libgen.h>
#include <msocket.h>

#define AF_MAXMAX AF_MAX+2

int all=1;
int verbose=0;
char family[AF_MAXMAX+1];
char *fname[AF_MAXMAX+1]={
"PF_UNSPEC",
"PF_UNIX ",
"PF_INET",
"PF_AX25",
"PF_IPX",
"PF_APPLETALK",
"PF_NETROM",
"PF_BRIDGE",
"PF_ATMPVC",
"PF_X25",
"PF_INET",
"PF_ROSE",
"PF_DECnet",
"PF_NETBEUI",
"PF_SECURITY",
"PF_KEY",
"PF_NETLINK",
"PF_PACKET ",
"PF_ASH",
"PF_ECONET",
"PF_ATMSVC",
"PF_PROTO21",
"PF_SNA",
"PF_IRDA",
"PF_PPPOX",
"PF_WANPIPE",
"PF_PROTO26",
"PF_PROTO27",
"PF_PROTO28",
"PF_PROTO29",
"PF_PROTO30",
"PF_BLUETOOTH",
"PF_PROTO32",
"PF_PROTO33",
"PF_PROTO34"};

void usage()
{
	fprintf(stderr, "Usage:\n\tmstack [-u46npbihv] [-f #] stack_mountpoint command\n");
	exit(0);
}

main(int argc, char *argv[])
{
	int c;
	argv++;
	argc--;
	while (**argv == '-') {
		char *s=*argv;
		char ff=0;
		while (*s) {
			switch (*s) {
				case '-' : break;
				case 'u' : all=0;family[AF_UNIX]=1; break;
				case '4' : all=0;family[AF_INET]=1; break;
				case '6' : all=0;family[AF_INET6]=1; break;
				case 'n' : all=0;family[AF_NETLINK]=1; break;
				case 'p' : all=0;family[AF_PACKET]=1; break;
				case 'b' : all=0;family[AF_BLUETOOTH]=1; break;
				case 'i' : all=0;family[AF_IRDA]=1; break;
				case 'f' : all=0;ff=1;break;
				case 'v' : verbose=1;break;
				case 'h'	: usage();break;
				default: 
										fprintf(stderr,"Unknown option %c\n",*s);
										usage();
			}
			s++;
		}
		if (ff) {
			argv++;
			argc--;
			s=*argv;
			while (*s) {
				int fam=atoi(s);
				if (fam > 0 && fam <= AF_MAXMAX) 
					family[fam]=1;
				while (*s >= '0' && *s <= '9')
					s++;
				if (*s == ',')
					s++;
			}
		}
		argv++;
		argc--;
	}

	if (argc < 2)
		usage();
	else {
		int fd;
		if (all) {
			if (verbose)
				fprintf(stderr, "pid %d: stack %s for all supported protocol families\n",getpid(),argv[0]);
			if ((fd=msocket(argv[0],0,SOCK_DEFAULT,0)) < 0) {
				perror("mstack");
				exit(-1);
			}
		}	else {
			int i;
			for (i=1;i<=AF_MAXMAX;i++)
				if (family[i]) {
					if (verbose)
						fprintf(stderr, "pid %d: stack %s for %d=%s\n",getpid(),argv[0],i,fname[i]);
					if ((fd=msocket(argv[0],i,SOCK_DEFAULT,0)) < 0) {
						perror("mstack");
						exit(-1);
					}
				}
		}
		argv ++;
		argc --;
		execvp(basename(argv[0]),argv);
	}
}
