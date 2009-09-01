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
 *   $Id$
 *
 */   
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <config.h>
#include <um_lib.h>

void usage()
{
	fprintf(stderr, 
			"Usage: vuname [OPTION]...\n"
			"Print certain View-OS system information.  With no OPTION, same as -s.\n"
			"\n"
			" -a, --all                print all information, in the following order,\n"
			" except omit -p and -i if unknown:\n"
			" -s, --kernel-name        print the kernel name\n"
			" -n, --nodename           print the network node hostname\n"
			" -r, --kernel-release     print the kernel release\n"
			" -v, --kernel-version     print the kernel version\n"
			" -m, --machine            print the machine hardware name\n"
			" -p, --processor          print the processor type or \"unknown\"\n"
			" -i, --hardware-platform  print the hardware platform or \"unknown\"\n"
			" -o, --operating-system   print the operating system\n"
			" -U, --serverid           print the server id\n"
			" -V, --viewid             print the view id\n"
			" -N, --viewname           print the view name\n"
			"other options\n"
			" -q, --quiet              quiet mode: silent on errors\n"
			" -x, --nouname            do not use uname when outside View-OS\n"
			"     --help     display this help and exit\n"
			"     --version  output version information and exit\n"
			"\n");
}

char flags[12];
int quiet;
int unameok=1;
main(int argc, char *argv[])
{
	int c;
	int position=0;
	int i;
	struct viewinfo vi;
	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
			{"all", 0, 0, 'a'},
			{"kernel-name", 0, 0, 's'},
			{"nodename",0,0,'n'},
			{"kernel-release",0,0,'r'},
			{"kernel-version",0,0,'v'},
			{"machine",0,0,'m'},
			{"processor",0,0,'p'},
			{"hardware-platform",0,0,'i'},
			{"operating-system",0,0,'o'},
			{"serverid",0,0,'U'},
			{"viewid",0,0,'V'},
			{"viewname",0,0,'N'},
			{"quiet",0,0,'q'},
			{"nouname",0,0,'x'},
			{"help",0,0,0x100},
			{"version",0,0,0x101},
			{0,0,0,0}
		};
		c=getopt_long(argc,argv,"asnrvmpioxqUVN",long_options,&option_index);
		if (c == -1) break;
		switch (c) {
			case 'a': flags[0]=1; break;
			case 's': flags[1]=1; break;
			case 'n': flags[2]=1; break;
			case 'r': flags[3]=1; break;
			case 'v': flags[4]=1; break;
			case 'm': flags[5]=1; break;
			case 'p': flags[6]=1; break;
			case 'i': flags[7]=1; break;
			case 'o': flags[8]=1; break;
			case 'U': flags[9]=1; break;
			case 'V': flags[10]=1; break;
			case 'N': flags[11]=1; break;
			case 'q': quiet=1; break;
			case 'x': unameok=0; break;
			case 0x100:
				usage();
				exit(0);
				break;
			case 0x101:
				printf("umviewname (View-OS project) 1.0\n"
						"Copyright (C) 2007 View-OS Team - University of Bologna\n"
						"This is free software.  You may redistribute copies of it under the terms of\n"
						"the GNU General Public License <http://www.gnu.org/licenses/gpl.html>.\n"
						"There is NO WARRANTY, to the extent permitted by law.\n"

						"Written by Renzo Davoli\n");
				exit(0);
				break;
			default:
				usage();
				exit(1);
		}
	}
	if (argc - optind != 0) {
		usage();
		exit(1);
	}
	c=um_view_getinfo(&vi);
	if (c<0) {
		if (unameok)
			c=uname(&vi.uname);
		if (c<0) {
			if (!quiet) perror("umviewname:");
			exit (1);
		}
	} else
		unameok=0;
	for (c=i=0;i<12;i++)
		c+=flags[i];
	if (c) {
		if(flags[0] || flags[1])
			printf("%s ",vi.uname.sysname);
		if(flags[0] || flags[2])
			printf("%s ",vi.uname.nodename);
		if(flags[0] || flags[3])
			printf("%s ",vi.uname.release);
		if(flags[0] || flags[4])
			printf("%s ",vi.uname.version);
		if(flags[0] || flags[5])
			printf("%s ",vi.uname.machine);
		if(flags[6])
			printf("%s ","unknown");
		if(flags[7])
			printf("%s ","unknown");
		if(flags[0] || flags[8]) {
			if (unameok)
				printf("%s ","GNU/Linux");
			else
				printf("%s ","GNU/Linux/View-OS");
		}
		if(flags[0] || flags[9])
			printf("%d ",vi.serverid);
		if(flags[0] || flags[10])
			printf("%d ",vi.viewid);
		if(flags[0] || flags[11])
			printf("%s ",vi.viewname);
		printf("\n");
	} else {
			printf("%s\n",vi.uname.nodename);
	}
}
