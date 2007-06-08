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
			"Usage: viewname [newname]\n"
			"\n"
			"This command can get or set the view name (View-OS)\n"
			"\n");
}

main(int argc, char *argv[])
{
	int c;
	struct viewinfo vi;
	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
			{0,0,0,0}
		};
		c=getopt_long(argc,argv,"",long_options,&option_index);
		if (c == -1) break;
		switch (c) {
		}
	}
	if (argc > 2) {
		usage();
		exit(-1);
	}
	if (argc == 1) {
		c=um_view_getinfo(&vi);
		if (c<0) {
			perror("umviewname:");
			exit (-1);
		}
		printf("%s\n",vi.viewname);
	} else {
		c=um_setviewname(argv[1]);
		if (c<0) {
			perror("umviewname:");
			exit (-1);
		}
	}
	exit (0);
}
