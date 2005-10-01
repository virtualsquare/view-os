/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   um_add_service user command
 *   
 *   Copyright 2005 Renzo Davoli University of Bologna - Italy
 *   
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 *   $Id$
 *
 */   
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>

void usage()
{
	fprintf(stderr, "Usage:\n\tum_add_service [-p #] service_dyn_library.so\n");
}

main(int argc, char *argv[])
{
	int c;
	int position=0;
	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
			{"position", 1, 0, 'p'},
			{0,0,0,0}
		};
		c=getopt_long(argc,argv,"p:",long_options,&option_index);
		if (c == -1) break;
		switch (c) {
			case 'p':
				position=atoi(optarg);
				break;
		}
	}
	if (argc - optind != 1)
		usage();
	else {
		if (um_add_service(position,argv[optind]) < 0) {
			perror("um_add_service");
			exit(-1);
		}
		else
			exit(0);
	}
}

