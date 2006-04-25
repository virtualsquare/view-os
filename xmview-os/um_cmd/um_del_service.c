/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   um_del_service user command
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
#include <unistd.h>
#include <getopt.h>

#define UM_NONE 0xff

void usage()
{
	fprintf(stderr, "Usage:\n\tum_del_service [-p #] [-c hex]\n"
			"\t -p or -c must be specified (but not both)\n");
}

main(int argc, char *argv[])
{
	int c;
	int position=0;
	int code=UM_NONE;
	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
			{"position", 1, 0, 'p'},
			{"code", 1, 0, 'c'},
			{0,0,0,0}
		};
		c=getopt_long(argc,argv,"p:c:",long_options,&option_index);
		if (c == -1) break;
		switch (c) {
			case 'p':
				position=atoi(optarg);
				break;
			case 'c':
				sscanf(optarg,"%x",&code);
				code = code &0xff;
				break;
		}
	}
	if (argc - optind != 0 || (position == 0 && code == UM_NONE) ||
			(position != 0 && code != UM_NONE))
		usage();
	else {
		if (position > 0) {
			char lsbuf[256];
			int n;
			if ((n=um_list_service(lsbuf,256)) < 0) {
				perror("um_del_service");
				exit(-1);
			}
			if (position > n) 
				position=n;
			code=lsbuf[position-1];
			
		}
		if (um_del_service(code) < 0) {
			perror("um_del_service");
			exit(-1);
		}
		else
			exit(0);
	}
}

