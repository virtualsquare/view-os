/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   um_ls_service user command
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
#include <config.h>

void usage()
{
	fprintf(stderr, "Usage:\n\tum_ls_service\n");
}

main(int argc, char *argv[])
{
	unsigned char lsbuf[256];
	char name[256];
	int i,n;
	if (argc != 1)
		usage();
	else {
		if ((n=um_list_service(lsbuf,256)) < 0) {
			perror("um_list_service");
			exit(-1);
		}
		else {
			for (i=0;i<n;i++) {
				if ((um_name_service(lsbuf[i],name,256))<0)
					*name=0;
				printf("um_service %-2d code %02x name \"%s\"\n",i+1,lsbuf[i],name);
			}
			exit(0);
		}
	}
}
