/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   um_lock_service user command
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
	fprintf(stderr, "Usage:\n\tum_lock_service [-i]\n");
}

main(int argc, char *argv[])
{
	if (argc > 2 || argc == 2 && strcmp(argv[1],"-i") != 0)
		usage();
	else {
		if (um_lock_service(argc==2) < 0) {
			perror("um_lock_service");
			exit(-1);
		}
		else
			exit(0);
	}
}

