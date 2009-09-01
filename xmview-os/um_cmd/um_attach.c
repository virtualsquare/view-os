/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   um_attach user command
 *   
 *   Copyright 2008 Renzo Davoli University of Bologna - Italy
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
#include <um_lib.h>

void usage()
{
	fprintf(stderr, "Usage:\n\tum_attach pid\n");
}

main(int argc, char *argv[])
{
	int pid;
	if (argc != 2)
		usage();
	else {
		if (um_attach(atoi(argv[1])) < 0) {
			perror("um_attach");
			exit(-1);
		}
		else
			exit(0);
	}
}

