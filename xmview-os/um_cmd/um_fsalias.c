/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   um_fsalias.c 
 *   define an alias for a file system name
 *   
 *   Copyright 2009 Renzo Davoli University of Bologna - Italy
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
 *   $Id: viewname.c 464 2008-04-17 10:53:55Z garden $
 *
 */   
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <config.h>
#include <um_lib.h>


void usage()
{
	fprintf(stderr, 
			"Usage: um_fsalias alias [filesystemname]\n"
			"\n"
			"This command sets an alias for a filesystemname (View-OS)\n"
			"\n");
}

main(int argc, char *argv[])
{
	char *filesystemname;
	struct viewinfo vi;
	if (argc < 2 || argc > 3) {
		usage();
		exit(-1);
	}
	if (argc == 2)
		filesystemname="";
	else
		filesystemname=argv[2];
	um_fsalias(argv[1],argv[2]);
	exit (0);
}
