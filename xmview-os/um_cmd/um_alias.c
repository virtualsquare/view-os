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
 */   
#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <config.h>
#include <libgen.h>
#include <um_lib.h>

void usage(char *name,char *what)
{
	fprintf(stderr, 
			"Usage: %s alias [%sname]\n"
			"\n"
			"This command sets an alias for a %sname (View-OS)\n"
			"\n",name,what,what);
	exit(2);
}

int main(int argc, char *argv[])
{
	char *aliasname;
	char *what;
	char *name=basename(argv[0]);
	int (*aliasfun)();
	if (strcmp(name,"um_fsalias")==0) {
		what="filesystem";
		aliasfun=um_fsalias;
	} else
		usage(name,"");
	if (um_check_viewos()==0) {
		fprintf(stderr,"This is a View-OS command. It works only inside a umview/kmview virtual machine\n");
		usage(name,what);
	}
	if (argc < 2 || argc > 3) {
		usage(name,what);
	}
	if (argc == 2)
		aliasname="";
	else
		aliasname=argv[2];
	aliasfun(argv[1],aliasname);
	return 0;
}
