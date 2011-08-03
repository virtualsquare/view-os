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
#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <config.h>
#include <limits.h>
#include <string.h>
#include <um_lib.h>

void usage()
{
	fprintf(stderr, "Usage:\n\tum_ls_service\n");
	exit(2);
}

int main(int argc, char *argv[])
{
	char lsbuf[PATH_MAX];
	char descr[PATH_MAX];
	int n;
	if (um_check_viewos()==0) {
		fprintf(stderr,"This is a View-OS command. It works only inside a umview/kmview virtual machine\n");
		usage();
	}            
	if (argc != 1)
		usage();
	else {
		if ((n=um_list_service(lsbuf,PATH_MAX)) < 0) {
			perror("um_list_service");
			exit(1);
		} else {
			char *name=lsbuf;
			while (1) {
				char *next=strchr(name,':');
				if (next==NULL)
					break;
				*next=0;
				next++;
				if ((um_name_service(name,descr,PATH_MAX))<0)
					*descr=0;
				printf("%s: %s\n",name,descr);
				name=next;
			}
			exit(0);
		}
	}
	return 0;
}
