/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   viewumount: umount command for viewos
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
#include<stdio.h>
#include<stdlib.h>
#include<fcntl.h>
#include<getopt.h>
#include<sys/mount.h>

void usage(void)
{
	fprintf(stderr,"Usage:\n"
			"    viewumount -h                       : print this help\n"
			"    viewumount [-f] [-l] special | node : ordinary mount command\n"
			"For many more details, say man 1 viewumount\n"
			);
	exit(2);
}

int main(int argc, char * argv[])
{
	char *target=NULL;
	unsigned long umountflags;
	int opt;

	while ((opt = getopt(argc, argv, "hfl")) != -1) {
		switch (opt) {
			case 'r':
				umountflags |= MNT_FORCE;
				break;
			case 'l':
				umountflags |= MNT_DETACH;
				break;
			default: /* '?' */
				usage();
		}
	}

	if (optind >= argc)
		usage();

	target=argv[optind];

	if (umount2(target, umountflags))
		perror("umount");

	return 0;
}
