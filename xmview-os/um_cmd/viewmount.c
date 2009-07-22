/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   viewmount: mount command for viewos
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

#include<stdio.h>
#include<stdlib.h>
#include<fcntl.h>
#include<getopt.h>
#include<sys/mount.h>

void usage(void)
{
	fprintf(stderr,"Usage:\n"
			"     viewmount -h                 : print this help\n"
			"     viewmount -t type dev dir    : ordinary mount command\n"
			"Other options: [-r] [-o options].\n"
			"For many more details, say man 1 viewmount.\n"
			);
	exit(2);
}

int main(int argc, char * argv[])
{
	char *type=NULL;
	char *source=NULL;
	char *target=NULL;
	char *options=NULL;
	unsigned long mountflags;
	int opt;

	while ((opt = getopt(argc, argv, "hVt:o:r")) != -1) {
		switch (opt) {
			case 't':
				type = optarg;
				break;
			case 'o':
				options = optarg;
				break;
			case 'r':
				mountflags |= MS_RDONLY;
				break;
			default: /* '?' */
				usage();
		}
	}

	if (optind+1 >= argc)
		usage();

	source=argv[optind];
	target=argv[optind+1];

	if (mount(source, target, type, mountflags, options))
		perror("mount");
}
