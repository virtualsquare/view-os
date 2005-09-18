/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   sctab.h: extension to pcb for sctab.c
 *   
 *   Copyright 2005 Renzo Davoli University of Bologna - Italy
 *   Modified 2005 Mattia Belletti
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
#ifndef __SCTAB_H
#define __SCTAB_H
#include <sys/select.h>
#include <sys/stat.h>

#include "umproc.h"
#include "defs.h"


struct pcb_fs {
	/* more than one process can share this structure - look at clone 2
	 * (CLONE_FS) */
	int count;
	/* filesystem informations (current working directory, root filesystem
	 * [chroot...], and umask) */
	char *cwd;
	void *root;
	mode_t mask;
};

#define MAX_SOCKET_ARGS 6
struct pcb_ext {
	void *path;
	void *selset;
	/* keep track of file system informations - look at clone 2
	 * (CLONE_FS) */
	struct pcb_fs *fdfs;
	/* file descriptors of this process */
	struct pcb_file *fds;
	/* PTRACE_MULTI for Sockets */
	long sockregs[MAX_SOCKET_ARGS];
};

extern int um_errno;
extern char um_patherror[];

void scdtab_init();

char *um_getpath(int laddr,struct pcb *pc);
char *um_abspath(int laddr,struct pcb *pc,int link);

void um_set_errno(struct pcb *pc,int i);
char *um_getcwd(struct pcb *pc,char *buf,int size);
int um_x_lstat64(char *filename, struct stat64 *buf,void *umph);
int um_x_readlink(char *path, char *buf, size_t bufsiz,void *umph);

/* modules callbacks for extra args */
int um_mod_getpid(void *umph);
int um_mod_getsyscallno(void *umph);
int* um_mod_getargs(void *umph);

//struct pcb* pid2pcb(int pid);

//#define UM_NONE 255
#endif
