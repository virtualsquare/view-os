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
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>

#include "umproc.h"
#include "defs.h"
#include "treepoch.h"

extern int _umview_version;

//extern pthread_key_t pcb_key; /* key to grab the current thread pcb */

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
	struct timestamp tst;
	epoch_t nestepoch;
	void *path;
	struct stat64 pathstat;
	/* struct seldata* */
	void *selset;
	/* path for tmp files that must be deleted over the next syscall */
	/* see execve mgmt */
	void *tmpfile2unlink_n_free;
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

char *um_getpath(long laddr,struct pcb *pc);
char *um_abspath(long laddr,struct pcb *pc,struct stat64 *pst,int dontfollowlink);

int pcb_newfork(struct pcb *pc);

void um_set_errno(struct pcb *pc,int i);
char *um_getcwd(struct pcb *pc,char *buf,int size);
int um_x_access(char *filename,int mode, struct pcb *pc);
int um_x_lstat64(char *filename, struct stat64 *buf, struct pcb *pc);
int um_x_readlink(char *path, char *buf, size_t bufsiz, struct pcb *pc);
epoch_t um_setepoch(epoch_t epoch);

struct timestamp *um_x_gettst();

/* modules callbacks for extra args */
int um_mod_getpid();
int um_mod_umoven(long addr, int len, void *_laddr);
int um_mod_umovestr(long addr, int len, void *_laddr);
int um_mod_ustoren(long addr, int len, void *_laddr);
int um_mod_ustorestr(long addr, int len, void *_laddr);
int um_mod_getsyscallno(void);
int um_mod_getumpid(void);
long* um_mod_getargs(void);
struct stat64 *um_mod_getpathstat(void);
char *um_mod_getpath(void);
int um_mod_getsyscalltype(int scno);


//struct pcb* pid2pcb(int pid);

//#define UM_NONE 255
#endif
