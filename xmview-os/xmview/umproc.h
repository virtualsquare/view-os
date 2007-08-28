/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   um_proc.h: mgmt of process fd's, services fd's and fake files
 *   
 *   Copyright 2005 Renzo Davoli University of Bologna - Italy
 *   Modified 2005 Mattia Belletti
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
#ifndef _UMPROC_H
#define _UMPROC_H

#define OLFD_STEP 8 /*only power of 2 values */
#define OLFD_STEP_1 (OLFD_STEP - 1)

//#define UM_NONE 255

#include "services.h"
#include "treepoch.h"

#ifdef _UM_MMAP
extern int um_mmap_secret;
extern int um_mmap_pageshift;
#endif

/* informations about the full set of file descriptors of a process */
struct pcb_file {
	/* with CLONE_FILES, more than one process can refer to the same file
	 * descriptors, so we must count them in order to make free at the
	 * right time */
	int count;
	/* lfdlist is an array of local file descriptors (which are indexes in
	 * the global lfd_tab); nolfd is the length of lfdlist; lfdlist[real
	 * file descriptor] = local file descriptor */
	int nolfd;
	int *lfdlist;
};

void um_proc_open();
void um_proc_close();
char *um_proc_fakecwd();
char *um_proc_tmpname();
#if 0
void lfd_addproc (struct pcb_file **p,int flag);
void lfd_delproc (struct pcb_file *p);
#endif
int lfd_open (service_t service, int sfd, char *path, int flags, int nested);
void lfd_close (int lfd);
int lfd_dup(int lfd);
int lfd_getcount(int lfd);
void lfd_nullsfd(int lfd);
int lfd_getsfd(int lfd);
service_t lfd_getservice(int lfd);
char *lfd_getfilename(int lfd);
char *lfd_getpath(int lfd);
int fd2lfd (struct pcb_file *p, int fd);
int fd_getfdfl(struct pcb_file *p, int fd);
int fd_setfdfl(struct pcb_file *p, int fd, int val);
int fd_getflfl(struct pcb_file *p, int fd);
int fd2sfd (struct pcb_file *p, int fd);
char *fd_getpath(struct pcb_file *p, int fd);
void lfd_register (struct pcb_file *p, int fd, int lfd);
void lfd_deregister_n_close(struct pcb_file *p, int fd);
void lfd_closeall();
void lfd_signal(int lfd);
void lfd_delsignal(int lfd);
service_t service_fd(struct pcb_file *p, int fd, int setepoch);
char *sfd_getpath(service_t code, int sfd);

#endif
