/*   This is part of km-ViewOS
 *   The kernel-mode implementation of OSVIEW -- A Process with a View
 *
 *   Copyright 2007 Renzo Davoli University of Bologna - Italy
 *   Based on um-ViewOS 2005 Renzo Davoli
 *   Modified 2005 Ludovico Gardenghi
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
#ifndef CAPTURE_KM_H_
#define CAPTURE_KM_H_
#include <defs.h>

extern divfun scdtab[];
extern char scdnarg[];
#if __NR_socketcall != __NR_doesnotexist
extern divfun sockcdtab[];
#endif
extern int kmviewfd;
extern int first_child_exit_status;
/* let the game start! */
int capture_main(char **argv,void (*root_process_init)());
/* resume a process previously suspended */
void sc_resume(void *pc);

/* get the pcb of the current thread (thread safe) */
struct pcb *get_pcb();
/* set the pcb of the current thread */
void set_pcb(void *new);
/* just ask for the current size of the pcbtable */
int pcbtablesize(void);

/* This is the handler of sigchld from user processes */
void tracehand(void *useless);

#endif
