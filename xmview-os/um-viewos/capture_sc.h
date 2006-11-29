/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   
 *
 *   Copyright 2005 Renzo Davoli University of Bologna - Italy
 *   Modified 2005 Ludovico Gardenghi
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
#ifndef CAPTURE_SC_H_
#define CAPTURE_SC_H_

extern int first_child_exit_status;
/* let the game start! */
int capture_main(char **argv,int has_pselect);
/* resume a process previously suspended */
void sc_resume(void *pc);

/* get the pcb of the current thread (thread safe) */
struct pcb *get_pcb();
/* set the pcb of the current thread */
void set_pcb(void *new);
/* just ask for the current size of the pcbtable */
int pcbtablesize(void);

/* set up an internal pipe for ancient kernels (< 2.6.18)
 * not supporting ppoll */
int wake_tracer_init();
/* wake up the tracer by the pipe (ancient kernels) */
void wake_tracer(int s);
/* read from the pipe to rearm the pipe trigger */
void do_wake_tracer();
/* This is the handler of sigchld from user processes */
void tracehand();

#endif
