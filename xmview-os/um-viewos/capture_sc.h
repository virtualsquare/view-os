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
int capture_main(char **argv,int has_pselect);
void sc_resume(void *pc);

struct pcb *get_pcb();
void set_pcb(void *new);
int pcbtablesize(void);

void wake_tracer_init();
void wake_tracer(int s);
int add_tracerpipe_to_wset(int prevmax, fd_set *wset);
int must_wake_tracer(fd_set *wset);
void tracehand();

#endif
