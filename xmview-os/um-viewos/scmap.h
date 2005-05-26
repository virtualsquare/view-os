/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   scmap.h: structures for system call wrapping table
 *   
 *   Copyright 2005 Renzo Davoli University of Bologna - Italy
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
#ifndef _SCMAP_H
#define _SCMAP_H
#include "services.h"

//typedef struct service *sss;
typedef char (* serfun)();
typedef char serfunt();
typedef int intfunt();
typedef int wrapinfun();
typedef int wrapoutfun();
/*
typedef int wrapinfun(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		                char sercode, intfun syscall);
typedef int wrapoutfun(int sc_number,struct pcb *pc,struct pcb_ext *pcdata);
*/

int uscno(int scno);
void init_scmap();

/* An entry in the system call table. Every such structure tells how to process
 * a system call */
struct sc_map {
	/* the number of the system call this row is about */
	int scno;
	/* the choice function: this function tells the service which have to
	 * manage the system call */
	serfun scchoice;
	/* wrapin function: this function is called in the IN phase of the
	 * syscall */
	intfun wrapin;
	/* ...guess... */
	intfun wrapout;
	/* flags: dependant on the table; contains stuff such that the ALWAYS
	 * flag, the CB_R flag, etc... (look below) */
	short flags;
	/* number of arguments of this system call - used for some
	 * optimizations */
	char nargs;
};

extern struct sc_map scmap[];
extern struct sc_map sockmap[];
extern int scmap_scmapsize;
extern int scmap_sockmapsize;

#define CB_R 0x1
#define CB_W 0x2
#define CB_X 0x4
/* if set, the wrapin function must be called anyway, even if the choice
 * function tell noone is interested - useful for some system call we must
 * process internally, e.g. to keep fd table updated, or mmap mappings,
 * etc... */
#define ALWAYS 0x10

#endif
