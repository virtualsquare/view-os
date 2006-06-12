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
typedef service_t (* serfun)();
typedef service_t serfunt();
typedef long sysfunt();
typedef long wrapinfun();
typedef long wrapoutfun();
typedef long wrapfun();
/*
typedef int wrapinfun(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		                char sercode, sysfun um_syscall);
typedef int wrapoutfun(int sc_number,struct pcb *pc,struct pcb_ext *pcdata);
*/

// remap real syscall number to a nu
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
	sysfun wrapin;
	/* ...guess... */
	sysfun wrapout;
	/* the choice function: this function tells the service which have to
	 * manage the nested system call */
	serfun nestchoice;
	/* wrapin function: this function is called for wrapped syscalls.
	 syscall */
	sysfun nestwrap;
	/* flags: dependant on the table; contains stuff such that the ALWAYS
	 * flag, the CB_R flag, etc... (look below) */
	short flags;
	/* number of arguments of this system call - used for some
	 * optimizations */
	char nargs;
	/* set of calls, for a better selection (choice fun)*/
	char setofcall;
};

extern struct sc_map scmap[];
extern struct sc_map sockmap[];
extern struct sc_map virscmap[];
extern int scmap_scmapsize;
extern int scmap_sockmapsize;
extern int scmap_virscmapsize;

#define CB_R 0x1
#define CB_W 0x2
#define CB_X 0x4
/* if set, the wrapin function must be called anyway, even if the choice
 * function tell noone is interested - useful for some system call we must
 * process internally, e.g. to keep fd table updated, or mmap mappings,
 * etc... */
#define ALWAYS 0x10

#define USC_TYPE(X) (scmap[(X)].setofcall)
#define SOC_NONE	0x00
#define SOC_SOCKET	0x80
#define SOC_FILE	0x40
#define SOC_NET	  0x20
#define SOC_TIME  0x1
#define SOC_UID   0x2
#define SOC_PRIO  0x3
#define SOC_PID   0x4
#define SOC_HOSTID 0x5

#endif
