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

struct sc_map {
	int scno;
	serfun scchoice;
	intfun wrapin;
	intfun wrapout;
	short flags;
	char nargs;
};

extern struct sc_map scmap[];
extern struct sc_map sockmap[];
extern int scmap_scmapsize;
extern int scmap_sockmapsize;

#define CB_R 0x1
#define CB_W 0x2
#define CB_X 0x4
#define ALWAYS 0x10

#endif
