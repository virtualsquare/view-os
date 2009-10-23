/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   pcb.c: merge pcb.* files to create the View-OS process control block
 *   
 *   Copyright 2007 Renzo Davoli University of Bologna - Italy
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

#include <config.h>
#include "pcb.h"

voidf 
#define _PCB_CONSTRUCTOR 
#include "pcb-all.h"
#undef _PCB_CONSTRUCTOR 
#define _PCB_DESTRUCTORS 
#include "pcb-all.h"
#undef _PCB_DESTRUCTORS 
dummy;

static voidfun constructors[] = {
#define _PCB_CONSTRUCTOR 
#include "pcb-all.h"
#undef _PCB_CONSTRUCTOR 
};
#define NCONSTRUCTORS sizeof(constructors)/sizeof(voidfun)

static voidfun destructors[] = {
#define _PCB_DESTRUCTOR
#include "pcb-all.h"
#undef _PCB_DESTRUCTOR 
};
#define NDESTRUCTORS sizeof(destructors)/sizeof(voidfun)

static voidfun inits[] = {
#define _PCB_INITS 
#include "pcb-all.h"
#undef _PCB_INITS 
};
#define NINITS sizeof(inits)/sizeof(voidfun)

static voidfun finis[] = {
#define _PCB_FINIS 
#include "pcb-all.h"
#undef _PCB_FINIS 
};
#define NFINIS sizeof(finis)/sizeof(voidfun)

void pcb_constructor(struct pcb *pcb,int flags,int npcbflag)
{
	register int i;
	for (i=0;i<NCONSTRUCTORS;i++) 
		constructors[i](pcb,flags,npcbflag);
}

void pcb_destructor(struct pcb *pcb,int flags,int npcbflag)
{
	register int i;
	for (i=NDESTRUCTORS-1;i>=0;i--) 
		destructors[i](pcb,flags,npcbflag);
}

void pcb_inits(int flags)
{
	register int i;
	for (i=0;i<NINITS;i++)
		inits[i](flags);
}

void pcb_finis(int flags)
{
	register long i;
	for (i=NFINIS-1;i>=0;i--)
		finis[i](flags);
}

