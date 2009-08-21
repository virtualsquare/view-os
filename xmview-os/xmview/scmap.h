/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   scmap.h: structures for system call wrapping table
 *   
 *   Copyright 2005 Renzo Davoli University of Bologna - Italy
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
#ifndef _SCMAP_H
#define _SCMAP_H
#include <poll.h>
#include "hashtab.h"
#include "defs.h"

#define VIRSYS_UMSERVICE 1
#define VIRSYS_MSOCKET 2
#define __NR_msocket VIRSYS_MSOCKET

/* macro for privatescno (as viewed by modules)
 * E-xtended scno (max 16384 syscall per type) */
#if __NR_socketcall != __NR_doesnotexist
#define ESCNO_SOCKET	0x4000
#else
#define ESCNO_SOCKET	0x0000
#endif
#define ESCNO_VIRSC		0x8000
#define ESCNO_MASK	0x3fff
#define ESCNO_MAP		0xC000

//typedef struct service *sss;
typedef struct ht_elem *(*htfun)();
typedef struct ht_elem *htfunt();
typedef long sysfunt();
typedef long wrapinfun();
typedef long wrapoutfun();
typedef long wrapfun();
/*
typedef int wrapinfun(int sc_number,struct pcb *pc,
		                struct ht *hte, sysfun um_syscall);
typedef int wrapoutfun(int sc_number,struct pcb *pc);
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
	htfun scchoice;
	/* wrapin function: this function is called in the IN phase of the
	 * syscall */
	sysfun wrapin;
	/* ...guess... */
	sysfun wrapout;
	/* the choice function: this function tells the service which have to
	 * manage the nested system call */
	htfun nestchoice;
	/* wrapin function: this function is called for wrapped syscalls.
	 syscall */
	sysfun nestwrap;
	/* flags: dependant on the table; contains stuff such that the ALWAYS
	 * flag, the CB_R flag, etc... (look below) */
	short flags;
	/* number of arguments of this system call - used for some
	 * optimizations (lower three bits) */
	/* path argument (for rewriting) in three more bits
		 bits 7,6 unused
		 bits 5,4,3 path arg (+1 !! path is arg 0
		 bits 2,1,0 nargs */
	char nargx;
	/* set of calls, for a better selection (choice fun)*/
	unsigned char setofcall;
};

#define NARGS(X) (X & 0x7)
#define ISPATHARG(X) ((X >> 3) & 0x7)
#define PATHARG(X) (((X >> 3) & 0x7) - 1)
#define PATH0 (1<<3)
#define PATH1 (2<<3)
#define PATH2 (3<<3)
#define PATH3 (4<<3)
#define PATH4 (5<<3)
#define PATH5 (6<<3)

extern struct sc_map scmap[];
extern int scmap_scmapsize;
extern struct sc_map virscmap[];
extern int scmap_virscmapsize;

extern struct sc_map sockmap[];
extern int scmap_sockmapsize;

#define CB_R POLLIN|POLLHUP
#define CB_W POLLOUT

/* if set, the wrapin function must be called anyway, even if the choice
 * function tell noone is interested - useful for some system call we must
 * process internally, e.g. to keep fd table updated, or mmap mappings,
 * etc... */
#define ALWAYS 0x8000
#define NALWAYS 0x4000

static inline struct sc_map *escmapentry(long esysno)
{
	long index=esysno & ESCNO_MASK;
	switch (esysno & ESCNO_MAP)
	{
#if __NR_socketcall != __NR_doesnotexist
		case ESCNO_SOCKET: return &(sockmap[index]);
#endif
		case ESCNO_VIRSC: return &(virscmap[index]);
		default: return &(scmap[uscno(index)]);
	}
}

/* #define USC_TYPE(X) (scmap[(X)].setofcall)*/
#define SOC_NONE	0x00
#define SOC_SOCKET	0x80
#define SOC_FILE	0x40
#define SOC_NET	  0x20
#define SOC_TIME  0x1
#define SOC_UID   0x2
#define SOC_PRIO  0x3
#define SOC_PID   0x4
#define SOC_HOSTID 0x5
#define SOC_MMAP 0x6
#define SOC_SIGNAL 0x7

#endif
