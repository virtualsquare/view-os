/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   
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
#ifndef _UTILS_H_
#define _UTILS_H_

/* Moves len bytes from address 'addr' in the address space of the process
 * whose pid is 'pid' to local address '_laddr'. */
int umoven(struct pcb *pc, long addr, int len, void *_laddr);
/* Moves bytes from address 'addr' in the address space of the process whose
 * pid is 'pid' to local address '_laddr', until it doesn't find a '\0' */
int umovestr(struct pcb *pc, long addr, int len, void *_laddr);
/* Moves len bytes from local address '_laddr' in our address space to address
 * 'addr' in the address space of the process whose pid is 'pid'. */
int ustoren(struct pcb *pc, long addr, int len, void *_laddr);
/* Moves bytes from local address '_laddr' in our address space to address
 * 'addr' in the address space of the process whose pid is 'pid', until it
 * doesn't find a '\0' */
int ustorestr(struct pcb *pc, long addr, int len, void *_laddr);

#endif

