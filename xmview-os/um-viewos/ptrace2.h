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
#ifndef _PTRACE2_H
#define _PTRACE2_H
#include <sys/ptrace.h>

#ifndef PTRACE_MULTI
#define PTRACE_MULTI 0x4300
#define PTRACE_PEEKCHARDATA 0x4301
#define PTRACE_POKECHARDATA 0x4302
#define PTRACE_PEEKSTRINGDATA 0x4303

struct ptrace_multi {
	long request;
	long addr;
	void *localaddr;
	long length;
};
#endif

#ifndef PTRACE_SYSVM	
#define PTRACE_SYSVM	33
/* options for PTRACE_SYSVM */
#define PTRACE_VM_TEST          0x80000000
#define PTRACE_VM_SKIPCALL      1
#define PTRACE_VM_SKIPEXIT      2
#endif
#define PTRACE_VM_SKIPOK        (PTRACE_VM_SKIPCALL | PTRACE_VM_SKIPEXIT)

#ifndef PTRACE_VIEWOS	
#define PTRACE_VIEWOS	0x4000
/* options fpr PTRACE_VIEWOS */
#define PT_VIEWOS_TEST          0x80000000
#endif

#endif
