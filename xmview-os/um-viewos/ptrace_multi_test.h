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
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sched.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <asm/ptrace.h>
#include "ptrace2.h"
#include <asm/unistd.h>

/* kernel feature test:
 * exit value =1 means that there is ptrace multi support
 * vm_mask and viewos_mask are masks of supported features of
 * PTRACE_SYSVM and PTRACE_VIEWOS tags, respectively*/
unsigned int test_ptracemulti(unsigned int *vm_mask,unsigned int *viewos_mask); 
