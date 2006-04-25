/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   ptrace_multi_test.c : Test if this kernel has the ptrace_multi patch
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
#include <errno.h>
#define r_waitpid(p,s,o) (syscall(__NR_waitpid,(p),(s),(o)))

static int child(void *arg)
{
  if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0){
    perror("ptrace test_ptracemulti");
  }
  kill(getpid(), SIGSTOP);
  return 0;
}

unsigned int test_ptracemulti(unsigned int *vm_mask, unsigned int *viewos_mask) {
  int pid, status, rv;
  static char stack[1024];

  if((pid = clone(child, &stack[1020], SIGCHLD, NULL)) < 0){
    perror("clone");
    return 0;
  }
  if((pid = r_waitpid(pid, &status, WUNTRACED)) < 0){
	  perror("Waiting for stop");
	  return 0;
  }
 if (ptrace(PTRACE_MULTI, pid, stack, 0) < 0) 
	  rv=0;
  else
	  rv=1;
  errno=0;
  *vm_mask=ptrace(PTRACE_SYSVM, pid, PTRACE_VM_TEST, 0);
  if (errno != 0)
	  *vm_mask=0;
  errno=0;
  *viewos_mask=ptrace(PTRACE_VIEWOS, pid, PT_VIEWOS_TEST, 0);
  if (errno != 0)
	  *viewos_mask=0;
  ptrace(PTRACE_KILL,pid,0,0);
  if((pid = r_waitpid(pid, &status, WUNTRACED)) < 0){
	  perror("Waiting for stop");
	  return 0;
  }
  return rv;
}
