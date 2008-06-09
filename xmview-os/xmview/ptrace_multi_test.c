/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   ptrace_multi_test.c : Test if this kernel has the ptrace_multi patch
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
#include <config.h>
#define r_waitpid(p,s,o) (syscall(__NR_wait4,(p),(s),(o),NULL))

/* these constant should eventually enter in sys/ptrace.h */
#ifndef PTRACE_SYSCALL_SKIPCALL
#define PTRACE_SYSCALL_SKIPCALL      0x6
#endif
#ifndef PTRACE_SYSCALL_SKIPEXIT
#define PTRACE_SYSCALL_SKIPEXIT      0x2
#endif


/* test thread code. This thread is started only to test 
 * which features are provided by the linux kernel */
static int child(void *arg)
{
	int *featurep=arg;
	int p[2]={-1,-1};
	if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0){
		perror("ptrace test_ptracemulti");
	}
	kill(getpid(), SIGSTOP);
	getpid();
	/* if it reaches this point in 1 stop it means that
	 *    * PTRACE_SYSCALL_SKIPEXIT works */
	*featurep=PTRACE_SYSCALL_SKIPEXIT;
	pipe(p);
	/* if after a PTRACE_SYSCALL_SKIPCALL p[0] is already <0 
	 *    * pipe has been really skipped */
	if (p[0] < 0)
		*featurep=PTRACE_SYSCALL_SKIPCALL;
	/* pipe's fds do not need clean up, they'll die with this thread */
	/* final stop the thread will be killed here*/
	getpid();
	return 0;
}

/* kernel feature test:
 * exit value =1 means that there is ptrace multi support
 * vm_mask is the mask of PTRACE_SYSVM supported features 
 * and sysvm_tag is the SYSVM ptrace option tag*/
unsigned int test_ptracemulti(unsigned int *vm_mask, unsigned int *sysvm_tag) {
  int pid, status, rv;
  static char stack[1024];

	*vm_mask=0;
	if((pid = clone(child, &stack[1020], SIGCHLD | CLONE_VM, vm_mask)) < 0){
		perror("clone");
		return 0;
	}
	if((pid = r_waitpid(pid, &status, WUNTRACED)) < 0){
		perror("Waiting for stop");
		return 0;
	}

	/* restart and wait for the next syscall (getpid)*/
	rv=ptrace(PTRACE_SYSCALL, pid, 0, 0);
	if(waitpid(pid, &status, WUNTRACED) < 0)
		goto out;
	/* try to skip the exit call */
	rv=ptrace(PTRACE_SYSCALL, pid, PTRACE_SYSCALL_SKIPEXIT, 0);
	if (rv < 0)
		goto out;
	/* wait for the next stop */
	if(waitpid(pid, &status, WUNTRACED) < 0)
		goto out;
	/* if feature is already 0 it means that this is the exit call,
	 * and it has not been skipped, otherwise this is the
	 * entry call for the system call "pipe" */
	if (*vm_mask<PTRACE_SYSCALL_SKIPEXIT)
		goto out;
	/* restart (pipe) and and try to skip the entire call */
	rv=ptrace(PTRACE_SYSCALL, pid, PTRACE_SYSCALL_SKIPCALL, 0);
	if(waitpid(pid, &status, WUNTRACED) < 0)
		return 0;
out:
	/*deprecated backward compatibility with SYS_VM */
	if (*vm_mask == 0) {
		errno=0;
		*vm_mask=ptrace(PTRACE_OLDSYSVM, pid, PTRACE_VM_TEST, 0);
		if (errno != 0) {
			*vm_mask=0;
			*sysvm_tag=0;
		} else
			*sysvm_tag=PTRACE_OLDSYSVM;
	} else
		*sysvm_tag=PTRACE_SYSCALL;
	if (ptrace(PTRACE_MULTI, pid, stack, 0) < 0) 
		rv=0;
	else
		rv=1;
	fprint2("MULTI=%d\n",rv);
  ptrace(PTRACE_KILL,pid,0,0);
  if((pid = r_waitpid(pid, &status, WUNTRACED)) < 0){
	  perror("Waiting for stop");
	  return 0;
  }
  return rv;
}
