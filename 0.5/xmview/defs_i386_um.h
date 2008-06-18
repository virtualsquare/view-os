/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   defs.h: interfaces to system call arguments (architecture dependant)
 *           needed for capture_um
 *   
 *   Copyright 2005 Renzo Davoli University of Bologna - Italy
 *   Modified 2005 Mattia Belletti, Ludovico Gardenghi, Andrea Gasparini
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
#ifndef _DEFS_I386
#define _DEFS_I386
/* libc keeps some critical values inside registers */
#define LIBC_VFORK_DIRTY_TRICKS
#define _KERNEL_NSIG   64
#define _KERNEL_SIGSET_SIZE _KERNEL_NSIG/8

static inline long getregs(struct pcb *pc)
{
	return ptrace(PTRACE_GETREGS,pc->pid,NULL,(void*) pc->saved_regs);
}

static inline long setregs(struct pcb *pc, enum __ptrace_request call,
		long op, long sig)
{
	if (has_ptrace_multi) {
		struct ptrace_multi req[] = {
			{PTRACE_SETREGS, 0, (void *) pc->saved_regs, 0}, 
			{call,op,(void *)sig,0}};
		return ptrace(PTRACE_MULTI,pc->pid,req,2);
	} else {
		int rv;
		rv=ptrace(PTRACE_SETREGS,pc->pid,NULL,(void*) pc->saved_regs);
		if(rv== 0) rv=ptrace(call,pc->pid,op,sig);
		return rv;
	}
}

//printregs: current state of the working copy of registers
static inline void printregs(struct pcb *pc)
{
	GDEBUG(3, "saved_regs:eax:%x\torig_eax:%x\n\tebx:%x\tecx:%x\n\tedx:%x\tesi:%x",
			pc->saved_regs[EAX],pc->saved_regs[ORIG_EAX],
			pc->saved_regs[EBX],pc->saved_regs[ECX],
			pc->saved_regs[EDX],pc->saved_regs[ESI]);
}

#define getscno(PC) ( (PC)->saved_regs[ORIG_EAX] )
#define putscno(X,PC) ( (PC)->saved_regs[ORIG_EAX]=(X) )
#define getargn(N,PC) ( (PC)->saved_regs[(N)] )
#define getargp(PC) ((long*)(PC)->saved_regs)
#define putargn(N,X,PC) ( (PC)->saved_regs[N]=(X) )
#define getrv(PC) ({ int eax; \
		eax = (PC)->saved_regs[EAX];\
		(eax<0 && -eax < MAXERR)? -1 : eax; })
#define putrv(RV,PC) ( (PC)->saved_regs[EAX]=(RV) )
#define puterrno(ERR,PC) ( ((ERR)!=0 && (PC)->retval==-1)?(PC)->saved_regs[EAX]=-(ERR) : 0 )
/*
#define putexit(RV,ERR,PC) \
	do { \
		ptrace(PTRACE_POKEUSER, ((PC)->pid), 4 * PT_R3, (RV)); \
		ptrace(PTRACE_POKEUSER, ((PC)->pid), 4 * ORIG_EAX, (ERR)); \
	} while (0)
	*/
#define getsp(PC) (PC)->saved_regs[UESP]
#define getpc(PC) (PC)->saved_regs[EIP]
#define putsp(RV,PC) ( (PC)->saved_regs[UESP]=(RV) )
#define putpc(RV,PC) ( (PC)->saved_regs[EIP]=(RV) )

#define LITTLEENDIAN
#define LONG_LONG(_l,_h) \
    ((long long)((unsigned long long)(unsigned)(_l) | ((unsigned long long)(_h)<<32)))

#define MAXERR 4096

#define __NR_setpgrp __NR_doesnotexist
#endif
