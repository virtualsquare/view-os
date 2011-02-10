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
#ifndef _DEFS_PPC
#define _DEFS_PPC
#define _KERNEL_NSIG   64
#define _KERNEL_SIGSET_SIZE _KERNEL_NSIG/8

#include <errno.h>

#ifndef PT_ORIG_R3
#define PT_ORIG_R3 34
#endif

static inline long getregs(struct pcb *pc)
{
	if (has_ptrace_multi) {
		struct ptrace_multi req[] = {{PTRACE_PEEKUSER, 0, pc->saved_regs, 10},
			{PTRACE_PEEKUSER, 4*PT_NIP, &(pc->saved_regs[10]), 1},
			{PTRACE_PEEKUSER, 4*PT_ORIG_R3, &(pc->saved_regs[11]), 1},
			{PTRACE_PEEKUSER, 4*PT_CCR, &(pc->saved_regs[12]), 1}};
			errno=0;
			return ptrace(PTRACE_MULTI,pc->pid,req,4);
	} else {
		register int count;
		for(count=0;count<10;count++){
			pc->saved_regs[count]=ptrace(PTRACE_PEEKUSER,pc->pid,(void*)(4*count),0);
			if(errno!=0) break; 
		}
		pc->saved_regs[10]=ptrace(PTRACE_PEEKUSER,pc->pid,(void*)(4*PT_NIP),0);
		pc->saved_regs[11]=ptrace(PTRACE_PEEKUSER,pc->pid,(void*)(4*PT_ORIG_R3),0);
		pc->saved_regs[12]=ptrace(PTRACE_PEEKUSER,pc->pid,(void*)(4*PT_CCR),0);
		return (errno!=0)?-1:0;
	}
}

/* XXX PTRACE_MULTI ORIG_R3 returns -1 when saved */
static inline long setregs(struct pcb *pc, enum __ptrace_request call,
		    long op, long sig)
{
	if (has_ptrace_multi) { 
		struct ptrace_multi req[] = {{PTRACE_POKEUSER, 0, pc->saved_regs, 10},
			{PTRACE_POKEUSER, 4*PT_NIP, &(pc->saved_regs[10]), 1},
			{PTRACE_POKEUSER, 4*PT_CCR, &(pc->saved_regs[12]), 1},
			{call, op, (void *) sig, 0}};
		return ptrace(PTRACE_MULTI,pc->pid,req,4); 
	} else {
		int rv,count;
		for(count=0;count<10;count++){
			rv=ptrace(PTRACE_POKEUSER,pc->pid,(void*)(4*count),pc->saved_regs[count]);
			if(rv!=0)break;
		}
		if(rv==0) rv=ptrace(PTRACE_POKEUSER,pc->pid,(void*)(4*PT_NIP),pc->saved_regs[10]);
		if(rv==0) rv=ptrace(PTRACE_POKEUSER,pc->pid,(void*)(4*PT_CCR),pc->saved_regs[12]);
		if(rv==0) rv=ptrace(call,pc->pid,op,sig);
		return rv;
	}
}

#define getscno(PC) ( (PC)->saved_regs[PT_R0] )
#define putscno(X,PC) ( (PC)->saved_regs[PT_R0]=(X) )
#define getargn(N,PC) ( (PC)->saved_regs[PT_R3+(N)] )
#define getargp(PC) (&((PC)->saved_regs[PT_R3]))
#define putargn(N,X,PC) ( (PC)->saved_regs[PT_R3+(N)]=(X) )
#define getrv(PC) ( (PC)->saved_regs[12] & 0x10000000 ? -1: (PC)->saved_regs[PT_R3] )
#define putrv(RV,PC) ( (PC)->saved_regs[PT_R3]=(RV) , 0 )
#define puterrno(ERR,PC) ({ if(ERR!=0){\
				(PC)->saved_regs[12]=(PC)->saved_regs[12] | 0x10000000;\
				(PC)->saved_regs[PT_R3]=(ERR);\
				} 0;\
				})
#define puterrno0(PC)
#define getsp(PC) ( (PC)->saved_regs[PT_R1] )
#define getpc(PC) ( (PC)->saved_regs[10] )
#define putsp(SP,PC) ( (PC)->saved_regs[PT_R1]=(SP) ;
#define putpc(PCX,PC) ( (PC)->saved_regs[10]=(PCX) )

#define BIGENDIAN
#define LONG_LONG(_l,_h) \
    ((long long)((unsigned long long)(unsigned)(_h) | ((unsigned long long)(_l)<<32)))


#define __NR_setpgrp __NR_doesnotexist
#endif // _DEFS_PPC 
