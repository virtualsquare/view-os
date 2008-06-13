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

#ifndef _DEFS_X86_64
#define _DEFS_X86_64
#define _KERNEL_NSIG   64
#define _KERNEL_SIGSET_SIZE _KERNEL_NSIG/8

// asm-x86_64/ptrace.h declare this as offset in bytes (and I don't want so)
//registers as mapped in x_86_64 kernel
// syscall argument are in inverted order!!!!!! (from RDI to R11 ! )
//  ( sgrunt !! )
#define R15 0
#define R14 1 //8
#define R13 2 //16
#define R12 3 //24
#define RBP 4 //32
#define RBX 5 //40
#define R11 6 //48
#define R10 7 // 56  
#define R9 	8 //64
#define R8 	9 //72
#define RAX 10 //80
#define RCX 11 //88
#define RDX 12 //96
#define RSI 13 //104
#define RDI 14 //112
#define ORIG_RAX 15 //120       /* = ERROR */ 
#define RIP 16 //128
#define CS 17 //136
#define EFLAGS 18 //144
#define RSP 19 //152
#define SS 20 //160
#define ARGOFFSET R11
// remapped registers:
/*
 *      Register setup:
 * system call number	rax
 * +    arg 1		rdi
 * +    arg 2		rsi
 * +    arg 3		rdx
 * +    arg 4		r10
 * +    arg 5		r8
 * +    arg 6		r9
 */
#define MY_RDI 0 //112
#define MY_RSI 1 //104
#define MY_RDX 2 //96
/*
#define MY_RCX 3 //88
#define MY_RAX 4 //80
#define MY_R8  5 //72
#define MY_R9  6 //64
#define MY_R10 7 // 56  
*/
#define MY_R10 3
#define MY_R8  4
#define MY_R9  5
#define MY_RCX 6
#define MY_RAX 7
#define MY_R11 8 //48
#define MY_RBX 9 //40
#define MY_RBP 10//32
#define MY_R12 11//24
#define MY_R13 12//16
#define MY_R14 13//8
#define MY_R15 14
#define MY_ORIG_RAX 15 //120       /* = ERROR */ 
#define MY_RIP 16 //128
#define MY_CS 17 //136
#define MY_EFLAGS 18 //144
#define MY_RSP 19 //152
#define MY_SS 20 //160
#define MY_ARGOFFSET 0

#define FS_BASE 21
#define GS_BASE 22
#define DS 23
#define ES 25
#define FS 26
#define GS 27

// arguments in x86_64 are saved in order from RDI to R8
// orig_rax contains syscall number 
// and rax (i think...) contains return value and errno
// for stack pointer -> RSP
// for instruction pointer -> RIP

static inline long getregs(struct pcb *pc)
{
	long temp[VIEWOS_FRAME_SIZE];
	long rv = ptrace(PTRACE_GETREGS, pc->pid,NULL,(void*) temp);

	pc->saved_regs[MY_RDI] = temp[RDI];
	pc->saved_regs[MY_RSI] = temp[RSI];
	pc->saved_regs[MY_RDX] = temp[RDX];
	pc->saved_regs[MY_RCX] = temp[RCX];
	pc->saved_regs[MY_RAX] = temp[RAX];
	pc->saved_regs[MY_R8] = temp[R8];
	pc->saved_regs[MY_R9] = temp[R9];
	pc->saved_regs[MY_R10] = temp[R10];
	pc->saved_regs[MY_R11] = temp[R11];
	pc->saved_regs[MY_RBX] = temp[RBX];
	pc->saved_regs[MY_RBP] = temp[RBP];
	pc->saved_regs[MY_R12] = temp[R12];
	pc->saved_regs[MY_R13] = temp[R13];
	pc->saved_regs[MY_R14] = temp[R14];
	pc->saved_regs[MY_R15] = temp[R15];
	pc->saved_regs[MY_ORIG_RAX] = temp[ORIG_RAX];
	pc->saved_regs[MY_RIP] = temp[RIP];
	pc->saved_regs[MY_CS] = temp[CS];
	pc->saved_regs[MY_EFLAGS] = temp[EFLAGS];
	pc->saved_regs[MY_RSP] = temp[RSP];
	pc->saved_regs[MY_SS] = temp[SS];
	pc->saved_regs[FS_BASE] = temp[FS_BASE];
	pc->saved_regs[GS_BASE] = temp[GS_BASE];
	pc->saved_regs[DS] = temp[DS];
	pc->saved_regs[ES] = temp[ES];
	pc->saved_regs[FS] = temp[FS];
	pc->saved_regs[GS] = temp[GS];

	return rv;
}

static inline long setregs(struct pcb *pc, enum __ptrace_request call, long op, long sig)
{
	long temp[VIEWOS_FRAME_SIZE];

	temp[RDI] = pc->saved_regs[MY_RDI];
	temp[RSI] = pc->saved_regs[MY_RSI];
	temp[RDX] = pc->saved_regs[MY_RDX];
	temp[RCX] = pc->saved_regs[MY_RCX];
	temp[RAX] = pc->saved_regs[MY_RAX];
	temp[R8] = pc->saved_regs[MY_R8];
	temp[R9] = pc->saved_regs[MY_R9];
	temp[R10] = pc->saved_regs[MY_R10];
	temp[R11] = pc->saved_regs[MY_R11];
	temp[RBX] = pc->saved_regs[MY_RBX];
	temp[RBP] = pc->saved_regs[MY_RBP];
	temp[R12] = pc->saved_regs[MY_R12];
	temp[R13] = pc->saved_regs[MY_R13];
	temp[R14] = pc->saved_regs[MY_R14];
	temp[R15] = pc->saved_regs[MY_R15];
	temp[ORIG_RAX] = pc->saved_regs[MY_ORIG_RAX];
	temp[RIP] = pc->saved_regs[MY_RIP];
	temp[CS] = pc->saved_regs[MY_CS];
	temp[EFLAGS] = pc->saved_regs[MY_EFLAGS];
	temp[RSP] = pc->saved_regs[MY_RSP];
	temp[SS] = pc->saved_regs[MY_SS];
	temp[FS_BASE] = pc->saved_regs[FS_BASE];
	temp[GS_BASE] = pc->saved_regs[GS_BASE];
	temp[DS] = pc->saved_regs[DS];
	temp[ES] = pc->saved_regs[ES];
	temp[FS] = pc->saved_regs[FS];
	temp[GS] = pc->saved_regs[GS];

	if (has_ptrace_multi)
	{
		struct ptrace_multi req[] = {
			{PTRACE_SETREGS, 0, (void *) temp, 0},
			{call, op, (void*) sig, 0}};
		return ptrace(PTRACE_MULTI, pc->pid, req, 2); 
	}
	else
	{
		int rv;
		rv = ptrace(PTRACE_SETREGS, pc->pid, NULL, (void*) temp);
		if (rv == 0) 
			rv = ptrace(call, pc->pid, op, sig);
		return rv;
	}
}

#define getargp(PC) ((long*)(PC)->saved_regs[MY_RDI])
#define printregs(PC)  // empty for a while... :P
#define getscno(PC) ( (PC)->saved_regs[MY_ORIG_RAX] )											 
#define putscno(X,PC) ( (PC)->saved_regs[MY_ORIG_RAX]=(X) )
#define getargn(N,PC) ( (PC)->saved_regs[(N)] )
#define putargn(N,X,PC) ( (PC)->saved_regs[(N)]=(X) )
#define getrv(PC) ({ long rax; \
		rax = (PC)->saved_regs[MY_RAX];\
		(rax<0 && -rax < MAXERR)? -1 : rax; })
#define putrv(RV,PC) ( (PC)->saved_regs[MY_RAX]=(RV), 0 )
#define puterrno(ERR,PC) (((ERR)!=0 && (PC)->retval==-1) ? \
				(PC)->saved_regs[MY_RAX]=-((long)(ERR)) : 0 )

#define getsp(PC) ( (PC)->saved_regs[MY_RSP] )
#define getpc(PC) ( (PC)->saved_regs[MY_RIP] )
#define putsp(RV,PC) ( (PC)->saved_regs[MY_RSP]=(RV) )
#define putpc(RV,PC) ( (PC)->saved_regs[MY_RIP]=(RV) )

#define LITTLEENDIAN
#define LONG_LONG(_l,_h) \
    ((long long)((unsigned long long)(unsigned)(_l) | ((unsigned long long)(_h)<<32)))

#define MAXERR 4096

#if 0 // let's help vim autoindent  :-P
}
#endif
// amd64 syscall stuff
// TODO: think how i can solve this problem... :(
#define __NR_socketcall	__NR_doesnotexist

#define __NR__newselect __NR_doesnotexist
#define __NR_umount __NR_doesnotexist
#define __NR_stat64 __NR_doesnotexist
#define __NR_lstat64 __NR_doesnotexist
#define __NR_fstat64 __NR_doesnotexist
#undef __NR_chown32
#define __NR_chown32 __NR_doesnotexist
#undef __NR_lchown32
#define __NR_lchown32 __NR_doesnotexist
#undef __NR_fchown32
#define __NR_fchown32 __NR_doesnotexist
#define __NR_fcntl64 __NR_doesnotexist
#define __NR__llseek __NR_doesnotexist
#define __NR_truncate64 __NR_doesnotexist
#define __NR_ftruncate64 __NR_doesnotexist
#define __NR_send __NR_doesnotexist
#define __NR_recv __NR_doesnotexist
#define __NR_statfs64 __NR_doesnotexist
#define __NR_fstatfs64 __NR_doesnotexist
#define __NR_nice __NR_doesnotexist
#define __NR_mmap2 __NR_doesnotexist

/* XXX: should we find a more elegant solution? */
#define wrap_in_statfs64 NULL
#define wrap_in_fstatfs64 NULL

#define wrap_in_stat wrap_in_stat64
#define wrap_in_fstat wrap_in_fstat64

#define __NR_setpgrp __NR_doesnotexist
#endif // _DEFS_X86_64
