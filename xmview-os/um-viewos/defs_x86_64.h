/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   defs.h: interfaces to system call arguments (architecture dependant)
 *           needed for capture_sc
 *   
 *   Copyright 2005 Renzo Davoli University of Bologna - Italy
 *   Modified 2005 Mattia Belletti, Ludovico Gardenghi, Andrea Gasparini
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

#ifndef _DEFS_X86_64
#define _DEFS_X86_64

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
#define MY_RDI 0 //112
#define MY_RSI 1 //104
#define MY_RDX 2 //96
#define MY_RCX 3 //88
#define MY_RAX 4 //80
#define MY_R8  5 //72
#define MY_R9  6 //64
#define MY_R10 7 // 56  
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
// arguments in x86_64 are saved in order from RDI to R8
// orig_rax contains syscall number 
// and rax (i think...) contains return value and errno
// for stack pointer -> RSP
// for instruction pointer -> RIP
				
#define getregs(PC) ({ long temp[FRAME_SIZE]; int i = ptrace(PTRACE_GETREGS,(PC)->pid,NULL,(void*) temp);\
			(PC)->saved_regs[MY_RDI] = temp[RDI]; \
			(PC)->saved_regs[MY_RSI] = temp[RSI]; \
			(PC)->saved_regs[MY_RDX] = temp[RDX]; \
			(PC)->saved_regs[MY_RCX] = temp[RCX]; \
			(PC)->saved_regs[MY_RAX] = temp[RAX]; \
			(PC)->saved_regs[MY_R8] = temp[R8]; \
			(PC)->saved_regs[MY_R9] = temp[R9]; \
			(PC)->saved_regs[MY_R10] = temp[R10]; \
			(PC)->saved_regs[MY_R11] = temp[R11]; \
			(PC)->saved_regs[MY_RBX] = temp[RBX]; \
			(PC)->saved_regs[MY_RBP] = temp[RBP]; \
			(PC)->saved_regs[MY_R12] = temp[R12]; \
			(PC)->saved_regs[MY_R13] = temp[R13]; \
			(PC)->saved_regs[MY_R14] = temp[R14]; \
			(PC)->saved_regs[MY_R15] = temp[R15]; \
			(PC)->saved_regs[MY_ORIG_RAX] = temp[ORIG_RAX]; \
			(PC)->saved_regs[MY_RIP] = temp[RIP]; \
			(PC)->saved_regs[MY_CS] = temp[CS]; \
			(PC)->saved_regs[MY_EFLAGS] = temp[EFLAGS]; \
			(PC)->saved_regs[MY_RSP] = temp[RSP]; \
			(PC)->saved_regs[MY_SS] = temp[SS]; \
			i; \
			})
#define setregs(PC,CALL,OP) ({ long temp[FRAME_SIZE]; \
			temp[RDI] = (PC)->saved_regs[MY_RDI]; \
			temp[RSI] = (PC)->saved_regs[MY_RSI]; \
			temp[RDX] = (PC)->saved_regs[MY_RDX]; \
			temp[RCX] = (PC)->saved_regs[MY_RCX]; \
			temp[RAX] = (PC)->saved_regs[MY_RAX]; \
			temp[R8] = (PC)->saved_regs[MY_R8]; \
			temp[R9] = (PC)->saved_regs[MY_R9]; \
			temp[R10] = (PC)->saved_regs[MY_R10]; \
			temp[R11] = (PC)->saved_regs[MY_R11]; \
			temp[RBX] = (PC)->saved_regs[MY_RBX]; \
			temp[RBP] = (PC)->saved_regs[MY_RBP]; \
			temp[R12] = (PC)->saved_regs[MY_R12]; \
			temp[R13] = (PC)->saved_regs[MY_R13]; \
			temp[R14] = (PC)->saved_regs[MY_R14]; \
			temp[R15] = (PC)->saved_regs[MY_R15]; \
			temp[ORIG_RAX] = (PC)->saved_regs[MY_ORIG_RAX]; \
			temp[RIP] = (PC)->saved_regs[MY_RIP]; \
			temp[CS] = (PC)->saved_regs[MY_CS]; \
			temp[EFLAGS] = (PC)->saved_regs[MY_EFLAGS]; \
			temp[RSP] = (PC)->saved_regs[MY_RSP]; \
			temp[SS] = (PC)->saved_regs[MY_SS]; \
	(has_ptrace_multi ? ({\
			     struct ptrace_multi req[] = {{PTRACE_SETREGS, 0, (void *) temp},\
			     {(CALL), (OP), 0}};\
			     ptrace(PTRACE_MULTI,(PC)->pid,req,2); }\
			    ) : (\
				    {int rv;\
				    rv=ptrace(PTRACE_SETREGS,(PC)->pid,NULL,(void*) temp);\
					    if(rv== 0) rv=ptrace((CALL),(PC)->pid,(OP),0);\
					    rv;}\
													) );\
	})
#define getargp(PC) ((PC)->saved_regs[MY_RDI])
#define printregs(PC)  // empty for a while... :P
#define getscno(PC) ( (PC)->saved_regs[MY_ORIG_RAX] )											 
#define putscno(X,PC) ( (PC)->saved_regs[MY_ORIG_RAX]=(X) )
#define getargn(N,PC) ( (PC)->saved_regs[(N)] )
#define putargn(N,X,PC) ( (PC)->saved_regs[(N)]=(X) )
#define getrv(PC) ({ long rax; \
		rax = (PC)->saved_regs[MY_RAX];\
		(rax<0 && -rax < MAXERR)? -1 : rax; })
#define putrv(RV,PC) ( (PC)->saved_regs[MY_RAX]=(RV), 0 )
#define puterrno(ERR,PC) ( ((ERR)!=0 && (PC)->retval==-1)?(PC)->saved_regs[MY_RAX]=-(ERR) : 0 )
#define getsp(PC) ( (PC)->saved_regs[MY_RSP] )
#define getpc(PC) ( (PC)->saved_regs[MY_RIP] )
#define putsp(RV,PC) ( (PC)->saved_regs[MY_RSP]=(RV) )
#define putpc(RV,PC) ( (PC)->saved_regs[MY_RIP]=(RV) )

#define LITTLEENDIAN
#define LONG_LONG(_l,_h) \
    ((long long)((unsigned long long)(unsigned)(_l) | ((unsigned long long)(_h)<<32)))

#define MAXSC (NR_syscalls)
#define MAXERR 4096

//#define MAXSC 256 // already defined in line 98
#define BASEUSC		4096
#define MAXUSC		0
#define SCREMAP(I)	(I)

extern short _i386_sc_remap[];
#define cdtab(X) (((X) < BASEUSC) ? scdtab[(X)] : scdtab[_i386_sc_remap[(X)-BASEUSC]])
#define setcdtab(X,Y) (((X) < BASEUSC) ? (scdtab[(X)] = (Y)) : (scdtab[_i386_sc_remap[(X)-BASEUSC]] = (Y)))

// Many syscalls are redefined, renamed, or simply dismissed in x86_64
#define __NR_lstat64	__NR_lstat
#define __NR_socketcall	__NR_socket

#ifdef PIVOTING_ENABLED
#error "Still to take the ASM_SYSCALL definition for i386 and adapt it to 64bit"
#endif


#endif // _DEFS_X86_64
