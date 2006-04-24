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
#ifndef _DEFS_I386
#define _DEFS_I386

#define getregs(PC)  ( ptrace(PTRACE_GETREGS,(PC)->pid,NULL,(void*) (PC)->saved_regs), (PC)->regs_modified=0 )

// this is coming to became unreadable... how about write a real function?
#define setregs(PC,CALL,OP) ({ (PC)->regs_modified==0 ? ptrace((CALL),(PC)->pid,(OP),0) :\
			   	(has_ptrace_multi ? ({\
			struct ptrace_multi req[] = {{PTRACE_SETREGS, 0, (void *) (PC)->saved_regs, 0},\
			{(CALL), (OP), 0, 0}};\
			ptrace(PTRACE_MULTI,(PC)->pid,req,2); }\
			) : (\
				{int rv;\
				rv=ptrace(PTRACE_SETREGS,(PC)->pid,NULL,(void*) (PC)->saved_regs);\
				if(rv== 0) rv=ptrace((CALL),(PC)->pid,(OP),0);\
				(PC)->regs_modified=0;\
				rv;}\
							                            ) ); \
				})


//printregs: current state of the working copy of registers
//#define printregs(PC)
#define printregs(PC) \
	 GDEBUG(3, "saved_regs:eax:%x\torig_eax:%x\n\tebx:%x\tecx:%x\n\tedx:%x\tesi:%x",\
			 (PC)->saved_regs[EAX],(PC)->saved_regs[ORIG_EAX],\
			 (PC)->saved_regs[EBX],(PC)->saved_regs[ECX],\
			 (PC)->saved_regs[EDX],(PC)->saved_regs[ESI])


#define getscno(PC) ( (PC)->saved_regs[ORIG_EAX] )
#define putscno(X,PC) ( (PC)->saved_regs[ORIG_EAX]=(X) , (PC)->regs_modified=1 )
#define getargn(N,PC) ( (PC)->saved_regs[(N)] )
#define getargp(PC) ((PC)->saved_regs)
#define putargn(N,X,PC) ( (PC)->saved_regs[N]=(X)  , (PC)->regs_modified=1 )
#define getrv(PC) ({ int eax; \
		eax = (PC)->saved_regs[EAX];\
		(eax<0 && -eax < MAXERR)? -1 : eax; })
#define putrv(RV,PC) ( (PC)->saved_regs[EAX]=(RV),(PC)->regs_modified=1 ,0 )
#define puterrno(ERR,PC) ( ((ERR)!=0 && (PC)->retval==-1)?(PC)->saved_regs[EAX]=-(ERR) , (PC)->regs_modified=1  : 0 )
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

#define MAXSC (NR_syscalls)
#define MAXERR 4096

//#define MAXSC 256 // already defined in line 98
#define BASEUSC		4096
#define MAXUSC		0
#define SCREMAP(I)	(I)

extern short _i386_sc_remap[];
#define cdtab(X) (((X) < BASEUSC) ? scdtab[(X)] : scdtab[_i386_sc_remap[(X)-BASEUSC]])
#define setcdtab(X,Y) (((X) < BASEUSC) ? (scdtab[(X)] = (Y)) : (scdtab[_i386_sc_remap[(X)-BASEUSC]] = (Y)))

#ifdef PIVOTING_ENABLED
/**
 * %0 = num syscall
 * %1..%6 = up to 6 arguments of syscall (doesn't matter about unused ones)
 */
#define ASM_SYSCALL \
	"mov  %0,    %%eax\n\t" \
	"mov  %1,    %%ebx\n\t" \
	"mov  %2,    %%ecx\n\t" \
	"mov  %3,    %%edx\n\t" \
	"mov  %4,    %%esi\n\t" \
	"mov  %5,    %%edi\n\t" \
	"mov  %6,    %%ebp\n\t" \
	"int  $0x80\n\t"
#endif

#endif // _DEFS_I386
