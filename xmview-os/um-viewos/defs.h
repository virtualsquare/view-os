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
#ifndef _DEFS_H
#define _DEFS_H
#include <sys/syscall.h>
#include <unistd.h>
#include "ptrace2.h"

extern int has_ptrace_multi;
#include <sys/ptrace.h>
#include <asm/ptrace.h>

#ifdef _MALLOC_DEBUG
#define free(X) ({ printf("MDBG-FREE %x %s %d\n",(X),__FILE__,__LINE__); \
		free(X); })
#define malloc(X) ({ void *x; x=malloc(X); \
		printf("MDBG-MALLOC %x %s %d\n",x,__FILE__,__LINE__); \
		x; })
#define strdup(X) ({ void *x; x=strdup(X); \
		printf("MDBG-STRDUP %x %s %d\n",x,__FILE__,__LINE__); \
		x; })
#define realloc(Y,X) ({ void *x,*old; \
		old=(Y);\
		x=realloc(old,(X)); \
		printf("MDBG-REALLOC %x->%x %s %d\n",old,x,__FILE__,__LINE__); \
		x; })
#endif

#if defined(__powerpc__) //setregs/getresg for ppc
#define FRAME_SIZE 13
#endif

/**
 * The type of a callback function. Look pivoting.h.
 */
struct pcb;
enum phase { PHASE_IN, PHASE_OUT };
typedef void pivoting_callback(int scno, enum phase p, struct pcb *pc,
		int counter);
/* Process Control Block */
struct pcb {
	short flags;
	int pid;                /* Process Id of this entry */
	struct pcb *pp;         /* Parent Process */
	long scno;              /* System call number */
	short behavior;
	unsigned int erno;
	int retval;
	unsigned int arg0;
	unsigned int arg1;
	unsigned int arg2;

	long saved_regs[FRAME_SIZE];
#ifdef PIVOTING_ENABLED
	/* address of the first instruction executed by the process (needed to
	 * know where to start for injecting code) - it's an address in the
	 * ptraced process address space, not ours! */
	void *first_instruction_address;
	/* saved code: when we inject some syscall code, we save the
	 * overwritten code in here */
	size_t saved_code_length;
	char *saved_code;
	/* the pivoting counter: give a look at pivoting_inject */
	int counter;
	/* the callback function */
	pivoting_callback *piv_callback;
	/* saved registers before pivoting - if you want register modification
	 * to propagate after pivoting, save them here */
	long saved_regs_pivoting[FRAME_SIZE];
#endif
	void *data;
};

typedef void (*voidfun)();
void forallpcbdo(voidfun f,void *arg);
int capture_main(char **argv);


#define NOSC -1
#define PCB_INUSE 0x1
#define PCB_BPTSET 0x2
#ifdef PIVOTING_ENABLED
#define PCB_INPIVOTING 0x100
#endif
#define PCB_SOFTSUSP 0x2000
#define PCB_FAKEWAITSTOP 0x4000
#define PCB_FAKESTOP 0x8000

typedef	int (*divfun)(int sc_number,int inout,struct pcb *ppcb);
typedef	void (*t_pcb_constr)(struct pcb *ppcb, int flags);
typedef	void (*t_pcb_destr)(struct pcb *ppcb);
#define IN 0
#define OUT 1

#define STD_BEHAVIOR 0
#define SC_FAKE 1
#define SC_CALLONXIT 2
#define SC_SOFTSUSP 3
#define SC_SUSPENDED 4
#define SC_SUSPIN 4     /* SUSPENDED + IN  */
#define SC_SUSPOUT 5    /* SUSPENDED + OUT */

//getregs/setregs: inline-function for getting/setting registers of traced process
#define pusher setregs
#define popper getregs
//printregs: current state of the working copy of registers
#if defined(__i386__) //getregs/setregs for ia32
#define getregs(PC) ptrace(PTRACE_GETREGS,(PC)->pid,NULL,(void*) (PC)->saved_regs)
#define setregs(PC) ptrace(PTRACE_SETREGS,(PC)->pid,NULL,(void*) (PC)->saved_regs)
//#define printregs(PC)
#define printregs(PC) \
	 GDEBUG(3, "saved_regs:eax:%x\torig_eax:%x\n\tebx:%x\tecx:%x\n\tedx:%x\tesi:%x",\
			 (PC)->saved_regs[EAX],(PC)->saved_regs[ORIG_EAX],\
			 (PC)->saved_regs[EBX],(PC)->saved_regs[ECX],\
			 (PC)->saved_regs[EDX],(PC)->saved_regs[ESI])


#define getscno(PC) ( (PC)->saved_regs[ORIG_EAX] )
#define putscno(X,PC) ( (PC)->saved_regs[ORIG_EAX]=(X) )
#define getargn(N,PC) ( (PC)->saved_regs[(N)] )
#define putargn(N,X,PC) ( (PC)->saved_regs[N]=(X) )
#define getarg0orig(PC) ( (PC)->saved_regs[0] )
#define putarg0orig(N,PC) ( (PC)->saved_regs[0]=(N) )
#define getrv(PC) ({ int eax; \
		eax = (PC)->saved_regs[EAX];\
		(eax<0 && -eax < MAXERR)? -1 : eax; })
#define putrv(RV,PC) ( (PC)->saved_regs[EAX]=(RV), 0 )
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
#elif defined(__powerpc__) //setregs/getresg for ppc
#if 0
#define getregs_ppc(PC) ({int count;for(count=0;count<FRAME_SIZE;count++){\
			(PC)->saved_regs[count]=ptrace(PTRACE_PEEKUSER,(PC)->pid,(void*)(4*count),0);\
			if(errno!=0) break;}\
			(errno!=0)? -1:0;\
			})
#define setregs_ppc(PC) ({int i,count;for(count=0;count<FRAME_SIZE;count++){\
			i=ptrace(PTRACE_POKEUSER,(PC)->pid,(void*)(4*count),(PC)->saved_regs[count]);\
			if(i!=0) break;}; (i!=0)? -1 : 0 ;})
#endif

#define getregs(PC) (has_ptrace_multi ? ({\
		struct ptrace_multi req[] = {{PTRACE_PEEKUSER, 0, (PC)->saved_regs, 10},\
		{PTRACE_PEEKUSER, 4*PT_NIP, &((PC)->saved_regs[10]), 1},\
		{PTRACE_PEEKUSER, 4*PT_ORIG_R3, &((PC)->saved_regs[11]), 1},\
		{PTRACE_PEEKUSER, 4*PT_CCR, &((PC)->saved_regs[12]), 1}};\
			errno=0;\
			ptrace(PTRACE_MULTI,(PC)->pid,req,4);}\
			) : (\
		{int count;for(count=0;count<10;count++){\
				(PC)->saved_regs[count]=ptrace(PTRACE_PEEKUSER,(PC)->pid,(void*)(4*count),0);\
				if(errno!=0)break;}\
				(PC)->saved_regs[10]=ptrace(PTRACE_PEEKUSER,(PC)->pid,(void*)(4*PT_NIP),0);\
				(PC)->saved_regs[11]=ptrace(PTRACE_PEEKUSER,(PC)->pid,(void*)(4*PT_ORIG_R3),0);\
				(PC)->saved_regs[12]=ptrace(PTRACE_PEEKUSER,(PC)->pid,(void*)(4*PT_CCR),0);\
				errno!=0?-1:0;}\
		) )
/* XXX PTRACE_MULTI ORIG_R3 returns -1 when saved */
#define setregs(PC) (has_ptrace_multi ? ({\
		struct ptrace_multi req[] = {{PTRACE_POKEUSER, 0, (PC)->saved_regs, 10},\
		{PTRACE_POKEUSER, 4*PT_NIP, &((PC)->saved_regs[10]), 1},\
		{PTRACE_POKEUSER, 4*PT_CCR, &((PC)->saved_regs[12]), 1}};\
			ptrace(PTRACE_MULTI,(PC)->pid,req,3); }\
			) : (\
		{int i,count;for(count=0;count<10;count++){\
				i=ptrace(PTRACE_POKEUSER,(PC)->pid,(void*)(4*count),(PC)->saved_regs[count]);\
				if(i!=0)break;}\
				ptrace(PTRACE_POKEUSER,(PC)->pid,(void*)(4*PT_NIP),(PC)->saved_regs[10]);\
				ptrace(PTRACE_POKEUSER,(PC)->pid,(void*)(4*PT_ORIG_R3),(PC)->saved_regs[11]);\
				ptrace(PTRACE_POKEUSER,(PC)->pid,(void*)(4*PT_CCR),(PC)->saved_regs[12]);}\
		) )

#define getscno(PC) ( (PC)->saved_regs[PT_R0] )
#define putscno(X,PC) ( (PC)->saved_regs[PT_R0]=(X) )
#define getargn(N,PC) ( (PC)->saved_regs[PT_R3+(N)] )
#define putargn(N,X,PC) ( (PC)->saved_regs[PT_R3+(N)]=(X) )
#define getarg0orig(PC) ( (PC)->saved_regs[11];)
#define putarg0orig(N,PC) ( (PC)->saved_regs[11]=(N) )
#define getrv(PC) ( (PC)->saved_regs[12] & 0x10000000 ? -1: (PC)->saved_regs[PT_R3] )
#define putrv(RV,PC) ( (PC)->saved_regs[PT_R3]=(RV) , 0 )
#define puterrno(ERR,PC) ({ if(ERR!=0){\
				(PC)->saved_regs[12]=(PC)->saved_regs[12] | 0x10000000;\
				(PC)->saved_regs[PT_R3]=(ERR);\
				}else 0;0;\
				})
#define getsp(PC) ( (PC)->saved_regs[PT_R1] )
#define getpc(PC) ( (PC)->saved_regs[10] )
#define putsp(SP,PC) ( (PC)->saved_regs[PT_R1]=(SP) ;
#define putpc(PCX,PC) ( (PC)->saved_regs[10]=(PCX) )

#endif


/*                                  I386 *********************************/
#if defined (__i386__)

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

/*                                  POWERPC *********************************/
#elif defined (__powerpc__) && !defined(__powerpc64__)
#define BIGENDIAN
#define LONG_LONG(_l,_h) \
    ((long long)((unsigned long long)(unsigned)(_h) | ((unsigned long long)(_l)<<32)))

#ifndef PT_ORIG_R3
#define PT_ORIG_R3 34
#endif

#define MAXSC (__NR_syscalls + 1)
#define BASEUSC		4096
#define MAXUSC		8
#define cdtab(X) (((X) < BASEUSC) ? scdtab[(X)] : scdutab[(X)-BASEUSC])
#define setcdtab(X,Y) (((X) < BASEUSC) ? (scdtab[(X)] = (Y)) : (scdutab[(X)-BASEUSC] = (Y)))

#ifdef PIVOTING_ENABLED
#error "Still to take the ASM_SYSCALL definition for i386 and adapt it to PowerPC"
#endif

#else
#error Unsupported HW Architecure
#endif /* architecture */

extern divfun scdtab[MAXSC];
extern divfun scdutab[MAXUSC];
extern t_pcb_constr pcb_constr;
extern t_pcb_destr pcb_destr;

#endif /* _SCTAB_H */
