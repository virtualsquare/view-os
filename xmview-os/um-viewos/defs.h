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
// nested_headers: stuff required if we compile with -DNESTING_TEST
#include "nested_headers.h"

/* Real SysCalls ! r_ prefixed calls do not enter the nidification
 * process and go straight to the kernel */
#include<sys/syscall.h>
#define r_read(f,b,c) (syscall(__NR_read,(f),(b),(c)))
#define r_write(f,b,c) (syscall(__NR_write,(f),(b),(c)))
#ifdef __NR__newselect
#define r_select(n,r,w,e,t) (syscall(__NR__newselect,(n),(r),(w),(e),(t)))
#else
#define r_select(n,r,w,e,t) (syscall(__NR_select,(n),(r),(w),(e),(t)))
#endif
#define r_waitpid(p,s,o) (syscall(__NR_waitpid,(p),(s),(o)))
#define r_lstat64(p,b) (syscall(__NR_lstat64,(p),(b)))
#define r_readlink(p,b,sz) (syscall(__NR_readlink,(p),(b),(sz)))
#define r_fcntl(f,c,a) (syscall(__NR_fcntl,(f),(c),(a)))
#define r_umask(m) (syscall(__NR_umask,(m)))
#define r_pipe(v) (syscall(__NR_pipe,(v)))
#define r_access(p,m) (syscall(__NR_access,(p),(m)))
#define r_setpriority(w,p,o) (syscall(__NR_setpriority,(w),(p),(o)))
#define r_setuid(u) (syscall(__NR_setuid,(u)))
#define r_getuid() (syscall(__NR_getuid))
#define r_getpid() (syscall(__NR_getpid))
/* be careful getcwd syscall does not allocate the string for path=NULL */
#define r_getcwd(p,l) (syscall(__NR_getcwd,(p),(l)))
#define r_mkdir(d,m) (syscall(__NR_mkdir,(d),(m)))
#define r_rmdir(d) (syscall(__NR_rmdir,(d)))

extern unsigned int has_ptrace_multi;
extern unsigned int ptrace_vm_mask;
#define PT_VM_OK ((ptrace_vm_mask & PTRACE_VM_SKIPOK) == PTRACE_VM_SKIPOK)
extern unsigned int ptrace_viewos_mask;
extern int _lwip_version;
#include <sys/ptrace.h>
#include <asm/ptrace.h>

#define WORDLEN sizeof(int *)
#define WORDALIGN(X) (((X) + WORDLEN) & ~(WORDLEN-1))

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
#elif defined(__x86_64__) // asm-x86_64 define it as 168 [offset in bytes] ! //#define VIEWOS_FRAME_SIZE 22
#define VIEWOS_FRAME_SIZE 28
#define NR_syscalls __NR_syscall_max
#elif defined(__i386__)
#define VIEWOS_FRAME_SIZE FRAME_SIZE
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
	unsigned short umpid;
	int pid;                /* Process Id of this entry */
	struct pcb *pp;         /* Parent Process */
	long scno;              /* System call number */
	short behavior;
	unsigned int erno;
	long retval;
	unsigned long arg0;
	unsigned long arg1;
	unsigned long arg2;

	long saved_regs[FRAME_SIZE];
	// if regs aren't modified (because of a real syscall...), we can 
	// avoid calling PTRACE_SETREGS
	char regs_modified;
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
#ifdef NESTING_TEST
	unsigned char	come_from_nest; //bool that tells if my syscall came from the nesting
							//system or not
	unsigned char	stop_nest;
#endif
	void *data;
};

typedef void (*voidfun)();
void forallpcbdo(voidfun f,void *arg);
int capture_main(char **argv);

#ifdef NESTING_TEST

// old stuff...
#ifndef __LIBMODCOMP // in libmodcomp.c we define this as static.
extern short int umview_inside_mod_flag;
extern struct pcb* main_umview_pcb;
extern void cancel_ld_preload(void);
#endif
//extern int nesting_level;
// come_from_nest tells if the last module has nested the last called syscall or not
// is used into wrap_in and wrap_out functions
// I think it's better use only in that scope (for comprehensibility)
#define inside_nesting(PC) ( (PC)->pid == main_umview_pcb->pid )
#define set_from_nesting() ( main_umview_pcb->come_from_nest = 1 )
#define unset_from_nesting() ( main_umview_pcb->come_from_nest = 0 )
#define get_from_nesting() (main_umview_pcb->come_from_nest)

#define set_stop_nest()	( main_umview_pcb->stop_nest=1 )
#define unset_stop_nest()	( main_umview_pcb->stop_nest=0 )
#define get_stop_nest() ( main_umview_pcb->stop_nest )
#endif

#define NOSC -1
#define PCB_INUSE 0x1
#define PCB_BPTSET 0x2
#ifdef PIVOTING_ENABLED
#define PCB_INPIVOTING 0x100
#endif
#define PCB_FAKEWAITSTOP 0x4000
#define PCB_FAKESTOP 0x8000

typedef	int (*divfun)(int sc_number,int inout,struct pcb *ppcb);
typedef	void (*t_pcb_constr)(struct pcb *ppcb, int flags, int maxtabsize);
typedef	void (*t_pcb_destr)(struct pcb *ppcb);
#define IN 0
#define OUT 1

/* constants are compatible with PTRACE_SYS_VM definitions */
#define STD_BEHAVIOR 2	/* DO_SYSCALL SKIP_EXIT */
#define SC_FAKE 3	/* SKIP_SYSCALL SKIP_EXIT */
#define SC_CALLONXIT 0  /* DO_SYSCALL DO_CALLONXIT */
#define SC_SUSPENDED 4
#define SC_SUSPIN 4     /* SUSPENDED + IN  */
#define SC_SUSPOUT 5    /* SUSPENDED + OUT */

// part of defs that's strictly architecture dependent
#if defined(__i386__) //getregs/setregs and so on, for ia32
#include "defs_i386.h"
#elif defined(__powerpc__) //setregs/getresg and so on, for ppc
#include "defs_ppc.h"
#elif defined(__x86_64__) //setregs/getresg and so on, for ppc
#include "defs_x86_64.h"
#else
#error Unsupported HW Architecure
#endif /* architecture */

extern divfun scdtab[MAXSC];
extern divfun scdutab[MAXUSC];
extern t_pcb_constr pcb_constr;
extern t_pcb_destr pcb_destr;

#endif // _DEFS_H
