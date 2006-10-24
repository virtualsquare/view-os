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
#include <endian.h>
#include <stdarg.h>
#include "ptrace2.h"
#include "nrsyscalls.h"

/* Real SysCalls ! r_ prefixed calls do not enter the nidification
 * process and go straight to the kernel */
#include<sys/syscall.h>
typedef long int (*sfun)(long int __sysno, ...);
extern sfun native_syscall;
#define r_open(p,f,m) (native_syscall(__NR_open,(p),(f),(m)))
#define r_read(f,b,c) (native_syscall(__NR_read,(f),(b),(c)))
#define r_write(f,b,c) (native_syscall(__NR_write,(f),(b),(c)))
#define r_close(f) (native_syscall(__NR_close,(f)))
#define r_getdents64(f,b,c) (native_syscall(__NR_getdents64,(f),(b),(c)))
#define r_unlink(p) (native_syscall(__NR_unlink,(p)))
#define r_dup(f) (native_syscall(__NR_dup,(f)))
#define r_dup2(f,g) (native_syscall(__NR_dup2,(f),(g)))
#ifdef __NR__newselect
#define r_select(n,r,w,e,t) (native_syscall(__NR__newselect,(n),(r),(w),(e),(t)))
#else
#define r_select(n,r,w,e,t) (native_syscall(__NR_select,(n),(r),(w),(e),(t)))
#endif
#define r_pselect6(n,r,w,e,t,m) (native_syscall(__NR_pselect6,(n),(r),(w),(e),(t),(m)))
#define r_waitpid(p,s,o) (native_syscall(__NR_wait4,(p),(s),(o),NULL))
#define r_lstat64(p,b) (native_syscall(NR64_lstat,(p),(b)))
#define r_readlink(p,b,sz) (native_syscall(__NR_readlink,(p),(b),(sz)))
#define r_fcntl(f,c,a) (native_syscall(__NR_fcntl,(f),(c),(a)))
#define r_umask(m) (native_syscall(__NR_umask,(m)))
#define r_pipe(v) (native_syscall(__NR_pipe,(v)))
#define r_access(p,m) (native_syscall(__NR_access,(p),(m)))
#define r_setpriority(w,p,o) (native_syscall(__NR_setpriority,(w),(p),(o)))
#define r_setuid(u) (native_syscall(__NR_setuid,(u)))
#define r_getuid() (native_syscall(__NR_getuid))
#define r_getpid() (native_syscall(__NR_getpid))
/* be careful getcwd syscall does not allocate the string for path=NULL */
#define r_getcwd(p,l) (native_syscall(__NR_getcwd,(p),(l)))
#define r_mkdir(d,m) (native_syscall(__NR_mkdir,(d),(m)))
#define r_rmdir(d) (native_syscall(__NR_rmdir,(d)))
#define r_kill(p,s) (native_syscall(__NR_kill,(p),(s)))
#define r_execve(p,a,e) (native_syscall(__NR_execve,(p),(a),(e)))
#define r_lseek(f,o,w) (native_syscall(__NR_close,(f),(o),(w)))
#ifdef __NR__llseek
#define r_llseek(f,ohi,olo,r,w) (native_syscall(__NR__llseek,(f),(ohi),(olo),(r),(w)))
#endif
#if defined(__powerpc__)
#define r_pread64(f,b,c,o1,o2) (native_syscall(__NR_pread64,(f),(b),(c),0,__LONG_LONG_PAIR((o1),(o2))))
#define r_pwrite64(f,b,c,o1,o2) (native_syscall(__NR_pwrite64,(f),(b),(c),0,__LONG_LONG_PAIR((o1),(o2))))
#else
#define r_pread64(f,b,c,o1,o2) (native_syscall(__NR_pread64,(f),(b),(c),__LONG_LONG_PAIR((o1),(o2))))
#define r_pwrite64(f,b,c,o1,o2) (native_syscall(__NR_pwrite64,(f),(b),(c),__LONG_LONG_PAIR((o1),(o2))))
#endif

extern int fprint2(const char *fmt, ...);
extern int vfprint2(const char *fmt, va_list ap);

extern unsigned int has_ptrace_multi;
extern unsigned int ptrace_vm_mask;
#define PT_VM_OK ((ptrace_vm_mask & PTRACE_VM_SKIPOK) == PTRACE_VM_SKIPOK)
extern unsigned int ptrace_viewos_mask;
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
#elif defined(__x86_64__) // asm-x86_64 define it as 168 [offset in bytes] ! 
//#define VIEWOS_FRAME_SIZE 22
#define VIEWOS_FRAME_SIZE 28
#define NR_syscalls _UM_NR_syscalls
#endif

#ifndef VIEWOS_FRAME_SIZE
#define VIEWOS_FRAME_SIZE FRAME_SIZE
#endif

/**
 * The type of a callback function. Look pivoting.h.
 */

struct pcb;
enum phase { PHASE_IN, PHASE_OUT };
typedef void pivoting_callback(int scno, enum phase p, struct pcb *pc,
		int counter);

// struct containing operation for pcb management
typedef int (*pcbfun)();

/* Process Control Block */
struct pcb {
	short flags;
	unsigned short umpid;
	int pid;                /* Process Id of this entry */
#ifdef _PROC_MEM_TEST
	int memfd; /* if !has_ptrace_multi, open /proc/PID/mem */
#endif
	struct pcb *pp;         /* Parent Process */
	long scno;              /* System call number */
	short behavior;
	unsigned int erno;
	long retval;
	unsigned long arg0;
	unsigned long arg1;
	unsigned long arg2;

	long saved_regs[VIEWOS_FRAME_SIZE];
	// if regs aren't modified (because of a real syscall...), we can 
	// avoid calling PTRACE_SETREGS
	char regs_modified;
	void *data;
};

typedef void (*voidfun)();
void forallpcbdo(voidfun f,void *arg);

#define NOSC -1
#define PCB_INUSE 0x1 /* INUSE=0: unused element ready for allocation. 
												 never = 0 for running processes pcb,
												 INUSE=0 is a flag for pcb managed outside capture_sc (capture_nested) */
#define PCB_ALLOCATED 0x2
											/* Dynamically allocated pcb, to be freed.
											 * never used inside capture_sc */
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


//#####################################
// SYSCALL STRANGE STUFF
#define __NR_doesnotexist -1
#if defined(__x86_64__)
#define NR64_stat	__NR_stat
#define NR64_lstat	__NR_lstat
#define NR64_fstat	__NR_fstat
#else
#define NR64_stat	__NR_stat64
#define NR64_lstat	__NR_lstat64
#define NR64_fstat	__NR_fstat64
#endif


//#####################################


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

#define __NR_UM_SERVICE 1
#define ADD_SERVICE 0
#define DEL_SERVICE 1
#define MOV_SERVICE 2
#define LIST_SERVICE 3
#define NAME_SERVICE 4
#define LOCK_SERVICE 5
#define RECURSIVE_UMVIEW 0x100

extern divfun scdtab[MAXSC];
extern t_pcb_constr pcb_constr;
extern t_pcb_destr pcb_destr;

#endif // _DEFS_H
