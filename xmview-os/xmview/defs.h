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
#ifndef _DEFS_H
#define _DEFS_H
#include <sys/syscall.h>
#include <unistd.h>
#include <stdlib.h>
#include <endian.h>
#include <stdarg.h>
#include <gdebug.h>
#ifdef _VIEWOS_UM
#	include "ptrace2.h"
#endif
#include "nrsyscalls.h"
#include <sys/ptrace.h>
#include <sys/utsname.h>
#include <asm/ptrace.h>

#define umNULL ((long) NULL)
#undef SNDRCVMSGUNIFY

#ifdef _VIEWOS_UM
#	define EUMWOULDBLOCK 1024

#	if defined(__powerpc__) //setregs/getresg for ppc
#		define FRAME_SIZE 13
#	elif defined(__x86_64__) // asm-x86_64 define it as 168 [offset in bytes] ! 
#		define VIEWOS_FRAME_SIZE 28
#	endif

#	ifndef VIEWOS_FRAME_SIZE
#		define VIEWOS_FRAME_SIZE FRAME_SIZE
#	endif
#endif

#include "pcb.h"
#ifdef GDEBUG_ENABLED
#include <syscallnames.h>
#endif
// #define FAKESIGSTOP

#ifdef _VIEWOS_KM
#	define sysargs	event.args
#	define sockargs event.args
#	define sockaddr event.addr
#	define sysscno event.scno
#	define getscno(PC) ( (PC)->event.scno )
#	define putscno(X,PC) ( (PC)->event.scno = (X) )
#	define getrv(PC) ( (PC)->outevent.retval) 
#	define putrv(RV,PC) ( (PC)->outevent.retval = (RV) )
#	define geterrno(PC) ( (PC)->outevent.erno )
#	define puterrno(ERR,PC) ( (PC)->outevent.erno = (ERR) )
#	define getsp(PC) ((PC)->event.sp)
#	define getpc(PC) ((PC)->event.pc)
#	define putsp(RV,PC) ( (PC)->event.sp=(RV) )
#	define putpc(RV,PC) ( (PC)->event.ps=(RV) )
#endif

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
#define r_poll(f,n,t) (native_syscall(__NR_poll,(f),(n),(t)))
#define r_ppoll(f,n,t,s,l) (native_syscall(__NR_ppoll,(f),(n),(t),(s),(l)))
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
#ifdef __NR_fcntl64
#define r_fcntl64(f,c,a) (native_syscall(__NR_fcntl64,(f),(c),(a)))
#endif
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
#define r_getresuid(r,e,s) (native_syscall(__NR_getresuid,(r),(e),(s)))
#define r_getresgid(r,e,s) (native_syscall(__NR_getresgid,(r),(e),(s)))
#if 0
#define r_sigsuspend(m) (native_syscall(__NR_sigsuspend,(m)))
#define r_sigaction(s,a,o) (native_syscall(__NR_sigaction,(s),(a),(o)))
#define r_sigprocmask(h,s,o) (native_syscall(__NR_sigprocmask,(h),(s),(o)))
#endif
#if 1
/* rd 20070818 There were these lines in the code instead of the 
 * "bypass lpurelibc" standard r_ call.
 * who inserted them and why?*/
/* Don't know who and when and why, but it does not work if you change this. */
#define r_sigsuspend(m) (sigsuspend(m))
#define r_sigaction(s,a,o) (sigaction((s),(a),(o)))
#define r_sigprocmask(h,s,o) (sigprocmask((h),(s),(o)))
#endif
#define r_ioctl(...) (native_syscall(__NR_ioctl,__VA_ARGS__))
#define r_fork() (native_syscall(__NR_fork))
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
#ifdef __NR_getgroups32
#define r_getgroups(s,g) (native_syscall(__NR_getgroups32,(s),(g)))
#define r_setgroups(s,g) (native_syscall(__NR_setgroups32,(s),(g)))
#else
#define r_getgroups(s,g) (native_syscall(__NR_getgroups,(s),(g)))
#define r_setgroups(s,g) (native_syscall(__NR_setgroups,(s),(g)))
#endif

/* debugging functions */
extern int printk(const char *fmt, ...);
extern int vprintk(const char *fmt, va_list ap);

/* verbosity/quietness */
extern unsigned int quiet;

#ifdef _VIEWOS_UM
	/* flags on the underlying kernel support */
	extern unsigned int has_ptrace_multi;
	extern unsigned int ptrace_vm_mask;
/* skipexit and some kind of syscall must be implemented */
# define PT_VM_OK ((ptrace_vm_mask & PTRACE_VM_SKIPOK) > PTRACE_VM_SKIPEXIT)
	extern unsigned int ptrace_sysvm_tag;
# define PTRACE_SYSVM (ptrace_sysvm_tag)
#endif

#define WORDLEN sizeof(int *)
#define WORDALIGN(X) (((X) + WORDLEN) & ~(WORDLEN-1))

#define MAX_SOCKET_NAME 1024
#define MAX_SOCKOPT_LEN 4096
#define MAX_SOCK_CONTROLLEN (1<<16) /*64K*/
#define _LARGE_ALLOCA_PROTECTION
#ifdef _LARGE_ALLOCA_PROTECTION
#define lalloca(L) ({ void *m; if (__builtin_expect(((L)>>16),0)) \
		{ if ((m=malloc(L))==NULL) \
		{ pc->retval= -1; pc->erno=ENOMEM; return SC_FAKE; } \
	 	} \
		else m=alloca(L); m; })
#define lnalloca(L) ({ void *m; if (__builtin_expect(((L)>>16),0)) \
		{ if ((m=malloc(L))==NULL) \
		{ errno=ENOMEM; return -1; } \
		} \
		else m=alloca(L); m; })
#define lfree(B,L) ({if (__builtin_expect(((L)>>16),0)) free(B); })
#define lfree(B,L) ({if (__builtin_expect(((L)>>16),0)) free(B); })
#else
#define lalloca(L) alloca(L)
#define lnalloca(L) alloca(L)
#define lfree(B,L)
#endif

/* there is a memory alignment problem in these architectures */
/* long long syscall args are 2 regs aligned */
#if (defined(__powerpc__) && !defined(__powerpc64__)) || (defined (MIPS) && !defined(__mips64))
#define PALIGN 1
#else
#define PALIGN 0
#endif

#if 0
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
#endif

void forallpcbdo(voidfun f,void *arg);

#ifdef FAKESIGSTOP
#define PCB_FAKEWAITSTOP 0x4000
#define PCB_FAKESTOP 0x8000
#endif

typedef	int (*divfun)(int sc_number,int inout,struct pcb *ppcb);

//#####################################
// SYSCALL STRANGE STUFF
// define __NR_doesnotexist all non-existent syscall
// in this way the sequence in scmap is preserved through
// different architectures
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

#ifndef __NR_pselect6
#define __NR_pselect6 __NR_doesnotexist
#endif
#ifndef __NR_ppoll
#define __NR_ppoll __NR_doesnotexist
#endif
#ifndef __NR_gethostname
#define __NR_gethostname __NR_doesnotexist
#endif
#ifndef __NR_getdomainname
#define __NR_getdomainname __NR_doesnotexist
#endif

/* UNAME HISTORY */
#ifndef __NR_oldolduname
#define __NR_oldolduname __NR_uname
#endif
#ifndef __NR_olduname
#define __NR_olduname __NR_uname
#endif

#ifndef __NR_dup3
#define __NR_dup3 __NR_doesnotexist
#endif

#ifndef __NR_openat
#define __NR_openat __NR_doesnotexist
#define __NR_mkdirat __NR_doesnotexist
#define __NR_mknodat __NR_doesnotexist
#define __NR_fchownat __NR_doesnotexist
#define __NR_futimesat  __NR_doesnotexist
#endif

#ifndef __NR_utimensat
#define __NR_utimensat __NR_doesnotexist
#endif

#ifndef __NR_getxattr
#define __NR_getxattr __NR_doesnotexist
#define __NR_lgetxattr __NR_doesnotexist
#define __NR_fgetxattr __NR_doesnotexist
#define __NR_setxattr __NR_doesnotexist
#define __NR_lsetxattr __NR_doesnotexist
#define __NR_fsetxattr __NR_doesnotexist
#define __NR_listxattr __NR_doesnotexist
#define __NR_llistxattr __NR_doesnotexist
#define __NR_flistxattr __NR_doesnotexist
#define __NR_removexattr __NR_doesnotexist
#define __NR_lremovexattr __NR_doesnotexist
#define __NR_fremovexattr __NR_doesnotexist
#endif

#ifndef __NR_preadv
#define __NR_preadv __NR_doesnotexist
#endif
#ifndef __NR_pwritev
#define __NR_pwritev __NR_doesnotexist
#endif

//#####################################


// part of defs that's strictly architecture dependent
#if defined _VIEWOS_UM
#	if defined(__i386__) //getregs/setregs and so on, for ia32
#		include "defs_i386_um.h"
#	elif defined(__powerpc__) //setregs/getresg and so on, for ppc
#		include "defs_ppc_um.h"
#	elif defined(__x86_64__) //setregs/getresg and so on, for ppc
#		include "defs_x86_64_um.h"
#	else
#		error Unsupported HW Architecure
#	endif /* architecture */
#elif defined _VIEWOS_KM
#	if defined(__i386__) //getregs/setregs and so on, for ia32
#		include "defs_i386_km.h"
#	elif defined(__powerpc__) //setregs/getresg and so on, for ppc
#		include "defs_ppc_km.h"
#	elif defined(__x86_64__) //setregs/getresg and so on, for ppc
#		include "defs_x86_64_km.h"
#	else
#		error Unsupported HW Architecure
#	endif /* architecture */
#else
#	error Unspecified mode (UM/KM)
#endif

/* XXX should be moved from here! */
struct viewinfo {
	struct utsname uname;
	pid_t	serverid;
	viewid_t viewid;
	char viewname[_UTSNAME_LENGTH];
};

#define __NR_UM_SERVICE 1
#define ADD_SERVICE 0
#define DEL_SERVICE 1
#define MOV_SERVICE 2
#define LIST_SERVICE 3
#define NAME_SERVICE 4
#define LOCK_SERVICE 5
#define RECURSIVE_VIEWOS   0x100
#define VIEWOS_GETINFO     0x101
#define VIEWOS_SETVIEWNAME 0x102
#define VIEWOS_KILLALL     0x103
#define VIEWOS_ATTACH      0x104
#define VIEWOS_FSALIAS     0x105

#endif // _DEFS_H
