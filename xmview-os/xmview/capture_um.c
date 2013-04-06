/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   capture_um.c : capture and divert system calls
 *   
 *   Copyright 2005-2012 Renzo Davoli University of Bologna - Italy
 *   Modified 2005 Mattia Belletti, Ludovico Gardenghi, Andrea Gasparini
 *   Modified 2006 Renzo Davoli
 *
 *   Some code has been inherited from strace
 *   Copyright (c) 1991, 1992 Paul Kranenburg <pk@cs.few.eur.nl>
 *   Copyright (c) 1993 Branko Lankester <branko@hacktic.nl>
 *   Copyright (c) 1993, 1994, 1995, 1996 Rick Sladkey <jrs@world.std.com>
 *   Copyright (c) 1996-1999 Wichert Akkerman <wichert@cistron.nl>
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
#include <assert.h>
#include <stdio.h>
#include <signal.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <stdarg.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <asm/ptrace.h>
#include <asm/unistd.h>
#include <sched.h>
#include <limits.h>
#include <assert.h>
#include <config.h>
#include "capture_nested.h"

#include "defs.h"
#include "utils.h"
#include "gdebug.h"
#include "capture_um.h"

#ifdef GDEBUG_ENABLED
#include "syscallnames.h"
#endif

#ifdef _UM_PTRACE
#define PT_M_OK(pc) (PT_VM_OK && PT_TRACED(pc) == NULL)
#define ptrace_hook_in(A,pc) ((ptraceemu && PT_TRACED(pc)) ? ptrace_hook_in((A),(pc)) : 0)
#define ptrace_hook_event(A,pc) ((ptraceemu && PT_TRACED(pc)) ? ptrace_hook_event((A),(pc)) : 0)
#define ptrace_hook_out(A,pc) (ptraceemu ? ptrace_hook_out((A),(pc)) : 0)
#define ptrace_hook_sysout(pc) ((ptraceemu && PT_TRACED(pc)) ? ptrace_hook_sysout(pc) : 0)
#else
#define PT_M_OK(pc) PT_VM_OK
#endif

#define PCBSIZE 16
#define PCBSTEP 16
#ifdef _UMPIDMAP
static unsigned short *umpidmap;
#endif

#ifdef _UM_PTRACE
#define UMPTRACEOPT (PTRACE_O_TRACESYSGOOD|PTRACE_O_TRACEFORK|PTRACE_O_TRACEVFORK|PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC|PTRACE_O_TRACEVFORKDONE|PTRACE_O_TRACEEXIT)
#else
#define UMPTRACEOPT (PTRACE_O_TRACESYSGOOD|PTRACE_O_TRACEFORK|PTRACE_O_TRACEVFORK|PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC)
#endif


pthread_key_t pcb_key=0; /* key to grab the current thread pcb */

sfun native_syscall=syscall;

/* debugging output, (bypass pure_libc when loaded) */
int vprintk(const char *fmt, va_list ap) {
	char *s;
	int rv=0;
	int level=PRINTK_STANDARD_LEVEL;
	if (fmt[0] == '<' && fmt[1] != 0 && fmt[2] == '>') {
		/*level*/
		switch (fmt[1]) {
			case '0' ... '7':
				level=fmt[1] - '0';
				fmt+=3;
				break;
		}
	}
	if (level <= printk_current_level) {
		rv=vasprintf(&s, fmt, ap);
		if (rv>0)
			rv=r_write(2,s,strlen(s));
		free(s);
	}
	return rv;
}

int printk(const char *fmt, ...) {
	int rv;
	va_list ap;
	va_start(ap,fmt);
	rv=vprintk(fmt,ap);
	va_end(ap);
	return rv;
}

static struct pcb **pcbtab;           /* capture_um pcb table */
int nprocs = 0;                       /* number of active processes */
static int pcbtabsize;                /* actual size of the pcb table */
static int pcbtabfree=-1;                /* actual size of the pcb table */

divfun scdtab[_UM_NR_syscalls];                 /* upcalls */
unsigned char scdnarg[_UM_NR_syscalls];	/*nargs 0x83 is OPEN */

/* linux has a single call for all the socket calls 
 * in several architecture (i386, ppc), socket calls are standard
 * system calls in others (x86_64) */
#if __NR_socketcall != __NR_doesnotexist
divfun sockcdtab[19];                 /* upcalls */
static char socketcallnargs[] = {
	0,
	3, /* sys_socket(2)    */
	3, /* sys_bind(2)      */
	3, /* sys_connect(2)   */
	2, /* sys_listen(2)    */
	3, /* sys_accept(2)    */
	3, /* sys_getsockname(2)   */
	3, /* sys_getpeername(2)   */
	4, /* sys_socketpair(2)    */
	4, /* sys_send(2)      */
	4, /* sys_recv(2)      */
	6, /* sys_sendto(2)    */
	6, /* sys_recvfrom(2)    */
	2, /* sys_shutdown(2)    */
	5, /* sys_setsockopt(2)    */
	5, /* sys_getsockopt(2)    */
	3, /* sys_sendmsg(2)   */
	3, /* sys_recvmsg(2)   */
	4  /* sys_msocket new call for multiple stack access */
};
#endif

/* umview have to exit with the exit code of the first child: here we remember
 * what the first child was, and save its exit value */
pid_t first_child_pid;
int first_child_exit_status = -1;

/* just an interface to a hidden value */
int pcbtablesize(void)
{
	return pcbtabsize;
}

/* the "current process" info gets stored as key specific data of the thread */
struct pcb *get_pcb()
{
	return pthread_getspecific(pcb_key);
}

void set_pcb(void *new)
{
	pthread_setspecific(pcb_key,new);
}

/* pcb allocator, it resizes the data structure when needed */
static struct pcb *newpcb (int pid)
{
	register int i,j;
	struct pcb *pcb;

	if (pcbtabfree < 0) {
		/* we enlarge the size, from pcbtabsize to pcbtabsize+PCBSTEP; to do this, we
		 * reallocate the newtab to increase its size; then we need
		 * PCBSTEP more pointers; so we allocate an array of struct pcb of size
		 * PCBSTEP, and the new pointers now points to that. It's
		 * a bit difficult to understand - graphically:
		 *
		 * newtab:
		 * +---------------------------------------------------------------+
		 * |01234567|89abfdef|......      |                                |
		 * +---------------------------------------------------------------+
		 *   |       |             |                         |
		 *   V       V             V                         V
		 * first    second       third                     fourth
		 * calloc   calloc       calloc                    calloc
		 *  of        of           of                        of
		 * newpcbs  newpcbs      newpcbs                   newpcbs
		 *
		 * Messy it can be, this way pointers to pcbs still remain valid after
		 * a reallocation.
		 */
		struct pcb **newtab = (struct pcb **)
			realloc(pcbtab, (pcbtabsize+PCBSTEP) * sizeof pcbtab[0]);
		struct pcb *newpcbs = (struct pcb *) calloc(PCBSTEP, sizeof *newpcbs); 
		if (newtab == NULL || newpcbs == NULL) {
			if (newtab != NULL)
				free(newtab);
			return NULL;
		}
		for (j = pcbtabsize; j < pcbtabsize+PCBSTEP; ++j) {
			newtab[j] = &newpcbs[j - pcbtabsize];
			newtab[j]->umpid = j+1;
		}
		newtab[pcbtabsize+PCBSTEP-1]->umpid=-1;
		pcbtabfree = pcbtabsize;
		pcbtabsize += PCBSTEP;
		pcbtab = newtab;
	}
	i=pcbtabfree;
	pcb=pcbtab[i];
	pcbtabfree=pcb->umpid;
	pcb->pid=pid;
	pcb->umpid=i+1; // umpid==0 is reserved for umview itself
	pcb->flags = PCB_INUSE;
	pcb->sysscno = NOSC;
	pcb->pp = NULL;
#ifdef _UMPIDMAP
	if (umpidmap)
		umpidmap[pid]=pcb->umpid;
#endif
	nprocs++;
	return pcb;
}

static void freepcb(struct pcb *pc)
{
	int index=pc->umpid-1;
#ifdef _UMPIDMAP
	if (umpidmap)
		umpidmap[pc->pid]=0;
#endif
	pc->umpid=pcbtabfree;
	pcbtabfree=index;
}

/* this is an iterator on the pcb table */
void forallpcbdo(voidfun f,void *arg)
{
	register int i;
	for (i = 0; i < pcbtabsize; i++) {
		struct pcb *pc = pcbtab[i];
		if (pc->flags & PCB_INUSE)
		{
			GDEBUG(8, "calling @%p with arg %p on pid %d", f, arg, pc->pid);
			f(pc,arg);
			GDEBUG(8, "returning from call");
		}
	}
}

/* pid 2 pcb conversion (by linear search) */
struct pcb *pid2pcb(int pid)
{
	register int i;
#ifdef _UMPIDMAP
	if (umpidmap) {
		i = umpidmap[pid] - 1;
		if (i < 0)
			return NULL;
		else
			return pcbtab[i];
	} else
#endif
	{
		for (i = 0; i < pcbtabsize; i++) {
			struct pcb *pc = pcbtab[i];
			if (pc->pid == pid && pc->flags & PCB_INUSE)
				return pc;
		}
		return NULL;
	}
}

/* orphan processes must NULL-ify their parent process pointer */
static void _cut_pp(struct pcb *pc, struct pcb *delpc)
{
	if (pc->pp == delpc)
		pc->pp = NULL;
}

/* pcb deallocator */
static void droppcb(struct pcb *pc,int status)
{
	/* the last process descriptor should stay "alive" for
	 * the termination of all modules */
	/* otherwise the "nesting" mechanism misunderstands
	 * the pcb by a npcb */
	/* XXX rd235 20090805: it seems not a problem any more
		 in the new version. deleted for dup delproc notication for proc #1 */
#ifdef _PROC_MEM_TEST
	if (pc->memfd >= 0)
		close(pc->memfd);
#endif
	nprocs--;
	forallpcbdo(_cut_pp,pc);
	pcb_destructor(pc,status,0);
	pc->flags = 0; /*NOT PCB_INUSE */;
	freepcb(pc);
}

/* initial PCB table allocation */
static void allocatepcbtab(int flags)
{
	struct pcb *pc;
	int i;

	/* Allocate the initial pcbtab.  */
	/* look at newpcb for some explanations about the structure */
	pcbtabsize = PCBSIZE;
	/* allocation of pointers */
	pcbtab = (struct pcb **) malloc (pcbtabsize * sizeof pcbtab[0]);
	/* allocation of PCBs */
	pc = (struct pcb *) calloc (pcbtabsize, sizeof *pcbtab[0]);
	/* each pointer points to the corresponding PCB */
	for (i = 0; i < PCBSIZE; i++) {
		pcbtab[i] = &pc[i];
		pcbtab[i]->umpid = i+1;
	}
	pcbtab[PCBSIZE-1]->umpid=-1;
	pcbtabfree=0;
#ifdef _UMPIDMAP
	if (flags & CAPTURE_USEPIDMAP) {
		int fd;
		fd=open("/proc/sys/kernel/pid_max",O_RDONLY);
		if (fd) {
			char buf[128];
			if (read(fd,buf,128) > 0) {
				int npids=atoi(buf);
				umpidmap=calloc(npids, sizeof(*umpidmap));
			}
		}
	}
#endif
}

static int handle_new_proc(int pid, struct pcb *pp, int flags)
{
	struct pcb *oldpc,*pc;

	if ((oldpc=pc=pid2pcb(pid)) == NULL && (pc = newpcb(pid))== NULL) {
		printk("[pcb table full]\n");
		if(r_ptrace(PTRACE_KILL, pid, 0, 0) < 0){
			GPERROR(0, "KILL");
			exit(1);
		}
	}
	if (pp != NULL) {
		//		GDEBUG(2, "handle_new_proc(pid=%d,pp=%d) -- pc->pid: %d oldpc=%d pc=%d",pid,pp,pc->pid,oldpc,pc);
		//printk("handle_new_proc(pid=%d,pp=%d)\n",pid,pp->pid);
		pc->pp = pp;
#ifdef _PROC_MEM_TEST
		if (!has_ptrace_multi) {
			char *memfile;
			asprintf(&memfile,"/proc/%d/mem",pc->pid);
			pc->memfd=r_open(memfile,O_RDWR,0);
			free(memfile);
		} else
			pc->memfd= -1;
#endif
		pc->signum=0;
		pcb_constructor(pc,flags,0);
		if (oldpc != NULL) {
			if(r_ptrace(PTRACE_SYSCALL, pid, 0, 0) < 0){
				GPERROR(0, "continuing");
				exit(1);
			}
			pc->saved_regs=NULL;
		} 
	}
	return 0;
}

#ifdef FAKESIGSTOP
int fakesigstopcont(struct pcb *pc)
{
	long kpid=getargn(0,pc);
	long ksig=getargn(1,pc);
	struct pcb *kpc;

	if ((kpc=pid2pcb(kpid)) != NULL && ksig == SIGCONT &&
			(kpc->flags & PCB_FAKESTOP))
	{
		GDEBUG(1, "FAKECONT %d",kpid);
		kpc->flags &= ~PCB_FAKESTOP;
		if(r_ptrace(PTRACE_SYSCALL, kpid, 0, 0) < 0){
			GPERROR(0, "continuing");
			exit(1);
		}
		return SC_FAKE;
	}
	return STD_BEHAVIOR;
}
#endif

#ifdef _UM_PTRACE
static pid_t tracing_wait(int *status, struct pcb **pc)
{
	int pid;
	pid = ptrace_hook_out(status, pc);
	if (pid == 0) {
		while (1) {
			pid = r_waitpid(-1, status, WUNTRACED | __WALL | WNOHANG);
			//printk("WAITPID %d %x\n",pid,*status);
			if (pid == 0) break;
			if (pid < 0) {
				GPERROR(0, "wait");
				exit(1);
			}
			*pc=pid2pcb(pid);
			if ((*pc) != NULL) {
				(*pc)->signum = 0;
				if (ptrace_hook_in(*status, *pc) == 0)
					break;
			} else
				break;
		}
	}
	return pid;
}
#else
static inline pid_t tracing_wait(int *status, struct pcb **pc)
{
	int pid;
	pid = r_waitpid(-1, status, WUNTRACED | __WALL | WNOHANG);
	if (pid > 0) {
		 *pc=pid2pcb(pid);
		 if ((*pc) != NULL) (*pc)->signum=0;
		 return pid;
	}
	else if (pid == 0) 
		return 0;
	else /* (pid < 0) */ {
		GPERROR(0, "wait");
		exit(1);
	}
}
#endif

/* Tracer core, executed any time an event occurs*/
void tracehand()
{
	int pid, status, scno=0;
	struct pcb *pc;

	while(nprocs>0){
		/* get the id of the signalling process */

		pid = tracing_wait(&status, &pc);
		//printk("%d: tracing_wait %d %x\n",getpid(),pid,status);
		/* This is a safe exit if there are no more events to process */
		if (pid==0) return;
		if (pc == NULL) {
			/* race condition, new procs can be faster than parents*/
			if(WIFSTOPPED(status) && (WSTOPSIG(status) == SIGSTOP)) {
				/* create the descriptor, block the process
				 * until the parent complete the pcb */
				//printk("RACE CONDITION %d\n",pid);
				handle_new_proc(pid,NULL,0);
				continue;
			}
			/* error case */
			GDEBUG(0, "signal from unknown pid %d: killed",pid);
			if(r_ptrace(PTRACE_KILL, pid, 0, 0) < 0){
				GPERROR(0, "KILL");
			}
			continue;
		}
		//printk("PC %p\n",pc);

		/* set the pcb of the signalling (current) process as a
		 * thread private data */
		pthread_setspecific(pcb_key,pc);

		if (WIFSTOPPED(status)) {
			int stopsig=WSTOPSIG(status);
			if(stopsig == (0x80 | SIGTRAP)){
				long saved_regs[VIEWOS_FRAME_SIZE];
				pc->saved_regs=saved_regs;
				if ( getregs(pc) < 0 ){
					GPERROR(0, "saving register");
					exit(1);
				}
				//printregs(pc);
				scno=getscno(pc);
				/* execve does not return */
				if (
#if __NR_socketcall != __NR_doesnotexist
						pc->sockaddr == 0 && 
#endif
						pc->sysscno == __NR_execve && 
						scno != __NR_execve && 
						(pc->behavior != SC_FAKE || scno != __NR_getpid)){
					pc->sysscno = NOSC;
				}
				/* sigreturn and rt_sigreturn give random "OUT" values, maybe 0.
				 * this is a workaroud */
#if defined(__x86_64__) //sigreturn and signal aren't defineed in amd64
				if (pc->sysscno == __NR_rt_sigreturn )
					pc->sysscno = NOSC;
#else
				if (
						/* x86_64 has not the single socketcall */
#if __NR_socketcall != __NR_doesnotexist
						pc->sockaddr == 0 && 
#endif
						(pc->sysscno == __NR_rt_sigreturn || pc->sysscno == __NR_sigreturn)) 
					pc->sysscno = NOSC;
				/*0 is READ for x86_84*/
				else if (scno == 0) {
					if (pc->sysscno == __NR_execve)
						pc->sysscno = NOSC;
				}
#endif
				else if (scno >= _UM_NR_syscalls) {
				}

				else if (pc->sysscno == NOSC) /* PRE syscall tracing event (IN)*/
				{
					divfun fun;
					GDEBUG(FRD | BYL | 3, "--> pid %d syscall %d (%s) @ %p", pid, scno, SYSCALLNAME(scno), getpc(pc));
					//printk("--> pid %d syscall %d (%s) @ %p\n", pid, scno, SYSCALLNAME(scno), getpc(pc));
					pc->sysscno = scno;
					switch (scdnarg[scno]) {
						case 0x6:
							pc->sysargs[5]=getargn(5,pc);
						case 0x5:
							pc->sysargs[4]=getargn(4,pc);
						case 0x4:
							pc->sysargs[3]=getargn(3,pc);
						case 0x83:
						case 0x3:
							pc->sysargs[2]=getargn(2,pc);
						case 0x2:
							pc->sysargs[1]=getargn(1,pc);
						case 0x1:
							pc->sysargs[0]=getargn(0,pc);
					}
#if __NR_socketcall != __NR_doesnotexist
					if (scno==__NR_socketcall) {
						//printk("socketcall %d %x\n",pc->sysargs[0],pc->sysargs[1]);
						pc->sysscno=pc->sysargs[0];
						pc->sockaddr=pc->sysargs[1];
						umoven(pc,pc->sockaddr,
								socketcallnargs[pc->sysscno] * sizeof(long), pc->sysargs);
						fun=sockcdtab[pc->sysscno];
					} else {
						pc->sockaddr=0;
						fun=scdtab[pc->sysscno];
					}
#else
					fun=scdtab[pc->sysscno];
#endif
					if (fun != NULL)
						pc->behavior=fun(pc->sysscno,IN,pc);
					else
						pc->behavior=STD_BEHAVIOR;
#ifdef FAKESIGSTOP
					if (scno == __NR_kill && pc->behavior == STD_BEHAVIOR)
						pc->behavior=fakesigstopcont(pc);
#endif
					if (pc->behavior & SC_SKIP_CALL) {
						if (PT_M_OK(pc)) { /* kernel supports System call skip PTRACE_SYSVM */
							if ((fun(scno,OUT,pc) & SC_SUSPENDED)==0)
								pc->sysscno=NOSC;
						} else {
							/* fake syscall with getpid if the kernel does not support
							 * syscall shortcuts */
							putscno(__NR_getpid,pc);
						}
					} else
					{
						if (pc->behavior & SC_SAVEREGS) {
							/* in case the call has been changed, count the 
							 * args for the new call */
							switch (scdnarg[getscno(pc)]) {
								case 0x83:
									if ((pc->sysargs[1] & O_ACCMODE) != O_RDONLY)
										putargn(2,pc->sysargs[2],pc);
									putargn(1,pc->sysargs[1],pc);
									putargn(0,pc->sysargs[0],pc);
									break;
								case 0x6:
									putargn(5,pc->sysargs[5],pc);
								case 0x5:
									putargn(4,pc->sysargs[4],pc);
								case 0x4:
									putargn(3,pc->sysargs[3],pc);
								case 0x3:
									putargn(2,pc->sysargs[2],pc);
								case 0x2:
									putargn(1,pc->sysargs[1],pc);
								case 0x1:
									putargn(0,pc->sysargs[0],pc);
							}
						}
					}
				} else { /* POST syscall management (OUT phase) */
					divfun fun;
					GDEBUG(FYL | BRD | 3, "<-- pid %d syscall %d (%s) @ %p", pid, scno, SYSCALLNAME(scno), getpc(pc));
					//printk("<-- pid %d syscall %d (%s) @ %p\n", pid, scno, SYSCALLNAME(scno), getpc(pc));
					//printk("OUT\n");
					/* It is just for the sake of correctness, this test could be
					 * safely eliminated  to increase the performance*/
					if ((pc->behavior == SC_FAKE && scno != __NR_getpid) && 
#if __NR_socketcall != __NR_doesnotexist
							(scno != __NR_socketcall && pc->sockaddr == 0) &&
#endif
							scno != pc->sysscno)
						GDEBUG(0, "error FAKE != %s",SYSCALLNAME(scno));
#if __NR_socketcall != __NR_doesnotexist
					if (pc->sockaddr == 0) 
						fun=scdtab[pc->sysscno];
					else 
						fun=sockcdtab[pc->sysscno];
#else
					fun=scdtab[pc->sysscno];
#endif
					if (fun != NULL &&
							(pc->behavior == SC_FAKE ||
							 pc->behavior == SC_CALLONXIT ||
							 pc->behavior == SC_TRACEONLY)) {
						pc->behavior = fun(pc->sysscno,OUT,pc);
						if ((pc->behavior & SC_SUSPENDED) == 0)
							pc->sysscno=NOSC;
						else
							pc->behavior=SC_SUSPOUT;
					} else {
						pc->behavior = STD_BEHAVIOR;
						pc->sysscno=NOSC;
					}
				} // end if scno==NOSC (OUT)
				/* resume the caller ONLY IF the syscall is not blocking */
				/* setregs is a macro that resume the execution, too */
				if ((pc->behavior & SC_SUSPENDED) == 0) {
					if ((pc->behavior & SC_SAVEREGS)) {
						if (PT_M_OK(pc)) {
							/*printk("SC %s %d\n",SYSCALLNAME(scno),pc->behavior);*/
							if(setregs(pc,PTRACE_SYSVM, (pc->behavior & SC_VM_MASK),pc->signum) == -1)
								GPERROR(0, "setregs");
							if(pc->behavior & PTRACE_VM_SKIPEXIT)
								pc->sysscno=NOSC; 
						} else {
#ifdef _UM_PTRACE
							if (setregs(pc,
										(ptrace_hook_sysout(pc))?0:PTRACE_SYSCALL, 0, pc->signum) < 0)
								GPERROR(0, "setregs");
#else
							if (setregs(pc,PTRACE_SYSCALL, 0, pc->signum) < 0)
								GPERROR(0, "setregs");
#endif
						}
					} else /* register not modified */
					{
						//printk ("RESTART\n");
						if (PT_M_OK(pc)) {
							if (r_ptrace(PTRACE_SYSVM,pc->pid,pc->behavior & SC_VM_MASK,pc->signum) < 0)
								GPERROR(0, "restart");
							if(pc->behavior & PTRACE_VM_SKIPEXIT)
								pc->sysscno=NOSC; 
						}else {
#ifdef _UM_PTRACE
							if (ptrace_hook_sysout(pc) == 0)
#endif
							{
								if (r_ptrace(PTRACE_SYSCALL,pc->pid,0,pc->signum) < 0)
									GPERROR(0, "restart");
							}
						}
					}
					pc->saved_regs=NULL;
				} else {
					pc->saved_regs=malloc(sizeof(saved_regs));
					memcpy(pc->saved_regs,saved_regs,sizeof(saved_regs));
				}

			} else
			if(stopsig == SIGTRAP) {
				pid_t newpid=0;
#ifdef _UM_PTRACE
				int followflag = ptrace_follow(status,pc) ? CLONE_PTRACE : 0;
#else
				int followflag = 0;
#endif
				long saved_regs[VIEWOS_FRAME_SIZE];
				pc->saved_regs=saved_regs;
				if ( getregs(pc) < 0 ){
					GPERROR(0, "saving register");
					printk("%d\n",pid);
					exit(1);
				}

				switch (status >> 16) {
					case PTRACE_EVENT_FORK:
					case PTRACE_EVENT_VFORK:
						r_ptrace(PTRACE_GETEVENTMSG, pid, NULL, (long) &newpid);
						// printk("pid %d FORK pid %d %d %d\n", pid, newpid,followflag,pc->sysscno);
						/* Kernel BUG: clone calls PTRACE_EVENT_FORK!*/
						if (pc->sysscno == __NR_clone)
							handle_new_proc(newpid,pc,getargn(0,pc) | followflag);
						else
							handle_new_proc(newpid,pc,SIGCHLD | followflag);
						break;
					case PTRACE_EVENT_CLONE:
						r_ptrace(PTRACE_GETEVENTMSG, pid, NULL, (long) &newpid);
						// printk("pid %d CLONE pid %d %x %d\n", pid, newpid,getargn(0,pc),followflag);
						handle_new_proc(newpid,pc,getargn(0,pc) | followflag);
						break;
#ifdef _UM_PTRACE
					case PTRACE_O_TRACEEXEC:
					case PTRACE_O_TRACEVFORKDONE:
					case PTRACE_O_TRACEEXIT:
						r_ptrace(PTRACE_GETEVENTMSG, pid, NULL, (long) &newpid);
						break;
#endif
				}
#ifdef _UM_PTRACE
				if (newpid == 0 || ptrace_hook_event(status,pc) == 0)
					r_ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
#else
				r_ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
#endif
				pc->saved_regs=NULL;
				continue;
			}

			/* Abend and signal management */
			else {
				long saved_regs[VIEWOS_FRAME_SIZE];
				pc->saved_regs=saved_regs;
				GDEBUG(3, "%d: stopped sig=%d",pid,(stopsig));
				if(stopsig == SIGSEGV)
				{
					if(getregs(pc) == -1)
						GDEBUG(3, "[err]");
					GDEBUG(3, "%d: stopped sig=SIGSEGV @ %p",
							pc->pid, getpc(pc));
				}
				/*if (!sigishandled(pc,  stopsig)) {
				// also progenie, but for now 
				//r_ptrace(PTRACE_KILL,pid,0,0);
				//printk("KILLED %d %d\n", pid,pc->pid);
				}*/
#ifdef FAKESIGSTOP
				if (stopsig == SIGTSTP && pc->pp != NULL) {
					pc->flags |= PCB_FAKESTOP;
					GDEBUG(1, "KILL 28 %d",pc->pp->pid);
					//SIGSTOP -> FAKE SIGWINCH
					kill(pc->pp->pid,28);
				} else
#endif
				{
					/* forward signals to the process */
					/* bugfix. Sometimes fake SIGSTOP get sent to processes.
						 SIGSTOP is used by ptrace here */
					if (stopsig == SIGSTOP)
						stopsig=0;
					if(r_ptrace(PTRACE_SYSCALL, pid, 0, stopsig) < 0){
						GPERROR(0, "continuing");
						/////printk("XXXcontinuing %d\n",pid);
						exit(1);
					}
				}
				pc->saved_regs=NULL;
			} 
		}
		else if(WIFSIGNALED(status)) {
			GDEBUG(3, "%d: signaled %d",pid,WTERMSIG(status));
			/* process killed by a signal */
			// printk("%d: signaled %d \n",pid,WTERMSIG(status));
			droppcb(pc,status);
		}
		/* process termination management */
		else if(WIFEXITED(status)) {
			// printk("%d: exited\n",pid);
			/* the process has terminated */
			droppcb(pc,status);
			/* if it was the "init" process (first child), save its exit status,
			 * since it is also _our_ exit status! */
			if(first_child_pid == pc->pid)
				first_child_exit_status = WEXITSTATUS(status);
		}
		else GDEBUG(1, "wait failed - pid = %d, status = %d", pid, status);
	}
}

/* pc can be resumed: there is data to unblock (maybe) its system call */
void sc_resume(struct pcb *pc)
{
	/* int pid=pc->pid; */
	//printk("RESUME %d\n",pc->pid);
	int scno=pc->sysscno;
	int inout=pc->behavior-SC_SUSPENDED;
	int signum=0;
	divfun fun;
	/* set the current process */
	pthread_setspecific(pcb_key,pc);
#if __NR_socketcall != __NR_doesnotexist
	if (pc->sockaddr == 0)
		fun=scdtab[pc->sysscno];
	else
		fun=sockcdtab[pc->sysscno];
#else
	fun=scdtab[scno];
#endif
	/* try again to execute the mgmt function */
	if (fun != NULL)
		pc->behavior=fun(scno,inout,pc);
	else
		pc->behavior=STD_BEHAVIOR;
	if (inout==IN) { /* resumed in IN phase */
		if (pc->behavior == SC_FAKE) {
			if (PT_M_OK(pc)) { /* in case PTRACE_SYSVM supports syscall skipping */
				if (inout==IN && (fun(scno,OUT,pc) & SC_SUSPENDED)==0)
					pc->sysscno=NOSC;
			} else
				putscno(__NR_getpid,pc);
		} else {
			if (pc->behavior & SC_SAVEREGS) {
				/* in case the call has been changed, count the 
				 * args for the new call */
				switch (scdnarg[getscno(pc)]) {
					case 0x83:
						if ((pc->sysargs[1] & O_ACCMODE) != O_RDONLY)
							putargn(2,pc->sysargs[2],pc);
						putargn(1,pc->sysargs[1],pc);
						putargn(0,pc->sysargs[0],pc);
						break;
					case 0x6:
						putargn(5,pc->sysargs[5],pc);
					case 0x5:
						putargn(4,pc->sysargs[4],pc);
					case 0x4:
						putargn(3,pc->sysargs[3],pc);
					case 0x3:
						putargn(2,pc->sysargs[2],pc);
					case 0x2:
						putargn(1,pc->sysargs[1],pc);
					case 0x1:
						putargn(0,pc->sysargs[0],pc);
				}
			}
		}
	} else { /* inout == OUT */
		if ((pc->behavior & SC_SUSPENDED) == 0)
			pc->sysscno=NOSC;
		else
			pc->behavior = SC_SUSPOUT;
		signum=pc->signum;
	}
	//printk("RESTARTED %d %d\n",pc->pid,pc->behavior);
	/* restore registers and restart ONLY IF the call is not already blocking */
	if ((pc->behavior & SC_SUSPENDED) == 0) {
		if (PT_M_OK(pc)) {
			if(setregs(pc,PTRACE_SYSVM,pc->behavior,signum) == -1)
				GPERROR(0, "setregs");
			if(pc->behavior & PTRACE_VM_SKIPEXIT)
				pc->sysscno=NOSC;
		} else {
#ifdef _UM_PTRACE
			if (setregs(pc,
						(ptrace_hook_sysout(pc))?0:PTRACE_SYSCALL,0,signum) == -1)
				GPERROR(0, "setregs");
#else
			if (setregs(pc,PTRACE_SYSCALL,0,signum) == -1)
				GPERROR(0, "setregs");
#endif
		}
		free(pc->saved_regs);
		pc->saved_regs=0;
	}
}

void wake_null(int s)
{
}

static void setsigaction(void)
{
	struct sigaction sa;
	sigset_t blockchild; 

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_IGN;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	r_sigaction(SIGTTOU, &sa, NULL);
	r_sigaction(SIGTTIN, &sa, NULL);
	r_sigaction(SIGHUP, &sa, NULL);
	r_sigaction(SIGINT, &sa, NULL);
	r_sigaction(SIGQUIT, &sa, NULL);
	r_sigaction(SIGPIPE, &sa, NULL);
	r_sigaction(SIGTERM, &sa, NULL);
	////sa.sa_handler = SIG_DFL;
	// SIGCHLD: syscall hadling is interruptable
	//sigaddset(&sa.sa_mask,SIGCHLD);
	// fillset: syscall handling is not interruptable
	sigfillset(&sa.sa_mask);
	/* 
	 * The signal handler is no longer the whole tracehand()
	 * but a smaller function whose only duty is to
	 * wake up the select() in main().
	 * With ppoll there is no need for pipe: in this latter
	 * case SIGCHLD gets blocked. SIGCHLD will unblock ppoll
	 */
	sigemptyset(&blockchild);
	sigaddset(&blockchild,SIGCHLD);
	r_sigprocmask(SIG_BLOCK,&blockchild,NULL);
	sa.sa_handler = wake_null;
	r_sigaction(SIGCHLD, &sa, NULL);
}

/* destructor: the pcb element is flagged as free */
static void vir_pcb_free(void *arg)
{
	struct pcb *pc=arg;
	if (pc->flags & PCB_ALLOCATED) {
		pcb_destructor(pc,0,1);
		free(arg);
	}
}

int capture_attach(struct pcb *pc,pid_t pid)
{
	handle_new_proc(pid,pc,0);
	if (r_ptrace(PTRACE_ATTACH,pid,0,0) < 0)
		return -errno;
	else {
		int status;
		if(r_waitpid(pid, &status, WUNTRACED) >= 0) {
			r_ptrace(PTRACE_SETOPTIONS, pid, 0, UMPTRACEOPT);
			if (r_ptrace(PTRACE_SYSCALL, pid, 0, 0) < 0)
				GPERROR(0, "restarting attached");
			return 0;
		} else
			return -errno;
	}
}

void capture_execrc(const char *path,const char *argv1)
{
	if (access(path,X_OK)==0) {
		int pid;
		int status;

		switch (pid=fork()) {
			case -1: exit (2);
			case 0: execl(path,path,argv1,(char *)0);
							exit (2);
			default: waitpid(pid,&status,0);
							 if (!WIFEXITED(status))
								 exit (2);
		}
	}
}

/* main capture startup */
int capture_main(char **argv, char *rc, int flags)
{
	int status;
#if __NR_socketcall != __NR_doesnotexist
	scdnarg[__NR_socketcall]=2;
#endif
	allocatepcbtab(flags);
	switch (first_child_pid=r_fork()) {
		case -1:
			GPERROR(0, "strace: fork");
			exit(1);
			break;
		case 0:
			{
				sigset_t unblockall;
				sigemptyset(&unblockall);
				r_sigprocmask(SIG_SETMASK,&unblockall,NULL);
			}
			unsetenv("LD_PRELOAD");
			/* try to set process priority back to standard prio (effective only when 
			 * umview runs in setuid mode), useless call elsewhere */
			r_setpriority(PRIO_PROCESS,0,0);
			if(r_ptrace(PTRACE_TRACEME, 0, 0, 0) < 0){
				GPERROR(0, "ptrace");
				exit(1);
			}
			r_kill(getpid(),SIGSTOP);
			capture_execrc("/etc/viewosrc",(char *)0);
			if (rc != NULL && *rc != 0)
				capture_execrc(rc,(char *)0);
			/* maybe it is better to use execvp instead of r_execvp.
			 * the former permits to load the startup executable through 
			 * a (preloaded) module */
			execvp(argv[0], argv);
			GPERROR(0, "strace: exec");
			_exit(1);
		default:
			/* UMVIEW TRACER startup */
			/* create the thread key */
			pthread_key_create(&pcb_key,vir_pcb_free);
			/* init the nested syscall capturing */
			capture_nested_init();
			/* create (by hand) the first process' pcb */
			handle_new_proc(first_child_pid,pcbtab[0],0);
			/* set the pcb_key for this process */
			pthread_setspecific(pcb_key,pcbtab[0]);
			if(r_waitpid(first_child_pid, &status, WUNTRACED) < 0){
				GPERROR(0, "Waiting for stop");
				//printk("B errno %d getpid %d\n",errno,getpid());
				exit(1);
			}
			/* set up the signal management */
			setsigaction();
			r_ptrace(PTRACE_SETOPTIONS, first_child_pid, 0, UMPTRACEOPT);
			/* okay, the first process can start (traced) */
			if(r_ptrace(PTRACE_SYSCALL, first_child_pid, 0, 0) < 0){
				GPERROR(0, "continuing");
				//printk("A getpid %d\n",getpid());
				exit(1);
			}
	}
	return 0;
}

/* vim: set ts=2 shiftwidth=2: */
