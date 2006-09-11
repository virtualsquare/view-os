/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   capture_sc.c : capture and divert system calls
 *   
 *   Copyright 2005 Renzo Davoli University of Bologna - Italy
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
#include "capture_nested.h"

// #define FAKESIGSTOP

#include "defs.h"
#include "utils.h"
#include "syscallnames.h"
#include "gdebug.h"


#define PCBSIZE 10

pthread_key_t pcb_key=0; /* key to grab the current thread pcb */

sfun native_syscall=syscall;

int fprint2(const char *fmt, ...) {
	char *s;
	int rv;
	va_list ap;
	va_start(ap,fmt);
	rv=vasprintf(&s, fmt, ap);
	va_end(ap);
	if (rv>0)
		rv=r_write(2,s,strlen(s));
	free(s);
	return rv;
}

int vfprint2(const char *fmt, va_list ap) {
	char *s;
	int rv;
	rv=vasprintf(&s, fmt, ap);
	va_end(ap);
	if (rv>0)
		rv=r_write(2,s,strlen(s));
	free(s);
	return rv;
}

static struct pcb **pcbtab;
int nprocs = 0;
static int pcbtabsize;

divfun scdtab[MAXSC];
t_pcb_constr pcb_constr=NULL;
t_pcb_destr pcb_destr=NULL;

/* When a SIGCHLD is received, the main select will be notified through this
 * pipe; the counter is used to notify it no more than one time. */
int tracerpipe[2];
int tracerpipecounter = 0;

/* umview have to exit with the exit code of the first child: here we remember
 * what the first child was, and save its exit value */
pid_t first_child_pid;
int first_child_exit_status = -1;

int pcbtablesize(void)
{
	return pcbtabsize;
}

struct pcb *get_pcb()
{
	return pthread_getspecific(pcb_key);
}

void set_pcb(void *new)
{
	pthread_setspecific(pcb_key,new);
}

static struct pcb *newpcb (int pid)
{
	register int i,j;
	struct pcb *pcb;

	for (i=0; 1; i++) {
		if (i==pcbtabsize) { /* expand the pcb table */
			/* we double the size, from pcbtabsize to pcbtabsize*2; to do this, we
			 * reallocate the newtab to double the size it was before; then we need
			 * pcbtabsize more pointers; so we allocate a table of pointers of size
			 * pcbtabsize, and the new pointers to pointers now points to that. It's
			 * a bit difficult to understand - graphically:
			 *
			 * newtab:
			 * +---------------------------------------------------------------+
			 * |0123|45678...|                |                                |
			 * +---------------------------------------------------------------+
			 *   |       |             |                         |
			 *   V       V             V                         V
			 * first    second       third                     fourth
			 * calloc   calloc       calloc                    calloc
			 *  of        of           of                        of
			 * newpcbs  newpcbs      newpcbs                   newpcbs
			 *
			 * Messy it can ben, this way pointers to pcbs still remain valid after
			 * a reallocation.
			 */
			struct pcb **newtab = (struct pcb **)
				realloc(pcbtab, 2 * pcbtabsize * sizeof pcbtab[0]);
			struct pcb *newpcbs = (struct pcb *) calloc(pcbtabsize, sizeof *newpcbs); 
			if (newtab == NULL || newpcbs == NULL) {
				if (newtab != NULL)
					free(newtab);
				return NULL;
			}
			for (j = pcbtabsize; j < 2 * pcbtabsize; ++j)
				newtab[j] = &newpcbs[j - pcbtabsize];
			pcbtabsize *= 2;
			pcbtab = newtab;
		}
		pcb=pcbtab[i];
		if (! (pcb->flags & PCB_INUSE)) {
			pcb->pid=pid;
			pcb->umpid=i+1; // umpid==0 is reserved for umview itself
			pcb->flags = PCB_INUSE;
			pcb->scno = NOSC;
			pcb->pp = NULL;
			pcb->data = NULL;
			nprocs++;
			return pcb;
		}
	}

	/* never reach here! */
	assert(0);
	return NULL;
}

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

//static struct pcb *
static struct pcb *
pid2pcb(int pid)
{
	register int i;
	for (i = 0; i < pcbtabsize; i++) {
		struct pcb *pc = pcbtab[i];
		if (pc->pid == pid && pc->flags & PCB_INUSE)
			return pc;
	}
	return NULL;
}

/*static void droppcb(struct pcb *pc)*/
/*{*/
/*  pc->flags = 0; |+NOT PCB_INUSE +|;*/
/*#ifdef _PROC_MEM_TEST*/
/*  if (pc->memfd >= 0)*/
/*    close(pc->memfd);*/
/*#endif*/
/*  if (pcb_destr != NULL)*/
/*    pcb_destr(pc);*/
/*  nprocs--;*/
/*}*/

static void _cut_pp(struct pcb *pc, struct pcb *delpc)
{
	if (pc->pp == delpc)
		pc->pp = NULL;
}

static void droppcb(struct pcb *pc)
{
	/* the last process descriptor should stay "alive" for
	 * the termination of all modules */
	/* otherwise the "nesting" mechanism misunderstands
	 * the pcb by a npcb */
	if (nprocs > 1)
		pc->flags = 0; /*NOT PCB_INUSE */;
#ifdef _PROC_MEM_TEST
	if (pc->memfd >= 0)
		close(pc->memfd);
#endif
	nprocs--;
	forallpcbdo(_cut_pp,pc);
	if (pcb_destr != NULL)
		pcb_destr(pc);
}

static void allocatepcbtab()
{
	struct pcb *pc;

	/* Allocate the initial pcbtab.  */
	/* look at newpcb for some explanations about the structure */
	pcbtabsize = PCBSIZE;
	pcbtab = (struct pcb **) malloc (pcbtabsize * sizeof pcbtab[0]);
	pcbtab[0] = (struct pcb *) calloc (pcbtabsize, sizeof *pcbtab[0]);
	for (pc = pcbtab[0]; pc < &pcbtab[0][pcbtabsize]; ++pc)
		pcbtab[pc - pcbtab[0]] = &pcbtab[0][pc - pcbtab[0]];
}

static int handle_new_proc(int pid, struct pcb *pp)
{
	struct pcb *oldpc,*pc;

	if ((oldpc=pc=pid2pcb(pid)) == NULL && (pc = newpcb(pid))== NULL) {
		fprintf(stderr, "[pcb table full]\n");
		if(ptrace(PTRACE_KILL, pid, 0, 0) < 0){
			GPERROR(0, "KILL");
			exit(1);
		}
	}
	if (pp != NULL) {
//		GDEBUG(2, "handle_new_proc(pid=%d,pp=%d) -- pc->pid: %d oldpc=%d pc=%d",pid,pp,pc->pid,oldpc,pc);
		if (oldpc != NULL) {
			if(ptrace(PTRACE_SYSCALL, pid, 0, SIGSTOP) < 0){
				GPERROR(0, "continuing");
				exit(1);
			}
			pc=oldpc;
		}
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
		if (pcb_constr != NULL)
			pcb_constr(pc,pp->arg2,pcbtabsize);
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
		if(ptrace(PTRACE_SYSCALL, kpid, 0, 0) < 0){
			GPERROR(0, "continuing");
			exit(1);
		}
		return SC_FAKE;
	}
	return STD_BEHAVIOR;
}
#endif

void offspring_enter(struct pcb *pc)
{
	//printf("offspring_enter:%d\n",pc->pid);
	pc->arg0=getargn(0,pc);
	pc->arg1=getargn(1,pc);
	if (pc->scno == __NR_fork || pc->scno == __NR_vfork) {
		putscno(__NR_clone,pc);
		putargn(0,CLONE_PTRACE|SIGCHLD, pc);
		putargn(1,0, pc);
		pc->arg2=SIGCHLD;
	}
	else if (pc->scno == __NR_clone) {
		putargn(0,pc->arg0 | CLONE_PTRACE, pc);
		pc->arg2=pc->arg0;
	}
}

void offspring_exit(struct pcb *pc)
{
	putargn(0,pc->arg0,pc);
	putargn(1,pc->arg1,pc);
}

void tracehand()
{
	int pid, status, scno=0;
	struct pcb *pc;

	while(nprocs>0){
		if((pid =  r_waitpid(-1, &status, WUNTRACED | __WALL | WNOHANG)) < 0)
		{
			GPERROR(0, "wait");
			exit(1);
		}

		// This is a safe exit if there are spurious chars in the pipe
		if (pid==0) return;
		if(WIFSTOPPED(status) && (WSTOPSIG(status) == SIGSTOP)) {
			/* race condition, new procs can be faster than parents*/
			if (pid2pcb(pid) == NULL) {
				/* create the descriptor, block the process
				 * until the parent complete the pcb */
				handle_new_proc(pid,NULL);
				//continue;
				return;
			}
		}
		if ((pc=pid2pcb(pid))==NULL) {
			GDEBUG(0, "signal from unknown pid %d: killed",pid);
			if(ptrace(PTRACE_KILL, pid, 0, 0) < 0){
				GPERROR(0, "KILL");
				exit(1);
			}
		}

		pthread_setspecific(pcb_key,pc);

		if(WIFSTOPPED(status) && (WSTOPSIG(status) == SIGTRAP)){
			int isreproducing=0;
			if ( getregs(pc) < 0 ){
				GPERROR(0, "saving register");
				exit(1);
			}
			//printregs(pc);
			scno=getscno(pc);
			/* execve does not return */
			if (pc->scno == __NR_execve && scno != __NR_execve){
				pc->scno = NOSC;
			}
			isreproducing=(scno == __NR_fork ||
					scno == __NR_vfork ||
					scno == __NR_clone);
			/* sigreturn and rt_sigreturn give random "OUT" values, maybe 0.
			 * this is a workaroud */
#if defined(__x86_64__) //sigreturn and signal aren't defineed in amd64
			if (pc->scno == __NR_rt_sigreturn ){
#else
			if (pc->scno == __NR_rt_sigreturn || pc->scno == __NR_sigreturn) {
#endif
				pc->scno = NOSC;
			}
#if !defined(__x86_64__) //0 is READ for x86_84
			else if (scno == 0) {
				if (pc->scno == __NR_execve)
					pc->scno = NOSC;
			}
#endif
			else if (pc->scno == NOSC)
			{
					divfun fun;
					GDEBUG(3, "--> pid %d syscall %d (%s) @ %p", pid, scno, SYSCALLNAME(scno), getpc(pc));
					//printf("IN\n");
					pc->scno = scno;
					fun=scdtab[scno];
					if (fun != NULL)
						pc->behavior=fun(scno,IN,pc);
					else
						pc->behavior=STD_BEHAVIOR;
#ifdef FAKESIGSTOP
					if (scno == __NR_kill && pc->behavior == STD_BEHAVIOR)
						pc->behavior=fakesigstopcont(pc);
#endif
					if (pc->behavior == SC_FAKE) {
						if (PT_VM_OK) {
							if ((fun(scno,OUT,pc) & SC_SUSPENDED)==0)
								pc->scno=NOSC;
						} else 
						/* fake syscall with getpid if the kernel does not support
						 * syscall shortcuts */
							putscno(__NR_getpid,pc);
					} else
					{
						/* fork is translated into clone 
						 * offspring management */
						if (isreproducing) {
							offspring_enter(pc);
						}
					}
			} else {
					divfun fun;
					GDEBUG(3, "<-- pid %d syscall %d (%s) @ %p", pid, scno, SYSCALLNAME(scno), getpc(pc));
					//printf("OUT\n");
					if (isreproducing) {
						long newpid;
						newpid=getrv(pc);
						handle_new_proc(newpid,pc);
						GDEBUG(3, "FORK! %d->%d",pid,newpid);

						/* restore original arguments */
						offspring_exit(pc);
						putrv(newpid,pc);
					}
					if ((pc->behavior == SC_FAKE && scno != __NR_getpid) && 
							scno != pc->scno)
						GDEBUG(0, "error FAKE != %d",scno);
					fun=scdtab[pc->scno];
					if (fun != NULL &&
							(pc->behavior == SC_FAKE ||
							 pc->behavior == SC_CALLONXIT)) {
						pc->behavior = fun(pc->scno,OUT,pc);
						if ((pc->behavior & SC_SUSPENDED) == 0)
							pc->scno=NOSC;
					} else {
						pc->behavior = STD_BEHAVIOR;
						pc->scno=NOSC;
					}
			} // end if scno==NOSC (OUT)
			if ((pc->behavior & SC_SUSPENDED) == 0) {
				if (PT_VM_OK) {
					/*printf("SC %s %d\n",SYSCALLNAME(scno),pc->behavior);*/
					if(setregs(pc,PTRACE_SYSVM, (isreproducing ? 0 : pc->behavior)) == -1)
							GPERROR(0, "setregs");
					if(!isreproducing && (pc->behavior & PTRACE_VM_SKIPEXIT))
						pc->scno=NOSC; 
				} else
					if( setregs(pc,PTRACE_SYSCALL, 0) == -1)
						GPERROR(0, "setregs");
			}
		} // end if SIGTRAP
		else if(WIFSIGNALED(status)) {
			GDEBUG(3, "%d: signaled %d",pid,WTERMSIG(status));
			/* process killed by a signal */
			droppcb(pc);
		}
		else if(WIFSTOPPED(status)) {
			GDEBUG(3, "%d: stopped sig=%d",pid,(WSTOPSIG(status)));
			if(WSTOPSIG(status) == SIGSEGV)
			{
				if(getregs(pc) == -1)
					GDEBUG(3, "[err]");
				GDEBUG(3, "%d: stopped sig=SIGSEGV @ %p",
						pc->pid, getpc(pc));
			}
			/*if (!sigishandled(pc,  WSTOPSIG(status))) {
				// also progenie, but for now 
				//ptrace(PTRACE_KILL,pid,0,0);
				//printf("KILLED %d %d\n", pid,pc->pid);
			}*/
#ifdef FAKESIGSTOP
			if (WSTOPSIG(status) == SIGTSTP && pc->pp != NULL) {
				pc->flags |= PCB_FAKESTOP;
				GDEBUG(1, "KILL 28 %d",pc->pp->pid);
				//SIGSTOP -> FAKE SIGWINCH
				kill(pc->pp->pid,28);
			} else
#endif
			/* forward signals to the process */
			if(ptrace(PTRACE_SYSCALL, pid, 0, WSTOPSIG(status)) < 0){
				GPERROR(0, "continuing");
				exit(1);
			}
		}
		else if(WIFEXITED(status)) {
			//printf("%d: exited\n",pid);
			/* the process has terminated */
			droppcb(pc);
			/* if it was the "init" process (first child), save its exit status,
			 * since it is also _our_ exit status! */
			if(first_child_pid == pc->pid)
				first_child_exit_status = WEXITSTATUS(status);
		}
		else GDEBUG(1, "wait failed - pid = %d, status = %d", pid, status);
	}
}

void sc_resume(struct pcb *pc)
{
	/* int pid=pc->pid; */
	int scno=pc->scno;
	int inout=pc->behavior-SC_SUSPENDED;
	int	isreproducing=(scno == __NR_fork ||
			scno == __NR_vfork ||
			scno == __NR_clone);
	divfun fun;
	fun=scdtab[scno];
	if (fun != NULL)
		pc->behavior=fun(scno,inout,pc);
	else
		pc->behavior=STD_BEHAVIOR;
	if (inout==IN) {
		if (pc->behavior == SC_FAKE) {
			if (PT_VM_OK) {
				if (inout==IN && (fun(scno,OUT,pc) & SC_SUSPENDED)==0)
					pc->scno=NOSC;
			} else
				putscno(__NR_getpid,pc);
		} else {
			if (isreproducing)
				offspring_enter(pc);
		}
	} else { /* inout == OUT */
		if ((pc->behavior & SC_SUSPENDED) == 0)
			pc->scno=NOSC;
	}
	if ((pc->behavior & SC_SUSPENDED) == 0) {
		if (PT_VM_OK) {
			if(setregs(pc,PTRACE_SYSVM,isreproducing ? 0 : pc->behavior) == -1)
			    GPERROR(0, "setregs");
			if(!isreproducing && (pc->behavior & PTRACE_VM_SKIPEXIT))
				pc->scno=NOSC;
  } else
		if( setregs(pc,PTRACE_SYSCALL,0) == -1)
			GPERROR(0, "setregs");
	}
}

/*
 * Set up the pipe used by the SIGCHLD signal handler to wake the main
 * select() and tell it to start tracehand().
 */
void wake_tracer_init()
{
	r_pipe(tracerpipe);
	r_fcntl(tracerpipe[0],F_SETFL,O_NONBLOCK);
}

/*
 * Write data to the tracerpipe: we received a SIGCHLD and the main
 * select cycle must run tracehand()
 */
void wake_tracer(int s)
{
	char x = 0;
	if (!tracerpipecounter) // No more than 1 message
	{
		tracerpipecounter = 1;
		r_write(tracerpipe[1], &x, 1);
	}
}

/*
 * Add the "read" end of the tracerpipe to a fd_set.
 * Return the new maximum fd number.
 */
int add_tracerpipe_to_wset(int prevmax, fd_set *wset)
{
	FD_SET(tracerpipe[0], wset);
	if (tracerpipe[0] > prevmax)
		return tracerpipe[0];
	else
		return prevmax;
}

/*
 * Check if the select() has been woken for a message
 * in the tracerpipe. In that case, also empty the pipe.
 */
int must_wake_tracer(fd_set *wset)
{
	int retval = FD_ISSET(tracerpipe[0], wset);
	if (retval)
	{
		char buf[256];
		r_read(tracerpipe[0], buf, 256);
		tracerpipecounter = 0;
	}
	return retval;
}

void wake_null(int s)
{
}

static void setsigaction(int has_pselect)
{
	struct sigaction sa;

	sa.sa_handler = SIG_IGN;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGTTOU, &sa, NULL);
	sigaction(SIGTTIN, &sa, NULL);
	sigaction(SIGHUP, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGQUIT, &sa, NULL);
	sigaction(SIGPIPE, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	////sa.sa_handler = SIG_DFL;
	// SIGCHLD: syscall hadling is interruptable
	//sigaddset(&sa.sa_mask,SIGCHLD);
	// fillset: syscall hadling is not interruptable
	sigfillset(&sa.sa_mask);
	/* 
	 * The signal handler is no longer the whole tracehand()
	 * but a smaller function whose only duty is to
	 * wake up the select() in main().
	 * With pselect there is no need for pipe: in this latter
	 * case SIGCHLD gets blocked. SIGCHLD will unblock pselect
	 */
	if (has_pselect) {
		sigset_t blockchild; 
		sigemptyset(&blockchild);
		sigaddset(&blockchild,SIGCHLD);
		sigprocmask(SIG_BLOCK,&blockchild,NULL);
		sa.sa_handler = wake_null;
	} else
		sa.sa_handler = wake_tracer;
	sigaction(SIGCHLD, &sa, NULL);
}

static void vir_pcb_free(void *arg)
{
	struct pcb *pc=arg;
	if (pc->flags & PCB_ALLOCATED) {
		free(arg);
	}
}

static int r_execvp(const char *file, char *const argv[]){
	if(strchr(file,'/') != NULL)
		return execve(file,argv,environ);
	else {
		char *path;
		char *envpath;
		char *pathelem;
		char buf[PATH_MAX];
		if ((envpath=getenv("PATH")) == NULL)
			envpath="/bin:/usr/bin";
		path=strdup(envpath);
		while((pathelem=strsep(&path,":")) != NULL){
			if (*pathelem != 0) {
				register int i,j;
				for (i=0; i<PATH_MAX && pathelem[i]; i++)
					buf[i]=pathelem[i];
				if(buf[i-1] != '/' && i<PATH_MAX)
					buf[i++]='/';
				for (j=0; i<PATH_MAX && file[j]; j++,i++)
					buf[i]=file[j];
				buf[i]=0;
				if (r_execve(buf,argv,environ)<0 &&
						((errno != ENOENT) && (errno != ENOTDIR) && (errno != EACCES))) {
					free(path);
					return -1;
				}
			}
		}
		free(path);
		errno = ENOENT;
		return -1;
	}
}

int capture_main(char **argv,int has_pselect)
{
	int status;

	allocatepcbtab();
	switch (first_child_pid=fork()) {
		case -1:
			GPERROR(0, "strace: fork");
			exit(1);
			break;
		case 0:
			if (!has_pselect) {
				close(tracerpipe[0]);
				close(tracerpipe[1]);
			}
			unsetenv("LD_PRELOAD");
			r_setpriority(PRIO_PROCESS,0,0);
			if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0){
				GPERROR(0, "ptrace");
				exit(1);
			}
			r_kill(getpid(), SIGSTOP);
			/* maybe it is better to use execvp instead of r_execvp.
			 * the former permits to use a (preloaded) module provided executable as startup process*/
			r_execvp(argv[0], argv);
			GPERROR(0, "strace: exec");
			_exit(1);
		default:
			pthread_key_create(&pcb_key,vir_pcb_free);
			capture_nested_init();
			handle_new_proc(first_child_pid,pcbtab[0]);
			pthread_setspecific(pcb_key,pcbtab[0]);
			if(r_waitpid(first_child_pid, &status, WUNTRACED) < 0){
				GPERROR(0, "Waiting for stop");
				exit(1);
			}
			setsigaction(has_pselect);
			if(ptrace(PTRACE_SYSCALL, first_child_pid, 0, 0) < 0){
				GPERROR(0, "continuing");
				exit(1);
			}
	}
	return 0;
}

/* vim: set ts=2 shiftwidth=2: */
