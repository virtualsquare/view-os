/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   capture_sc.c : capture and divert system calls
 *   
 *   Copyright 2005 Renzo Davoli University of Bologna - Italy
 *   Modified 2005 Mattia Belletti, Ludovico Gardenghi, Andrea Gasparini
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
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <asm/ptrace.h>
#include <asm/unistd.h>
#include <sched.h>
#include <limits.h>
#include <assert.h>

// #define FAKESIGSTOP

#include "defs.h"
#include "sctab.h"
#include "utils.h"
#include "syscallnames.h"
#include "gdebug.h"
#ifdef PIVOTING_ENABLED
#include "pivoting.h"
#endif


#define PCBSIZE 10

static struct pcb **pcbtab;
int nprocs = 0;
static int pcbtabsize;

divfun scdtab[MAXSC];
divfun scdutab[MAXUSC];
t_pcb_constr pcb_constr=NULL;
t_pcb_destr pcb_destr=NULL;

#ifdef __i386__ 
/* i386 kernel does not accept out of range system calls, 
 * user system call remapped onto unused ones */
short _i386_sc_remap[]={251,222,17,31,32,35,44,53,56,58,98,112,127,130,137,167};
#endif

/* When a SIGCHLD is received, the main select will be notified through this
 * pipe; the counter is used to notify it no more than one time. */
int tracerpipe[2];
int tracerpipecounter = 0;

/* umview have to exit with the exit code of the first child: here we remember
 * what the first child was, and save its exit value */
pid_t first_child_pid;
int first_child_exit_status = -1;

struct pcb *newpcb (int pid)
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
			pcb->flags = PCB_INUSE;
			pcb->scno = NOSC;
			pcb->pp = NULL;
			pcb->data = NULL;
#ifdef PIVOTING_ENABLED
			pcb->first_instruction_address = NULL;
			pcb->saved_code = NULL;
#endif
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
			f(pc,arg);
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

static void droppcb(struct pcb *pc)
{
	pc->flags = 0; /*NOT PCB_INUSE */;
	if (pcb_destr != NULL)
		pcb_destr(pc);
	nprocs--;
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
	if ((oldpc=pid2pcb(pid)) == NULL && (pc = newpcb(pid))== NULL) {
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
		if (pcb_constr != NULL)
			pcb_constr(pc,pp->arg2);
	}
	return 0;
}
	
#ifdef FAKESIGSTOP
int fakesigstopcont(struct pcb *pc)
{
	int kpid=getargn(0,pc);
	int ksig=getargn(1,pc);
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
		putarg0orig(CLONE_PTRACE|SIGCHLD, pc);
		putargn(1,0, pc);
		pc->arg2=SIGCHLD;
	}
	else if (pc->scno == __NR_clone) {
		putargn(0,pc->arg0 | CLONE_PTRACE, pc);
		putarg0orig(pc->arg0 | CLONE_PTRACE, pc);
		pc->arg2=pc->arg0;
	}
	pc->flags |= PCB_BPTSET;
}

void offspring_exit(struct pcb *pc)
{
	putarg0orig(pc->arg0,pc);
	putargn(1,pc->arg1,pc);
        pc->flags &= ~PCB_BPTSET;
}

void sc_soft_suspend(struct pcb *pc)
{
	unsigned int sp=getsp(pc);
	GDEBUG(1, "sc_soft_suspend %d fd %d",pc->pid,pc->retval);
	pc->arg0=getargn(0,pc);
	pc->arg1=getargn(1,pc);
	pc->arg2=getargn(2,pc);
	putscno(__NR_read,pc);
	putargn(0,pc->retval, pc);
	putarg0orig(pc->retval, pc);
	putargn(1,sp-4,pc);
	putargn(2,1,pc);
	pc->flags |= PCB_SOFTSUSP; /* unused ? */
}

void sc_soft_resume(struct pcb *pc)
{
	int syscall=pc->scno;
	GDEBUG(1, "sc_soft_resume %d",pc->pid);
	putscno(syscall,pc);
	putargn(0,pc->arg0, pc);
	putarg0orig(pc->arg0, pc);
	putargn(1,pc->arg1,pc);
	putargn(2,pc->arg2,pc);
	pc->flags &= ~PCB_SOFTSUSP; /* unused ? */
}


void tracehand(int s)
{
	int pid, status, syscall=0;
	struct pcb *pc;

	while(nprocs>0){
		if((pid = waitpid(-1, &status, WUNTRACED | __WALL | WNOHANG)) < 0)
		////if((pid = waitpid(-1, &status, WUNTRACED | __WALL)) <= 0)
		{
			GPERROR(0, "wait");
			exit(1);
		}
		////comment out the following line
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

#ifdef PIVOTING_TEST
		if(pc->flags & PCB_INPIVOTING)
		{
			int _pc;
			int data;
			if(popper(pc) < 0)
				GPERROR(0, "saving register");
			_pc = getpc(pc);
			umoven(pc->pid, _pc, 4, &data);
			GDEBUG(3, "pc=%x, instruction=%x", _pc, data);
		}
#endif

		if(WIFSTOPPED(status) && (WSTOPSIG(status) == SIGTRAP)){
			if ( popper(pc) < 0 ){
				GPERROR(0, "saving register");
				exit(1);
			}
			//printregs(pc);
			syscall=getscno(pc);
			GDEBUG(3, "+++pid %d syscall %d (%s) @ %p --", pid, syscall, SYSCALLNAME(syscall),
					getpc(pc));
			/* execve does not return */
			if (pc->scno == __NR_execve && syscall != __NR_execve){
				pc->scno = NOSC;
			}
			/* sigreturn and rt_sigreturn give random "OUT" values, maybe 0.
			 * this is a workaroud */
			if (pc->scno == __NR_rt_sigreturn || pc->scno == __NR_sigreturn) {
				pc->scno = NOSC;
			}
			else if (syscall == 0) {
				if (pc->scno == __NR_execve)
					pc->scno = NOSC;
			}
			else if (pc->scno == NOSC)
			{
#ifdef PIVOTING_ENABLED
				/* if we are in pivoting, calls are diverted to the callback function */
				if(pc->flags & PCB_INPIVOTING)
				{
					GDEBUG(3, "pivoting, IN phase");
					printregs(pc);
					pc->scno = syscall;
					pc->piv_callback(syscall, PHASE_IN, pc, pc->counter++);
					/* we put by hand a fake syscall, with a big number; check if this is
					 * the case. if it is, pivoting has ended */
					if(syscall == BIG_SYSCALL)
					{
						pivoting_eject(pc);
						/* simulate a fake syscall */
						putscno(__NR_getpid, pc);
						pc->behavior = SC_FAKE;
					}
				}
				else
				{
#endif
					divfun fun;
					//printf("IN\n");
					pc->scno = syscall;
					fun=cdtab(syscall);
					if (fun != NULL)
						pc->behavior=fun(syscall,IN,pc);
					else
						pc->behavior=STD_BEHAVIOR;
#ifdef FAKESIGSTOP
					if (syscall == __NR_kill && pc->behavior == STD_BEHAVIOR)
						pc->behavior=fakesigstopcont(pc);
#endif
					if (pc->behavior == SC_FAKE) {
						//printf("syscall %d faked",pc->scno);
						/* fake syscall with getpid */
						putscno(__NR_getpid,pc);
					} else if (pc->behavior == SC_SOFTSUSP) {
						sc_soft_suspend(pc);
					} else
					{
						/* fork is translated into clone 
						 * offspring management */
						if (syscall == __NR_fork ||
								syscall == __NR_vfork ||
								syscall == __NR_clone)
							offspring_enter(pc);
					}
#ifdef PIVOTING_ENABLED
				}
#endif
			} else {
#ifdef PIVOTING_ENABLED
				/* if we are in pivoting, calls are diverted to the callback function */
				if(pc->flags & PCB_INPIVOTING)
				{
					GDEBUG(3, "pivoting, OUT phase");
					printregs(pc);
					pc->piv_callback(syscall, PHASE_OUT, pc, pc->counter++);
					pc->scno = NOSC;
				}
				else
				{
#endif
					divfun fun;
					//printf("OUT\n");
					if (pc->behavior == SC_SOFTSUSP) {
						int n=getrv(pc);
						if (n <= 0) {
							puterrno(EAGAIN,pc);
							putrv(-1,pc);
							pc->behavior = STD_BEHAVIOR;
						} else {
							sc_soft_resume(pc);
							syscall=pc->scno;
							fun=cdtab(syscall);
							//GDEBUG(2, "enter resumed fun");
							pc->behavior=fun(syscall,IN,pc);
							//GDEBUG(2, "exit resumed fun %d",pc->behavior);
							if (pc->behavior == SC_FAKE)
								syscall=__NR_getpid;
						}
					}
					if (syscall == __NR_fork ||
							syscall == __NR_vfork ||
							syscall == __NR_clone) {
						int newpid;
						newpid=getrv(pc);
						handle_new_proc(newpid,pc);
						GDEBUG(3, "FORK! %d->%d",pid,newpid);

						/* restore original arguments */
						offspring_exit(pc);
						putrv(newpid,pc);
					}
					if ((pc->behavior == SC_FAKE && syscall != __NR_getpid) && 
							syscall != pc->scno)
						GDEBUG(0, "error FAKE != %d",syscall);
					fun=cdtab(pc->scno);
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
#ifdef PIVOTING_ENABLED
				}
#endif
			} // end if scno==NOSC (OUT)
			if( pusher(pc) == -1 ){
					//printf("errno - pusher: %d on process %d \n",errno,pc->pid);
					GPERROR(0, "pusher");
					// think if we have to decomment this line...
					//exit(-1);
			}
			//debug string
			/*printf("+++pid %d syscall %d %d %s rv %d --\n",pid,pc->scno,syscall,
					 SYSCALLNAME(syscall),getrv(pc));*/
			if((pc->behavior & SC_SUSPENDED) == 0) {
				if (ptrace(PTRACE_SYSCALL, pid, 0, 0) < 0){
					GPERROR(0, "continuing");
					exit(1);
				}
			} // end if behavior & SC_SUSP
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
				if(popper(pc) == -1)
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
	int pid=pc->pid;
	int syscall=pc->scno;
	int inout=pc->behavior-SC_SUSPENDED;
	divfun fun;
	fun=cdtab(syscall);
	if (fun != NULL)
		pc->behavior=fun(syscall,inout,pc);
	else
		pc->behavior=STD_BEHAVIOR;
	if (inout==IN) {
		if (pc->behavior == SC_FAKE) {
			putscno(__NR_getpid,pc);
		} else {
			if (syscall == __NR_fork ||
					syscall == __NR_vfork ||
					syscall == __NR_clone)
				offspring_enter(pc);
		}
	} else { /* inout == OUT */
		if ((pc->behavior & SC_SUSPENDED) == 0)
			pc->scno=NOSC;
	}
	if( pusher(pc) == -1 ){
		          //printf("errno - pusher: %d on process %d \n",errno,pc->pid);
		GPERROR(0, "pusher");
		// think if we have to decomment this line...
		//exit(-1);
	}
	if((pc->behavior & SC_SUSPENDED) == 0) {
		if (ptrace(PTRACE_SYSCALL, pid, 0, 0) < 0){
			GPERROR(0, "continuing");
			exit(1);
		}
	}
}

/*
 * Set up the pipe used by the SIGCHLD signal handler to wake the main
 * select() and tell it to start tracehand().
 */
void wake_tracer_init()
{
	pipe(tracerpipe);	
	fcntl(tracerpipe[0],F_SETFL,O_NONBLOCK);
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
		write(tracerpipe[1], &x, 1);
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
		read(tracerpipe[0], buf, 256);
		tracerpipecounter = 0;
	}
	return retval;
}

static void setsigaction()
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
	 */
	sa.sa_handler = wake_tracer;
	sigaction(SIGCHLD, &sa, NULL);
}


int capture_main(char **argv)
{
	int status;

	allocatepcbtab();
	switch (first_child_pid=fork()) {
		case -1:
			GPERROR(0, "strace: fork");
			exit(1);
			break;
		case 0:
			if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0){
				GPERROR(0, "ptrace");
				exit(1);
			}
			kill(getpid(), SIGSTOP);
			execvp(argv[0], argv);
			GPERROR(0, "strace: exec");
			_exit(1);
		default:
			handle_new_proc(first_child_pid,pcbtab[0]);
			if(waitpid(first_child_pid, &status, WUNTRACED) < 0){
				GPERROR(0, "Waiting for stop");
				exit(1);
			}
#ifdef PIVOTING_ENABLED
			register_first_instruction(pcbtab[0]);
#endif
			setsigaction();
			if(ptrace(PTRACE_SYSCALL, first_child_pid, 0, 0) < 0){
				GPERROR(0, "continuing");
				exit(1);
			}
	}

	return 0;
}

/* vim: set ts=2 shiftwidth=2: */
