/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   um_ptrace: ptrace management
 *   
 *   Copyright 2011-2012 Renzo Davoli University of Bologna - Italy
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
 *   $Id: um_wdm.c 823 2010-03-06 17:43:18Z rd235 $
 *
 */   
#include <assert.h>
#include <string.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <asm/ptrace.h>
#include <asm/unistd.h>
#include <linux/net.h>
#include <sys/uio.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/user.h>
#include <stdlib.h>
#include <config.h>
#include "defs.h"
#include "umproc.h"
#include "hashtab.h"
#include "um_services.h"
#include "sctab.h"
#include "scmap.h"
#include "utils.h"
#include "gdebug.h"
#include "capture.h"
#include "mainpoll.h"
#ifdef _UM_PTRACE
#if defined(__i386__) || defined(__x86_64__)
#include <sys/reg.h>
#endif

struct pcblist {
	struct pcblist *next;
	struct pcb *pc;
};

static struct pcblist *pcblist_resume=NULL;

static struct pcblist *pcblistfree=NULL;
#define PCBLIST_ALLOC_SIZE 16
static struct pcblist *pcblist_alloc(void) {
	struct pcblist *rv;
	if (pcblistfree == NULL) {
		int i;
		rv = malloc(sizeof(struct pcblist) *  PCBLIST_ALLOC_SIZE);
		if (rv == NULL)
			return NULL;
		for (i=0;i<PCBLIST_ALLOC_SIZE-1;i++)
			rv[i].next=&rv[i+1];
		rv[i].next=NULL;
		pcblistfree=rv;
	}
	rv=pcblistfree;
	pcblistfree=pcblistfree->next;
	return rv;
}

static void pcblist_free(struct pcblist *old)
{
	old->next=pcblistfree;
	pcblistfree=old;
}

static void pcblist_enqueue(struct pcblist **list, struct pcb *pc)
{
	struct pcblist *new=pcblist_alloc();
	if (new) {
		new->pc = pc;
		if (*list == NULL) 
			*list=new->next=new;
		else {
			new->next=*list;
			(*list)->next=new;
			*list=new;
		}
	}
}

static struct pcb *pcblist_dequeue(struct pcblist **list)
{
	if (*list == NULL)
		return NULL;
	else {
		struct pcblist *head=(*list)->next;
		struct pcb *pc;
		pc = head->pc;
		if (head->next == head) 
			*list = NULL;
		else 
			(*list)->next = head->next;
		pcblist_free(head);
		return pc;
	}
}

#ifndef _VIEWOS_KM
static void ptrace_resume(struct pcb *pc)
{
	// printk("ptrace_resume %d %x\n",pc->pid,pc->ptrace_request);
	if (pc->ptrace_request & PTRACE_STATUS_SYSOUT)
	{
		if (r_ptrace(PTRACE_SYSCALL,pc->pid,0,pc->signum) < 0)
			GPERROR(0, "restart");
	} else {
		pcblist_enqueue(&pcblist_resume,pc);
		restart_main_loop();
	}
}

static struct pcb *ptrace_pid2pcb(pid_t pid, struct pcb *pc)
{
	struct pcb *rv=pid2pcb(pid);
	//printk("ptrace_pid2pcb %d %p\n",pid,rv);
	if (rv==NULL || rv->ptrace_pp != pc)
		return NULL;
	else
		return rv;
}
#endif

int wrap_in_ptrace(int sc_number,struct pcb *pc,
		struct ht_elem *hte, sysfun um_syscall)
{
#ifdef _VIEWOS_KM
	return STD_BEHAVIOR;
#else
	if (!ptraceemu)
		return STD_BEHAVIOR;
	else {
		enum __ptrace_request request=pc->sysargs[0];
		pid_t pid=pc->sysargs[1];
		long addr=pc->sysargs[2];
		long data=pc->sysargs[3];
		struct pcb *tracedpc;
		// printk("PTRACE %d %d %x %x\n",request,pid,addr,data);
		pc->retval=0;
		pc->erno=0;
		switch (request) {
			case PTRACE_PEEKTEXT:
			case PTRACE_PEEKDATA:
			case PTRACE_POKETEXT:
			case PTRACE_POKEDATA:
			case PTRACE_PEEKUSER:
			case PTRACE_POKEUSER:
			case PTRACE_KILL:
			case PTRACE_SYSCALL:
			case PTRACE_SINGLESTEP:
			case PTRACE_CONT:
			case PTRACE_GETREGS:
			case PTRACE_SETREGS:
			case PTRACE_GETSIGINFO:
			case PTRACE_SETSIGINFO:
			case PTRACE_GETFPREGS:
			case PTRACE_SETFPREGS:
			case PTRACE_DETACH:
			case PTRACE_ATTACH:
			case PTRACE_GETEVENTMSG:
				tracedpc=ptrace_pid2pcb(pid,pc);
				if (tracedpc == NULL) {
					pc->retval=-1;
					pc->erno=ESRCH;
					return SC_FAKE;
				}
				break;
			default:
				tracedpc=NULL;
		}
		switch (request) {
			case PTRACE_TRACEME:
				if (pc->pp != pc && /* init cannot be traced! */
						pc->ptrace_pp == NULL) {
					//printk("PTRACE_TRACEME %d %d\n",pc->pid,pc->pp->pid);
					pc->ptrace_pp=pc->pp;
					pc->ptrace_pp->ptrace_ntraced++;
				} else {
					pc->retval=-1;
					pc->erno=EPERM;
				}
				break;
			case PTRACE_SETOPTIONS:
				// printk ("%d PTRACE_SETOPTIONS %x\n",pc->pid,data);
				pc->ptrace_options=data;
				break;
			case PTRACE_PEEKTEXT:
			case PTRACE_PEEKDATA: 
				{
					long traced_data; 
					if (umoven(tracedpc, addr, sizeof(long), &traced_data) < 0 || 
							ustoren(pc, data, sizeof(long), &traced_data) < 0)
					{
						pc->retval=-1;
						pc->erno=EFAULT;
					}
				}
				break;
			case PTRACE_POKETEXT:
			case PTRACE_POKEDATA:
				{
					if (ustoren(tracedpc, addr, sizeof(long), &data) < 0)  {
						pc->retval=-1;
						pc->erno=EFAULT;
					}
				}
				break;

			case PTRACE_PEEKUSER:
				{
					long traced_data; 
					pc->retval = r_ptrace(PTRACE_PEEKUSER, tracedpc->pid, (void *)addr, &traced_data);
					if (pc->retval >= 0) {
						if (ustoren(pc, data, sizeof(long), &traced_data) < 0) {
							pc->retval=-1;
							pc->erno=EFAULT;
						} else
							pc->retval= 0;
					} else
						pc->erno = errno;
					break;
				}

			case PTRACE_POKEUSER:
				pc->retval = r_ptrace(PTRACE_POKEUSER, tracedpc->pid, (void *)addr, data);
				break;

			case PTRACE_GETREGS:
				{
#ifdef __arm__
					struct user_regs regs;
#else
					struct user_regs_struct regs;
#endif
					//printk("PTRACE_GETREGS %d %x\n",tracedpc->pid,data);
					if (r_ptrace(PTRACE_GETREGS,  tracedpc->pid, NULL, &regs) < 0 ||
							ustoren(pc, data, sizeof(regs), &regs) < 0) {
						pc->retval=-1;
						pc->erno=EFAULT;
					}
				}
				break;

			case PTRACE_SETREGS:
				{
#ifdef __arm__
					struct user_regs regs;
#else
					struct user_regs_struct regs;
#endif
					if (umoven(pc, data, sizeof(regs), &regs) < 0 ||
							r_ptrace(PTRACE_SETREGS,  tracedpc->pid, NULL, &regs) < 0) {
						pc->retval=-1;
						pc->erno=EFAULT;
					}
					//printk("PTRACE_SETREGS %d %d\n",tracedpc->pid,regs.eax);
				}
				break;

			case PTRACE_GETFPREGS:
				{
#ifdef __arm__
					struct user_fpregs regs;
#else
					struct user_fpregs_struct regs;
#endif
					if (r_ptrace(PTRACE_GETFPREGS,  tracedpc->pid, NULL, &regs) < 0 ||
							ustoren(pc, data, sizeof(regs), &regs) < 0) {
						pc->retval=-1;
						pc->erno=EFAULT;
					}
				}
				break;
			case PTRACE_SETFPREGS:
				{
#ifdef __arm__
					struct user_fpregs regs;
#else
					struct user_fpregs_struct regs;
#endif
					if (umoven(pc, data, sizeof(regs), &regs) < 0 ||
							r_ptrace(PTRACE_SETFPREGS,  tracedpc->pid, NULL, &regs) < 0) {
						pc->retval=-1;
						pc->erno=EFAULT;
					}
				}
				break;

			case PTRACE_GETSIGINFO:
				{
					siginfo_t siginfo;
					if (r_ptrace(PTRACE_GETSIGINFO,  tracedpc->pid, NULL, &siginfo) < 0 ||
							ustoren(pc, data, sizeof(siginfo), &siginfo) < 0) {
						pc->retval=-1;
						pc->erno=EFAULT;
					}
				}
				break;
			case PTRACE_SETSIGINFO:
				{
					siginfo_t siginfo;
					if (umoven(pc, data, sizeof(siginfo), &siginfo) < 0 ||
							r_ptrace(PTRACE_SETSIGINFO,  tracedpc->pid, NULL, &siginfo) < 0) {
						pc->retval=-1;
						pc->erno=EFAULT;
					}
				}
				break;

			case PTRACE_GETEVENTMSG:
				{
					unsigned long msg;
					if (r_ptrace(PTRACE_GETEVENTMSG, tracedpc->pid, (void *)addr, &msg) ||
							ustoren(pc, data, sizeof(msg), &msg) < 0) {
						pc->retval=-1;
						pc->erno=EFAULT;
					}
				}
				break;

			case PTRACE_KILL:
				//printk("-----------------------KILL %d %d\n",pid,tracedpc->pid);
				tracedpc->signum=9;
				ptrace_resume(tracedpc);
				break;
			case PTRACE_SYSCALL:
				tracedpc->signum=data;
				tracedpc->ptrace_request |= PTRACE_STATUS_SYSCALL;
				ptrace_resume(tracedpc);
				break;

			case PTRACE_SINGLESTEP:
				tracedpc->signum=data;
				tracedpc->ptrace_request |= PTRACE_STATUS_SINGLESTEP;
				ptrace_resume(tracedpc);
				break;

			case PTRACE_CONT:
				tracedpc->signum=data;
				tracedpc->ptrace_request &= ~(PTRACE_STATUS_SYSCALL | PTRACE_STATUS_SINGLESTEP);
				ptrace_resume(tracedpc);
				break;

			case PTRACE_DETACH:
				if (tracedpc->ptrace_pp == pc) {
					tracedpc->ptrace_pp = NULL;
					pc->ptrace_ntraced--;
					ptrace_resume(tracedpc);
				} else {
					pc->retval=-1;
					pc->erno=EPERM;
				}
				break;

			case PTRACE_ATTACH:
				//printk ("ATTACH ATTACH ATTACH!!!!\n");


			default:
				pc->retval=-1;
				pc->erno=EPERM;
		}
		//printk("PTRACE %d %d %x %x DONE\n",request,pid,addr,data);
		return SC_FAKE;
	}
#endif
}

static int ptrace_this(int status, struct pcb *pc)
{
#ifdef _VIEWOS_KM
	return 0;
#else
	if (WIFSTOPPED(status)) {
		if (WSTOPSIG(status) == (0x80 | SIGTRAP)) {
			/* syscall */
			if (pc->ptrace_request & PTRACE_STATUS_SYSCALL) {
				int scno;
				/* workaround: execve->getpid when SC_FAKE, so the
					 check in capture_um fails */
				// printk("ptrace_this STATUS %x\n",status);
				r_ptrace(PTRACE_PEEKUSER,pc->pid,SCNOPEEKOFFSET,&scno);
				if (pc->sysscno == __NR_getpid && scno != __NR_getpid)
					pc->sysscno = __NR_execve;
				if (pc->sysscno == __NR_execve) {
					//printk("TEST EXECVE  PTRACE EXECVE %d\n",scno); 
					if (
#if __NR_socketcall != __NR_doesnotexist
							pc->sockaddr == 0 &&
#endif
							scno != __NR_execve &&
							(pc->behavior != SC_FAKE || scno != __NR_getpid)){
						//printk("EXECVE  PTRACE EXECVE %d\n",scno); 
						pc->ptrace_request &= ~PTRACE_STATUS_SYSOUT;
						return 1;
					}
				}
				if (pc->sysscno < 0) {
					pc->ptrace_request &= ~PTRACE_STATUS_SYSOUT;
					return 1;
				} else {
					pc->ptrace_request |= PTRACE_STATUS_SYSOUT;
					return 0;
				}
			} else
				return 0;
		} else if (WIFSTOPPED(status) && (status >> 16) > 0)
			return 0;
		else
			return 1;
	} else 
		/* if it is terminated or signaled, and the tracker is my parent DOES NOT TRACK IT!
			 (will be signaled anyway.
			 in all other cases forward the ptrace */
		if ((WIFEXITED(status) || WIFSIGNALED(status)) && (pc->pp == pc->ptrace_pp))
			return 0;
		else
			return 1;
#endif
}


int ptrace_hook_in(int status, struct pcb *pc)
{
#ifdef _VIEWOS_KM
	return 0;
#else
	int scno;
	r_ptrace(PTRACE_PEEKUSER,pc->pid,SCNOPEEKOFFSET,&scno);
	/*if (pc->ptrace_pp != NULL)
		printk("ptrace_hook_in %d %p %x (%x) SYSSCO %d SC %d\n",pc->pid,pc->ptrace_pp,status,pc->ptrace_request,pc->sysscno,scno);*/
	if (pc->ptrace_pp != NULL) {
		if ((pc->ptrace_request == 0) &&
				pc->sysscno == __NR_execve && (scno == __NR_execve || scno == 0)) {
			pc->signum = SIGSTOP;
		}
		pc->ptrace_status=status;
		/*select SYSCALL/CONT/SINGLESTEP*/
		if (ptrace_this(status, pc)) {
			// printk("ptrace_hook_in %d -> %x SC%d\n",pc->pid,status,scno);
			pcblist_enqueue(&pc->ptrace_pp->ptrace_notify_head, pc);
			if (pc->ptrace_pp->ptrace_waitpid < 0 || pc->ptrace_pp->ptrace_waitpid == pc->pid) {
				pc->ptrace_pp->ptrace_waitpid = 0;
				sc_resume(pc->ptrace_pp);
			} else
				r_kill(pc->ptrace_pp->pid,SIGCHLD);
			//printk("%x %x %d\n",pc->pp,pc->ptrace_pp,((WIFEXITED(status) || WIFSIGNALED(status)) && (pc->pp != pc->ptrace_pp)));
			/* DO NOT stop for termination tracking */
			if (WIFEXITED(status) || WIFSIGNALED(status))
				return 0;
			else
				return 1;
		}
	}
	return 0;
#endif
}

#ifndef _VIEWOS_KM
static int matchrequest(int status,int options)
{
	// printk("matchrequest %x %x\n",status,options);
	switch (status>>16) {
		case PTRACE_EVENT_FORK:
			return options & PTRACE_O_TRACEFORK;
		case PTRACE_EVENT_VFORK:
			return options & PTRACE_O_TRACEVFORK;
		case PTRACE_EVENT_CLONE:
			return options & PTRACE_O_TRACECLONE;
		case PTRACE_EVENT_EXEC:
			return options & PTRACE_O_TRACEEXEC;
		case PTRACE_EVENT_VFORK_DONE:
			return options & PTRACE_O_TRACEVFORKDONE;
		case PTRACE_EVENT_EXIT:
			return options & PTRACE_O_TRACEEXIT;
		default:
			return 0;
	}
}
#endif

int ptrace_hook_event(int status, struct pcb *pc)
{
#ifdef _VIEWOS_KM
	return 0;
#else
	if (pc->ptrace_pp != NULL && matchrequest(status,pc->ptrace_pp->ptrace_options)) {
		pc->ptrace_status=status;
		// printk("ptrace_hook_event NOTIFY %x!!\n",status);
		pc->ptrace_request |= PTRACE_STATUS_SYSOUT;
		pcblist_enqueue(&pc->ptrace_pp->ptrace_notify_head, pc);
		if (pc->ptrace_pp->ptrace_waitpid < 0 || pc->ptrace_pp->ptrace_waitpid == pc->pid) {
			pc->ptrace_pp->ptrace_waitpid = 0;
			sc_resume(pc->ptrace_pp);
		} else
			r_kill(pc->ptrace_pp->pid,SIGCHLD);
		return 1;
	}
	else
		return 0;
#endif
}

int ptrace_follow(int status, struct pcb *pc)
{
#ifdef _VIEWOS_KM
	return 0;
#else
	if (pc->ptrace_pp == NULL)
		return 0;
	else {
		int options=pc->ptrace_pp->ptrace_options;
		switch (status>>16) {
			case PTRACE_EVENT_FORK:
				return options & PTRACE_O_TRACEFORK;
			case PTRACE_EVENT_VFORK:
				return options & PTRACE_O_TRACEVFORK;
			case PTRACE_EVENT_CLONE:
				return options & PTRACE_O_TRACECLONE;
			default:
				return 0;
		}
	}
#endif
}

int ptrace_hook_out(int *status, struct pcb **pc)
{
	*pc = pcblist_dequeue(&pcblist_resume);
	if (*pc) {
		// printk("ptrace_hook_out %d %x\n",(*pc)->pid,(*pc)->ptrace_status); 
		*status = (*pc)->ptrace_status;
		return (*pc)->pid;
	} else
		return 0;
}

int ptrace_hook_sysout(struct pcb *pc)
{
	/*if (pc->ptrace_pp != NULL) 
		 printk("ptrace_hook_sysout %d %x %x T%d SC%d\n",pc->pid,pc->ptrace_status,pc->ptrace_request,
		 (pc->ptrace_pp)?pc->ptrace_pp->pid:-1,getscno(pc));*/
	if (pc->ptrace_pp != NULL &&
			(pc->ptrace_request & PTRACE_STATUS_SYSCALL) &&
			(pc->ptrace_request & PTRACE_STATUS_SYSOUT)) {
		pcblist_enqueue(&pc->ptrace_pp->ptrace_notify_head, pc);
		if (pc->ptrace_pp->ptrace_waitpid < 0 || pc->ptrace_pp->ptrace_waitpid == pc->pid) {
			pc->ptrace_pp->ptrace_waitpid = 0;
			sc_resume(pc->ptrace_pp);
		} else
			r_kill(pc->ptrace_pp->pid,SIGCHLD);
		return 1;
	} else
		return 0;
}

int wrap_out_ptrace(int sc_number,struct pcb *pc)
{
#ifdef _VIEWOS_KM
	return STD_BEHAVIOR;
#else
	putrv(pc->retval,pc);
	if (pc->retval < 0)
		puterrno(pc->erno,pc);
	return SC_MODICALL;
#endif
}

static inline int stripstatus(struct pcb *pc, int status)
{
	if (WIFSTOPPED(status) && (WSTOPSIG(status) == (0x80 | SIGTRAP))) {
		if (!(pc->ptrace_options & PTRACE_O_TRACESYSGOOD))
			return status & ~0x8000;
	}
	return status;
}

int wrap_in_waitpid(int sc_number,struct pcb *pc,
		struct ht_elem *hte, sysfun um_syscall)
{	
#ifdef _VIEWOS_KM
	return STD_BEHAVIOR;
#else
	if (!ptraceemu)
		return STD_BEHAVIOR;
	else {
		pid_t pid=pc->sysargs[0];
		long pstatus=pc->sysargs[1];
		long options=pc->sysargs[2];
		struct pcb *w4pcb=NULL;
		//printk("waitpid %d %d %x %d\n",pc->pid,pid,options,pc->ptrace_nterminated);
		if (pc->ptrace_notify_head != NULL) {/*pending ptrace notifications*/
			struct pcb *wpc=pcblist_dequeue(&pc->ptrace_notify_head);
			int status=stripstatus(pc, wpc->ptrace_status);
			pc->retval = wpc->pid;
			ustoren (pc, pstatus, sizeof(long), &status);
			pc->signum = SIGCHLD;
			// printk("pending ptrace %d %x -> %d\n",wpc->pid,wpc->ptrace_status,pc->pid);
			return SC_FAKE;
		}
		if (pid >= 0)
			w4pcb=pid2pcb(pid);
		else
			w4pcb=NULL;
		if (w4pcb && w4pcb->pp != pc) {
			pc->retval = -1;
			pc->erno = ECHILD;
			//printk("NO SUCH CHILD ERR %d (getpid=%d) nchildren %d\n",pid,pc->pid,pc->ptrace_nchildren);
			return SC_FAKE;
		}
		else if (pc->ptrace_nterminated > 0 &&
				(w4pcb == NULL ||
				 w4pcb->ptrace_request & PTRACE_STATUS_TERMINATED)) {
			pc->ptrace_waitpid = 0;
			pc->ptrace_nterminated--;
			pc->ptrace_nchildren--;
			//printk("pending ptrace terminated\n");
			return STD_BEHAVIOR;
		} else if ( pc->ptrace_nchildren==0 ||
				(pid >= 0 && w4pcb == NULL)) {
			pc->retval = -1;
			pc->erno = ECHILD;
			//printk("NO SUCH CHILD %d (getpid=%d) nchildren %d\n",pid,pc->pid,pc->ptrace_nchildren);
			return SC_FAKE;
		} else if (options & WNOHANG) {
			pc->retval = pc->erno = 0;
			//printk("UM_NOHANG\n");
			return SC_FAKE;
		} else {
			//printk("UM_SUSPENDED\n");
			pc->ptrace_waitpid = pid;
			return SC_SUSPENDED;
		}
	}
#endif
}

int wrap_in_waitid(int sc_number,struct pcb *pc,
		struct ht_elem *hte, sysfun um_syscall)
{
#ifdef _VIEWOS_KM
	return STD_BEHAVIOR;
#else
	if (!ptraceemu) 
		return STD_BEHAVIOR;
	else {
		//printk("waitid \n");
		pc->retval = -1;
		pc->erno = ENOSYS;
		return SC_FAKE;
	}
#endif
}

void um_ptrace_addproc(struct pcb *pc,int flags,int npcbflag)
{
	if (!npcbflag) {
		pc->ptrace_pp=NULL;
		pc->ptrace_notify_head=NULL;
		pc->ptrace_ntraced=0;
		pc->ptrace_status=0;
		pc->ptrace_request=0;
		pc->ptrace_options=0;
		pc->ptrace_nchildren=0;
		pc->ptrace_nterminated=0;
		pc->ptrace_waitpid=0;
#ifndef _VIEWOS_KM
		if (ptraceemu) {
			if (pc->pp != pc)
				pc->pp->ptrace_nchildren++;
			// printk("um_ptrace_addproc %d %x\n",pc->pid,flags);
			if (pc->pp->ptrace_pp != NULL) {
				if (flags & CLONE_PTRACE) {
					pc->ptrace_pp = pc->pp->ptrace_pp;
					pc->ptrace_pp->ptrace_ntraced++;
					pc->ptrace_request |= PTRACE_STATUS_SYSOUT;
					if (secretdebug)
						printk("[%d] CLONED TRACED PROCESS %d p%d t%d\n",getpid(),pc->pid,pc->pp->pid,pc->ptrace_pp->pid);
				}
			}
		}
#endif
	}
}

void um_ptrace_delproc(struct pcb *pc,int status,int npcbflag)
{
#ifndef _VIEWOS_KM
	if (!npcbflag && ptraceemu) {
		pc->ptrace_request |= PTRACE_STATUS_TERMINATED;
		//printk("> NOTIFY !!!!!!!!!! %d %x\n",pc->pid,status);
		if (pc->ptrace_pp != NULL) {
			pc->ptrace_pp->ptrace_ntraced--;
		}
		if (pc->pp != NULL && pc->pp != pc) {
			//printk("Ptrace TERMINATED PROCESS %d\n",pc->pid);
			pc->pp->ptrace_nterminated++;
			if (pc->pp->ptrace_waitpid < 0 || pc->pp->ptrace_waitpid == pc->pid) {
				/*printk("process %d terminated notify %d T%d\n",pc->pid, pc->pp->pid,
				(pc->ptrace_pp)?pc->ptrace_pp->pid:-1);*/
				pc->pp->ptrace_waitpid = 0;
				sc_resume(pc->pp);
			}
		}
	}
#endif
}

#endif
