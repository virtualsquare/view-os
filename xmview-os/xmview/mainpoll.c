/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   Mainpoll: management of the main event ppoll
 *
 *   Copyright 2006 Renzo Davoli University of Bologna - Italy
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
 */
#include <poll.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <config.h>
#include "defs.h"
#include "services.h"

#define STEP_SIZE_POLLFD_TABLE 8

static struct pollfd *gpollfd;
static struct pollext **pollext;
static int gnfds,maxgnfds;
static int bqsignaled;
#ifndef _VIEWOS_KM
static int bqpipe[2];
#endif

struct pollext {
	void (*fun)(void *);
	void *arg;
	int persistent;
};

static struct blockq **blockq;
static int gnbq,maxbq;

struct blockq {
	struct pcb *pc;
	void (*fun)(struct pcb *);
};

static int umviewmainpid;
static void restart_main_loop(void)
{
	r_kill(umviewmainpid,SIGUSR1);
}

void bq_add(void (*fun)(struct pcb *), struct pcb *pc)
{
	assert(pc->pollstatus != READY);
	if (gnbq >= maxbq) {
		maxbq += STEP_SIZE_POLLFD_TABLE;
		blockq = realloc(blockq, maxbq * sizeof(struct blockq *));
		assert (blockq != 0);
	}
	blockq[gnbq]=malloc(sizeof(struct blockq));
	blockq[gnbq]->pc=pc;
	blockq[gnbq]->fun = fun;
	gnbq++;
}

void bq_signal(struct pcb *pc)
{
	assert(pc);
	pc->pollstatus=WAKE_ME_UP;
	restart_main_loop();
}

int bq_pidwake(long pid,int signum)
{
	int i;
	for (i=0;i<gnbq;i++)
		if (pid == blockq[i]->pc->pid) {
			blockq[i]->pc->flags |= PCB_SIGNALED;
			blockq[i]->pc->signum = signum;
			bq_signal(blockq[i]->pc);
			return 1;
		}
	return 0;
}

void bq_terminate(struct pcb *pc)
{
	pc->pollstatus=TERMINATED;
	restart_main_loop();
}

static void bq_try()
{
	int i,j;
	for (i=0,j=0;i<gnbq;i++)
	{
		switch (blockq[i]->pc->pollstatus) {
			case WAKE_ME_UP:
				blockq[i]->fun(blockq[i]->pc);
			case TERMINATED:
				free(blockq[i]);
				break;
			default:
				if (j < i)
					blockq[j]=blockq[i];
				j++;
				break;
		}
	}
	gnbq=j;
}

void bq_wake(int signal)
{
	bqsignaled=1;
}

void bq_ppolltry()
{
	if (bqsignaled) {
		bqsignaled=0;
		bq_try();
	}
}

/* add a callback related to a fd */
void mp_add(int fd, short events, void (*fun)(void *), void *arg, int persistent)
{
	//printk("mp_add %d %p\n",fd,arg);
	if (gnfds >= maxgnfds) {
		maxgnfds += STEP_SIZE_POLLFD_TABLE;
		gpollfd = realloc(gpollfd,maxgnfds * sizeof(struct pollfd));
		pollext = realloc(pollext, maxgnfds * sizeof(struct pollext *));
		assert (gpollfd != NULL && pollext != NULL);
	}
	gpollfd[gnfds].fd=fd;
	gpollfd[gnfds].events=events;
	gpollfd[gnfds].revents=0;
	pollext[gnfds]=malloc(sizeof(struct pollext));
	assert (pollext[gnfds] != NULL);
	pollext[gnfds]->fun=fun;
	pollext[gnfds]->arg=arg;
	pollext[gnfds]->persistent=persistent;
	gnfds++;
}

/* delete a callback related to a fd */
void mp_del(int fd,void *arg)
{
	int i;
	//printk("mp_del %d %p\n",fd,arg);
	for (i=0;i<gnfds;i++)
		if (gpollfd[i].fd == fd && pollext[i]->arg == arg)
			break;
	if (i<gnfds) {
		pollext[i]->fun=NULL;
		/*
			 printk("FOUND\n");
			 free(pollext[i]);
			 memmove(gpollfd+i,gpollfd+(i+1),(gnfds-(i+1))*sizeof(struct pollfd));
			 memmove(pollext+i,pollext+(i+1),(gnfds-(i+1))*sizeof(struct pollext *));
			 gnfds--;
			 */
	}
}

static void mp_pack()
{
	int i,j;
	for (i=0,j=0;i<gnfds;i++) {
		if (pollext[i]->fun == NULL) {
			free(pollext[i]);
		} else {
			if (j < i) {
				gpollfd[j]=gpollfd[i];
				pollext[j]=pollext[i];
			}
			j++;
		}
	}
	gnfds=j;
}

/* newer linux-es use ppoll */
int mp_ppoll( const sigset_t *sigmask)
{
	int rv;
	int i;

	//printk("mp_ppoll %d\n",gnfds);
	/* if there are just signals to wait use sigsuspend instead of ppoll */
	if (gnfds==0) {
		rv=r_sigsuspend(sigmask);
	} else {
		rv=r_ppoll(gpollfd,gnfds,NULL,sigmask,_KERNEL_SIGSET_SIZE);
		if (rv < 0 && errno != EINTR)
			printk("ppoll ERR %s\n",strerror(errno));
#if 0
		if (gnfds>0)
			printk("mp_rv (%d,%d,%d) %d %s\n",
					gpollfd[0].fd,
					gpollfd[0].events,
					gpollfd[0].revents,
					rv,strerror(errno));
		if (rv<0 && gnfds>0) {
			struct stat buf;
			int x=fstat(gpollfd[0].fd,&buf);
			printk("%d %d\n",x,buf.st_mode);
		}
#endif
		/* callbacks for file events */
		for (i=0; rv>0; i++) {
			assert(i<gnfds);
			//printk("mp_ppoll awake %d\n",i);
			if (gpollfd[i].revents)	{
				rv--;
				if (pollext[i]->fun) {
					pollext[i]->fun(pollext[i]->arg);
					if (!pollext[i]->persistent)
						pollext[i]->fun=NULL;
				}
			}
		}
		mp_pack();
	}
	bq_ppolltry();
	return rv;
}

void mainpoll_addproc(struct pcb *pc,int flags,int npcbflag)
{
	pc->pollstatus=READY;
}

void mainpoll_delproc(struct pcb *pc,int flags,int npcbflag)
{
}

void mainpoll_init(int want_ppoll)
{
	struct sigaction sa;
	sigset_t blockusr1;
	umviewmainpid=r_getpid();
	sigemptyset(&blockusr1);
	sigaddset(&blockusr1,SIGUSR1);
	r_sigprocmask(SIG_BLOCK,&blockusr1,NULL);
	sigfillset(&sa.sa_mask);
	sa.sa_handler = bq_wake;
	sa.sa_flags = 0;
	r_sigaction(SIGUSR1, &sa, NULL);
}
