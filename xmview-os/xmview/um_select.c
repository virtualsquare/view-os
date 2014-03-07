/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   um_select: select management (partial VM can have some files managed
 *   by the hosting computer kernel and some by the partial VM).
 *   
 *   Copyright 2005,2006 Renzo Davoli University of Bologna - Italy
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
#include <string.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/poll.h>
#include <sys/epoll.h>
#include <sys/uio.h>
#include <asm/ptrace.h>
#include <asm/unistd.h>
#include <linux/net.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <config.h>
#include "defs.h"
#include "umproc.h"
#include "services.h"
#include "hashtab.h"
#include "um_services.h"
#include "sctab.h"
#include "um_select.h"
#include "scmap.h"
#include "utils.h"
#include "capture.h"
#include "mainpoll.h"

#ifndef __FDELT
#ifndef __NFDBITS
#define __NFDBITS       (8 * sizeof(unsigned long))
#endif
#define __FDELT(d)      ((d) / __NFDBITS)
#endif

enum {RX, WX, XX} stype;

struct pendingdata {
	int fd;
	short how;
};

struct seldata {
	/* one of the lfd from the last select(), the process is waiting
	 * at the other end of this named pipe */
	int lfd;
	int len;
	struct pendingdata *pending;
//	fd_set origfds[3];
};

#define WAKEONRFD 0  /*there are rfd in the set*/
#define WAKEONCB 1   /*only callbacks pending */
#define WAKEUP 2     /*the process must wake up!*/

static void cleanup_pending(struct pcb *pc)
{
	epoch_t oldepoch=um_setnestepoch(0);
  struct seldata *sd=pc->selset;
	if (sd) {
		int i;
		assert(sd->pending);
		for (i=0; i<sd->len; i++) {
			struct ht_elem *hte=ht_fd(pc->fds,sd->pending[i].fd,1);
			sysfun local_event_subscribe=ht_event_subscribe(hte);
			int sfd=fd2sfd(pc->fds,sd->pending[i].fd);
			assert(local_event_subscribe != NULL && sfd >= 0);
			local_event_subscribe(NULL,pc,sfd,sd->pending[i].how);
			um_setnestepoch(oldepoch);
		}
		pc->selset=NULL;
		bq_terminate(pc);
		free(sd->pending);
		free(sd);
	}
}

/* how is a bit field: look CB_R, CB_W */
/* check for possibly blocking operation.
 * e.g. READ or recvmsg can block if there is no pending data
 */
static void suspend_signaled(struct pcb *pc)
{
	epoch_t oldepoch=um_setnestepoch(0);
	struct seldata *sd=pc->selset;
	if (!sd)
		printk("suspend_signaled warning %d\n",pc->pid);
	assert(sd);
	assert(sd->pending);
	struct ht_elem *hte=ht_fd(pc->fds,sd->pending[0].fd,1);
	sysfun local_event_subscribe=ht_event_subscribe(hte);
	int sfd=fd2sfd(pc->fds,sd->pending[0].fd);
	assert(local_event_subscribe != NULL && sfd >= 0);
	local_event_subscribe(NULL,pc,sfd,sd->pending[0].how);
	pc->selset=NULL;
	um_setnestepoch(oldepoch);
	free(sd->pending);
	free(sd);
	sc_resume(pc);
}

int check_suspend_on(struct pcb *pc, int fd, int how)
{
	epoch_t oldepoch=um_setnestepoch(0);
	struct ht_elem *hte=ht_fd(pc->fds,fd,1);
	int sfd;
	/*int i;*/
	assert (pc->selset == NULL);
	/* do not suspend signaled processes */
	if (pc->flags & PCB_SIGNALED) {
		pc->flags &= ~PCB_SIGNALED;
		pc->retval=-1;
		pc->erno=EINTR;
		//pc->retval=0;
		//pc->erno=0;
		return SC_CALLONXIT;
	}
	/* check the fd is managed by some service and gets its service fd (sfd) */
	if (hte != NULL && (sfd=fd2sfd(pc->fds,fd)) >= 0) {
		sysfun local_event_subscribe;
		int flfl=fd_getflfl(pc->fds,fd);
		if ((local_event_subscribe=ht_event_subscribe(hte)) != NULL &&
				!(flfl & O_NONBLOCK)) {
			bq_block(pc);
			if (local_event_subscribe(bq_signal, pc, sfd, how) == 0)
			{
				struct seldata *sd=malloc(sizeof(struct seldata));
				/*printk("check_suspend_on_block %d %x\n",sfd,how);*/
				sd->pending=malloc(sizeof(struct pendingdata));
				sd->len=1;
				sd->lfd=-1;
				sd->pending[0].fd=fd;
				sd->pending[0].how=how;
				pc->selset=sd;
				bq_add(suspend_signaled,pc);
				um_setnestepoch(oldepoch);
				return SC_SUSPENDED;
			} else
				bq_unblock(pc);
		}
	}
	um_setnestepoch(oldepoch);
	return STD_BEHAVIOR;
}

/* optimization: copy only the useful part given the max fd */
static void getfdset(long addr,struct pcb* pc, int max, fd_set *lfds)
{
	FD_ZERO(lfds);
	if (addr != umNULL)
		umoven(pc,addr,(__FDELT(max)+1)*sizeof(__fd_mask),lfds);
}

static void putfdset(long addr, struct pcb* pc, int max, fd_set *lfds)
{
	if (addr != umNULL)
		ustoren(pc,addr,(__FDELT(max)+1)*sizeof(__fd_mask),lfds);
}

static void selectpoll_signal(struct pcb *pc)
{
	struct seldata *sd=pc->selset;
	if (!sd)
		printk("sd err %p\n",sd);
	else if (sd->lfd < 0)
		printk("lfd err\n",sd->lfd);
	else {
		assert(sd->lfd >= 0);
		lfd_signal(sd->lfd);
	}
}

static short select2poll[]={POLLIN,POLLOUT,POLLPRI};

int wrap_in_select(int sc_number,struct pcb *pc,
		struct ht_elem *hte, sysfun um_syscall)
{
	register int n=pc->sysargs[0];
	int i,fd,count;
	long pfds[3];
	fd_set wfds[3]; /* modified waiting fds virtual files are R-waiting on the FIFOs */ 
	epoch_t oldepoch=um_setnestepoch(0);
	/*long ptimeout=pc->sysargs[4];
	struct timeval *lptimeout;
	struct timeval ltimeout;*/
	//printk("SELECT %d PID %d\n",sc_number,pc->pid);

	/* Does two things:
	 * - copies the sets passed as arguments to the syscall in lfds[i]
	 * - copies the same data on wfds[i] */
	for (i=0;i<3;i++) {
		pfds[i]=pc->sysargs[i+1];
		getfdset(pfds[i],pc,n,&wfds[i]);
		//dumpfdset(n,stype_str[i],&wfds[i]);
	}

	/* count how many virtual file are there */
	for(fd=0,count=0;fd<n;fd++) { 
		short how;
		for (i=0,how=0;i<3;i++) {
			if (FD_ISSET(fd,&wfds[i]))
				//how |= 1<<i;
				how |= select2poll[i];
		}
		if (how) {
			struct ht_elem *hte=ht_fd(pc->fds,fd,0);
			if (hte != NULL && (fd2sfd(pc->fds,fd)) >= 0
					&& (ht_event_subscribe(hte)) != NULL)
				count++;
		}
	}

	/* no virtual file: nothing to do here */
	if (count == 0) {
		return STD_BEHAVIOR;
	} else {
		/* ok, let's do the hard work */
		struct seldata *sd=(struct seldata *)malloc(sizeof(struct seldata));
		int signaled=0;
		sd->pending=malloc(sizeof(struct pendingdata) * count);
		sd->len=count;
		sd->lfd=-1;
		pc->selset=sd;
		for(fd=0,count=0;fd<n;fd++) {
			short how;
			for (i=0,how=0;i<3;i++) {
				if (FD_ISSET(fd,&wfds[i]))
					//how |= 1<<i;
					how |= select2poll[i];
			}
			if (how) {
				struct ht_elem *hte=ht_fd(pc->fds,fd,1);
				if (hte != NULL) {
					int sfd=fd2sfd(pc->fds,fd);
					sysfun local_event_subscribe=ht_event_subscribe(hte);
					if (sfd >= 0 && local_event_subscribe) {
						/* virtual file: split components */
						/* how encodes the requested waiting flags for event_subscribe */
						/* wfds gets modified for the select syscall of the usermode process*/
						int lfd=fd2lfd(pc->fds,fd);
						sd->pending[count].fd = fd;
						sd->pending[count].how = how;
						if (sd->lfd < 0) sd->lfd = lfd;
						FD_SET(fd,&wfds[RX]);
						FD_CLR(fd,&wfds[WX]); /* needed? maybe no*/
						FD_CLR(fd,&wfds[XX]); /* needed? maybe no*/
						if (signaled==0 && local_event_subscribe(selectpoll_signal, pc, sfd, how) > 0) {
							/* if local_event_subscribe returned with a nonzero value, it
							 * means there's *already* data! */
							signaled++;
							lfd_signal(lfd);
						}
						count++;
					}
				}
				um_setnestepoch(oldepoch);
			}
		}
		for (i=0;i<3;i++)  
			putfdset(pfds[i],pc,n,&wfds[i]);
		return SC_CALLONXIT;
	}
}
		
int wrap_out_select(int sc_number,struct pcb *pc)
{
	struct seldata *sd=pc->selset;
	if (sd != NULL) {
		epoch_t oldepoch=um_setnestepoch(0);
		register int n=pc->sysargs[0];
		long pfds[3];
		fd_set lfds[3]; /* local copy of the signaled SC fds */
		int i,j,fd;
		pc->retval=getrv(pc);
		if (pc->retval >= 0) {
			for (i=0;i<3;i++) {
				pfds[i]=pc->sysargs[i+1];
				getfdset(pfds[i],pc,n,&lfds[i]);
			}
		}
		for (i=0; i<sd->len; i++) {
			struct ht_elem *hte=ht_fd(pc->fds,sd->pending[i].fd,1);
			sysfun local_event_subscribe=ht_event_subscribe(hte);
			int sfd=fd2sfd(pc->fds,sd->pending[i].fd);
			assert(local_event_subscribe != NULL && sfd >= 0);
			int howret=local_event_subscribe(NULL,pc,sfd,sd->pending[i].how);
			int lfd=fd2lfd(pc->fds,sd->pending[i].fd);
			lfd_delsignal(lfd);
			for (j=0;j<3;j++) {
				//if (howret & 1<<j) 
				if(howret & select2poll[j])
					FD_SET(sd->pending[i].fd,&lfds[j]);
				else
					FD_CLR(sd->pending[i].fd,&lfds[j]);
			}
			um_setnestepoch(oldepoch);
		}
		pc->selset=NULL;
		/* retval must be evaluated again */
		if (pc->retval >= 0) {
			for(fd=0,pc->retval=0;fd<n;fd++) {
				if (FD_ISSET(fd,&lfds[0]) || FD_ISSET(fd,&lfds[1]) || FD_ISSET(fd,&lfds[1]))
					pc->retval++;
			}
			for (i=0;i<3;i++) {
				putfdset(pfds[i],pc,n,&lfds[i]);
			}
			putrv(pc->retval,pc);
		}
		free(sd->pending);
		free(sd);
	}
	return SC_MODICALL;
}

int wrap_in_poll(int sc_number,struct pcb *pc,
		struct ht_elem *hte, sysfun um_syscall)
{
	struct pollfd *ufds; /*local copy*/
	unsigned int nfds=pc->sysargs[1];
	unsigned long pufds=pc->sysargs[0];
	int i,count;
	epoch_t oldepoch=um_setnestepoch(0);
	int rv;

	ufds=lalloca(nfds*sizeof(struct pollfd));
	umoven(pc,pufds,nfds*sizeof(struct pollfd),ufds);

	/* count how many virtual file are there */
	for(i=0,count=0;i<nfds;i++) {
		int fd=ufds[i].fd;
		struct ht_elem *hte=ht_fd(pc->fds,fd,1);
		if (ufds[i].events && hte != NULL && fd2sfd(pc->fds,fd) >= 0 &&
				ht_event_subscribe(hte))
			count++;
	}
	/* no virtual file: nothing to do here */
	if (count == 0) {
		rv = STD_BEHAVIOR;
	} else {
		/* ok, let's do the hard work */
		struct seldata *sd=(struct seldata *)malloc(sizeof(struct seldata));
		int signaled=0;
		sd->pending=malloc(sizeof(struct pendingdata) * count);
		sd->len=count;
		sd->lfd= -1;
		pc->selset=sd;
		for(i=0,count=0;i<nfds;i++) {
			if (ufds[i].events) {
				int fd=ufds[i].fd;
				struct ht_elem *hte=ht_fd(pc->fds,fd,1);
				if (hte != NULL) {
					int sfd=fd2sfd(pc->fds,fd);
					sysfun local_event_subscribe=ht_event_subscribe(hte);
					if (sfd >= 0 && local_event_subscribe) {
						int lfd=fd2lfd(pc->fds,fd);
						if (sd->lfd < 0) sd->lfd=lfd;
						sd->pending[count].fd = fd;
						sd->pending[count].how = ufds[i].events;
						ufds[i].events=POLLIN;
						//printk("POLL %d %x\n",sfd,sd->pending[count].how);
						if (signaled==0 && local_event_subscribe(selectpoll_signal, pc, sfd, sd->pending[count].how) > 0) {
							signaled++;
							lfd_signal(lfd);
						}
						count++;
					}
				}
				um_setnestepoch(oldepoch);
			}
		}
		ustoren(pc,pufds,nfds*sizeof(struct pollfd),ufds);
		rv = SC_CALLONXIT;
	}
	lfree(ufds,nfds*sizeof(struct pollfd));
	return rv;
}

int wrap_out_poll(int sc_number,struct pcb *pc)
{
	struct seldata *sd=pc->selset;
	if (sd != NULL) {
		epoch_t oldepoch=um_setnestepoch(0);
		struct pollfd *ufds;
		unsigned long pufds=pc->sysargs[0];
		unsigned int nfds=pc->sysargs[1];
		int i,j;
		pc->retval=getrv(pc);
		ufds=lalloca(nfds*sizeof(struct pollfd));
		umoven(pc,pufds,nfds*sizeof(struct pollfd),ufds);
		if (pc->retval >= 0) {
			pc->retval=0;
			for(i=0,j=0;i<nfds;i++) {
				if(j<sd->len && ufds[i].fd == sd->pending[j].fd) {/* virtual file */
					struct ht_elem *hte=ht_fd(pc->fds,sd->pending[j].fd,1);
					sysfun local_event_subscribe=ht_event_subscribe(hte);
					int sfd=fd2sfd(pc->fds,sd->pending[j].fd);
					assert(local_event_subscribe != NULL && sfd >= 0);
					int lfd=fd2lfd(pc->fds,sd->pending[j].fd);
					int howret=local_event_subscribe(NULL,pc ,sfd,sd->pending[j].how);
					//printk("POLLOUT %d %x %x\n",sfd,sd->pending[j].how,howret);
					lfd_delsignal(lfd);
					ufds[i].events=sd->pending[j].how;
					ufds[i].revents=howret;
					/* XXX ERR/HUP ??? */
					um_setnestepoch(oldepoch);
					j++;
				} 
				if (ufds[i].revents)
					pc->retval++;
			}
			pc->selset=NULL;
			ustoren(pc,pufds,nfds*sizeof(struct pollfd),ufds);
			putrv(pc->retval,pc);
			free(sd->pending);
			free(sd);
		} else {
			for(i=0,j=0;i<nfds && j<sd->len;i++) {
				if(ufds[i].fd == sd->pending[j].fd) {/* virtual file */
					ufds[i].events=sd->pending[j].how;
					ufds[i].revents=0;
					j++;
				}
				ustoren(pc,pufds,nfds*sizeof(struct pollfd),ufds);
			}
			cleanup_pending(pc);
		}
		lfree(ufds,nfds*sizeof(struct pollfd));
	}
	return SC_MODICALL;
}

#ifdef _UM_EPOLL

/* The support of epoll is still under development */

static char *epoll_tag = "EP";

int wrap_in_epoll_create(int sc_number,struct pcb *pc,
		    struct ht_elem *hte, sysfun um_syscall)
{
	int flags=0;
#if __NR_epoll_create1 != __NR_epoll_create
	if (sc_number== __NR_epoll_create1)
		flags = pc->sysargs[0];
#endif
	/* Linux: EPOLL_CLOEXEC==O_CLOEXEC */
	flags &= (EPOLL_CLOEXEC);
	//printk("wrap_in_epoll_create %x\n",flags);
	pc->retval=lfd_open(NULL,-1,epoll_tag,flags,0);
	return SC_CALLONXIT;
}

int wrap_out_epoll_create(int sc_number,struct pcb *pc)
{
	if (pc->retval >= 0) {
		int fd=getrv(pc);
		//printk("wrap_out_epoll_create %d\n",fd);
		if (fd >= 0) 
			lfd_register(pc->fds,fd,pc->retval);
		else
			lfd_close(pc->retval);
	} else {
		putrv(pc->retval,pc);
		puterrno(pc->erno,pc);
	}
	return SC_MODICALL;
}

int wrap_in_epoll_ctl(int sc_number,struct pcb *pc,
		    struct ht_elem *hte, sysfun um_syscall)
{
	int epfd=pc->sysargs[0];
	int op=pc->sysargs[1];
	int fd=pc->sysargs[2];
	long pevent=pc->sysargs[3];
	char *tag=fd_getpath(pc->fds,epfd);
	struct lfd_epoll_item *ep_item;
	if (tag==NULL) return STD_BEHAVIOR;
	//printk("wrap_in_epoll_ctl %d %d %s %p %p\n",op,fd,tag,tag,epoll_tag);
	switch (op) {
		case EPOLL_CTL_ADD:
			ep_item=malloc(sizeof(struct lfd_epoll_item));
			if (ep_item) {
				struct epoll_event user_event;
				struct ht_elem *hte=ht_fd(pc->fds,fd,1);
				umoven(pc,pevent,sizeof(struct epoll_event),&user_event);
				ep_item->fd=fd;
				ep_item->event=user_event;
				user_event.data.ptr = ep_item;
				if (hte != NULL && fd2sfd(pc->fds,fd) >= 0 && ht_event_subscribe(hte))
					user_event.events = EPOLLIN;
				ustoren(pc,pevent,sizeof(struct epoll_event),&user_event);
				/*printk("ADD real_data = %llx our_data = %llx ptr = %p\n",
						ep_item->event.data.u64, user_event.data.u64, user_event.data.ptr);*/
			}
			pc->retval = (long) ep_item;
			break;
		case EPOLL_CTL_MOD:
			ep_item=malloc(sizeof(struct lfd_epoll_item));
			if (ep_item) {
				struct epoll_event user_event;
				struct ht_elem *hte=ht_fd(pc->fds,fd,1);
				umoven(pc,pevent,sizeof(struct epoll_event),&user_event);
				ep_item->fd=fd;
				ep_item->event=user_event;
				user_event.data.ptr = lfd_epoll_search(pc->fds, epfd, fd);
				if (hte != NULL && fd2sfd(pc->fds,fd) >= 0 && ht_event_subscribe(hte))
					user_event.events = EPOLLIN;
				ustoren(pc,pevent,sizeof(struct epoll_event),&ep_item->event);
			}
			break;
		case EPOLL_CTL_DEL:
			pc->retval = (long) NULL;
			break;
	}
	return SC_CALLONXIT;
}

int wrap_out_epoll_ctl(int sc_number,struct pcb *pc)
{
	int epfd=pc->sysargs[0];
	int op=pc->sysargs[1];
	int fd=pc->sysargs[2];
	long pevent=pc->sysargs[3];
	struct lfd_epoll_item *ep_item=(struct lfd_epoll_item *)pc->retval;
	int rv=getrv(pc);
	//printk("wrap_out_epoll_ctl %d %d\n",rv,fd);
	if (rv >= 0) {
		switch (op) {
			case EPOLL_CTL_ADD:
				if (ep_item) {
					lfd_epoll_add(pc->fds, epfd, ep_item);
					/*printk("ADD reset real data %llx\n", ep_item->event.data.u64);*/
					ustoren(pc,pevent,sizeof(struct epoll_event *),&ep_item->event);
				}
				break;
			case EPOLL_CTL_MOD: 
				if (ep_item) {
					struct lfd_epoll_item *ep_mod_item = lfd_epoll_search(pc->fds, epfd, fd);
					if (ep_mod_item != NULL) ep_mod_item->event = ep_item->event;
					ustoren(pc,pevent,sizeof(struct epoll_event *),&ep_item->event);
					free(ep_item);
				}
				break;
			case EPOLL_CTL_DEL:
				lfd_epoll_del(pc->fds, epfd, fd);
		}
	} else {
		if (ep_item != NULL)
			free(ep_item);
	}
	return SC_MODICALL;
}

static void epoll_signal (void *arg)
{
	int lfd=(int)arg;
	//printk("epoll_signal ---------> lfd %d\n",lfd);
	lfd_signal(lfd);
}

static void wrap_in_epoll_wait_test(struct lfd_epoll_item *ep_item, void *arg)
{
	struct pcb *pc=arg;
	int fd=ep_item->fd;
	struct ht_elem *hte=ht_fd(pc->fds,fd,1);
	if (hte != NULL) {
		int sfd=fd2sfd(pc->fds,fd);
		sysfun local_event_subscribe=ht_event_subscribe(hte);
		if (sfd >= 0 && local_event_subscribe) {
			int lfd=fd2lfd(pc->fds,fd);
			if (local_event_subscribe(epoll_signal, (void *)lfd, sfd, ep_item->event.events) > 0) {
				lfd_signal(lfd);
			}
		}
	}
}

int wrap_in_epoll_wait(int sc_number,struct pcb *pc,
		    struct ht_elem *hte, sysfun um_syscall)
{
	int epfd = pc->sysargs[0];
	char *tag = fd_getpath(pc->fds,epfd);
	if (tag == NULL) return STD_BEHAVIOR;
	lfd_epoll_forall(pc->fds, epfd, wrap_in_epoll_wait_test, pc);
	//printk("wrap_in_epoll_wait\n");
	return SC_CALLONXIT;
}

static void wrap_out_epoll_wait_unsubscribe(struct lfd_epoll_item *ep_item, void *arg)
{
	struct pcb *pc=arg;
	int fd=ep_item->fd;
	struct ht_elem *hte=ht_fd(pc->fds,fd,1);
	if (hte != NULL) {
		int sfd=fd2sfd(pc->fds,fd);
		sysfun local_event_subscribe=ht_event_subscribe(hte);
		if (sfd >= 0 && local_event_subscribe) {
			int lfd=fd2lfd(pc->fds,fd);
			local_event_subscribe(NULL, (void *)lfd, sfd, ep_item->event.events); 
		}
	}
}

int wrap_out_epoll_wait(int sc_number,struct pcb *pc)
{
	int epfd = pc->sysargs[0];
	long pevents = pc->sysargs[1];
	int maxevents = pc->sysargs[2];
	int size_events = maxevents * sizeof(struct epoll_event *);
	int nevents = getrv(pc);
	if (nevents > 0) {
		struct epoll_event *events=lalloca(size_events);
		if(events) {
			int i;
			umoven(pc,pevents,size_events,events);
			for (i = 0; i < nevents; i++) {
				struct lfd_epoll_item *ep_item = events[i].data.ptr;
				struct ht_elem *hte;
				//printk("wrap_out_epoll_wait reset from %p\n",ep_item);
				events[i].data = ep_item->event.data;
				hte=ht_fd(pc->fds,ep_item->fd,1);
				if (hte != NULL) {
					int sfd=fd2sfd(pc->fds,ep_item->fd);
					sysfun local_event_subscribe=ht_event_subscribe(hte);
					if (sfd >= 0 && local_event_subscribe) {
						int lfd=fd2lfd(pc->fds,ep_item->fd);
						events[i].events = local_event_subscribe(NULL, (void *)lfd, sfd, ep_item->event.events);
						lfd_delsignal(lfd);
					}
				}
				//printk("wrap_out_epoll_wait reset data %llx\n",events[i].data.u64);
			}
			ustoren(pc,pevents,size_events,events);
		}
		lfree(events,size_events);
	}
	lfd_epoll_forall(pc->fds, epfd, wrap_out_epoll_wait_unsubscribe, pc);
	//printk("wrap_out_epoll_wait\n");
	return SC_MODICALL;
}

#endif

void um_select_addproc(struct pcb *pc,int flags,int npcbflag)
{
	pc->selset=NULL;
}

void um_select_delproc(struct pcb *pc,int flags,int npcbflag)
{
	if (pc->selset)
		cleanup_pending(pc);
}
