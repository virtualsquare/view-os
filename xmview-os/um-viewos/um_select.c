/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   um_select: select management (partial VM can have some files managed
 *   by the hosting computer kernel and some by the partial VM).
 *   
 *   Copyright 2005 Renzo Davoli University of Bologna - Italy
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
#include <string.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/poll.h>
#include <sys/uio.h>
#include <asm/ptrace.h>
#include <asm/unistd.h>
#include <linux/net.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include "defs.h"
#include "umproc.h"
#include "services.h"
#include "um_services.h"
#include "sctab.h"
#include "um_select.h"
#include "scmap.h"
#include "utils.h"
#include "capture_sc.h"

/* pipe to wake up main */
static int wakeupmainfifo[2];
static int wakeupmainfifocount;

#define umNULL ((int) NULL)
static struct timeval timeout0={0,0};

enum {RX, WX, XX} stype;
struct seldata {
	/* maximum number of fd present in wrfds[0], wrfds[1], wrfds[2] */
	int rfdmax;
	/* one of the lfd from the last select(), the process is waiting
	 * at the other end of this named pipe */
	int a_random_lfd;
	/* [0] = write, [1] = read, [2] = exception */
	fd_set wrfds[3];
	int wakemeup;
	union {
		fd_set origfds[3];
		int *origevents;
	} sop;	/* select or poll */
};

#define WAKEONRFD 0  /*there are rfd in the set*/
#define WAKEONCB 1   /*only callbacks pending */
#define WAKEUP 2     /*the process must wake up!*/

char stype_str[]={'R','W','X'};

struct fillset {
	int *max;
	fd_set *wset;
};

#if 0
static void dumpfdset (int n,char s, fd_set *f)
{
	int i;
	printf("%c ",s);
	for (i=0;i<=n;i++) {
		if (FD_ISSET(i,f)) 
			printf("%d-",i); 
	}
	printf(" === ");
}
#endif

/* fills the fillset fsp with all the fds present in pc->data->selset, and
 * updates its 'max' accordingly */
void select_fill_wset_item(struct pcb *pc,struct fillset *fsp)
{
	struct pcb_ext *pcdata=(struct pcb_ext *)(pc->data);
	if (pcdata != NULL) {
		struct seldata *sd=pcdata->selset;
		if (sd != NULL) {
			//printf("select_fill_wset_item rfdmax=%d\n",sd->rfdmax);
			register int rfd;
			for (rfd=0;rfd<= sd->rfdmax;rfd++)
			{	/* main loop: three ifs are faster than a for */
				if (FD_ISSET(rfd,&sd->wrfds[RX])) FD_SET(rfd,&fsp->wset[RX]);
				if (FD_ISSET(rfd,&sd->wrfds[WX])) FD_SET(rfd,&fsp->wset[WX]);
				if (FD_ISSET(rfd,&sd->wrfds[XX])) FD_SET(rfd,&fsp->wset[XX]);
			}
			if (sd->rfdmax > *fsp->max) *fsp->max=sd->rfdmax;
		}
	}
}

int select_fill_wset(fd_set *wset)
{
	int max=wakeupmainfifo[0];
	struct fillset workfs;
	workfs.max=&max;
	workfs.wset=wset;
	FD_SET(wakeupmainfifo[0],&wset[RX]);
	if(wakeupmainfifo[0]>max) max=wakeupmainfifo[0];
	//printf("select_fill_wset start\n");
	forallpcbdo(select_fill_wset_item,&workfs);
	/*if (*max >= 0)
	  {
	  printf("fill max=%d   ",*max);
	  int i;
	  for (i=0;i<3;i++) {
	  dumpfdset(*max,stype_str[i],&wset[i]);
	  }
	  printf("\n");
	  } */
	return max;
}

void select_check_wset_item(struct pcb *pc,struct fillset *fsp)
{
	struct pcb_ext *pcdata=(struct pcb_ext *)(pc->data);
	if (pcdata != NULL) {
		struct seldata *sd=pcdata->selset;
		if (sd != NULL) {
			register int rfd;
			//printf("PID %d WUP %d\n",pc->pid,sd->wakemeup);
			for (rfd=0;rfd<= sd->rfdmax && sd->wakemeup==WAKEONRFD;rfd++)
			{	/* main loop: three 'if's are faster than a 'for' */
				if ((FD_ISSET(rfd,&fsp->wset[RX]) && FD_ISSET(rfd,&sd->wrfds[RX])) ||
						(FD_ISSET(rfd,&fsp->wset[WX]) && FD_ISSET(rfd,&sd->wrfds[WX])) ||
						(FD_ISSET(rfd,&fsp->wset[XX]) && FD_ISSET(rfd,&sd->wrfds[XX]))) {
					//printf("****************** signal reverse! PID %d %d\n",pc->pid,sd->a_random_lfd);
					sd->wakemeup=WAKEUP;
				}
			}
			if (sd->wakemeup==WAKEUP) {
				switch (pc->scno) {
					case __NR_select:
#if !defined(__x86_64__)
					case __NR__newselect:
#endif
					case __NR_poll:
						lfd_signal(sd->a_random_lfd); /*private lfd*/
						break;
					default: {
							 struct seldata *norace=pcdata->selset;
							 pcdata->selset = NULL;
							 free(norace);
						 }
						 //printf("RESUME %d %d\n",rfd,pc->pid);
						 sc_resume(pc);  /* SC_SUSPEND */
						 /* printf("soft resume \n");
						    lfd_signal(sd->a_random_lfd);
						    FD_CLR(rfd,&sd->wrfds[0]); */ /* no use to continue selecting already signalled files */
						 break;
				}
			}
		}
	}
}

static void inline wakeupmainfifo_signal()
{
	char x=0;
	if (wakeupmainfifocount==0) {
		wakeupmainfifocount=1;
		r_write(wakeupmainfifo[1],&x,1);
	}
}

static void select_wakeup_cb(int *wakeupvar)
{
	*wakeupvar=WAKEUP;
	wakeupmainfifo_signal();
}
	
void select_check_wset(int max,fd_set *wset)
{
	struct fillset workfs;
	char buf[256];
	if (FD_ISSET(wakeupmainfifo[0],wset)) {
		r_read(wakeupmainfifo[0],buf,256); /* NON BLOCKING */
		wakeupmainfifocount=0;
	}
	workfs.max=&max;
	workfs.wset=wset;
	//printf("select_check_wset start\n");
	forallpcbdo(select_check_wset_item,&workfs);
	//printf("select_check_wset end\n");
}

/* how is a bit field: look CB_R, CB_W, CB_X */
/* check for possibly blocking operation.
 * e.g. READ or recvmsg can block if there is no pending data
 */
int check_suspend_on(struct pcb *pc, struct pcb_ext *pcdata, int fd, int how)
{
	if (pcdata != NULL) {
		epoch_t oldepoch=um_getnestepoch();
		int sercode=service_fd(pcdata->fds,fd);
		int sfd;
		int rfd;
		int i;
		assert (pcdata->selset == NULL);
		/* check the fd is managed by some service and gets its service fd (sfd) */
		if (sercode != UM_NONE && (sfd=fd2sfd(pcdata->fds,fd)) >= 0) {
			sysfun local_select_register;
			if ((local_select_register=service_select_register(sercode)) == NULL) {
#if defined(__x86_64__)
				sysfun localselect=service_syscall(sercode,uscno(__NR_select));
#else
				sysfun localselect=service_syscall(sercode,uscno(__NR__newselect));
#endif
				/* use the standard "select" provided by the service. */
				if (localselect != NULL) {
					fd_set tfds[3];
					fd_set wrfds[3];
					rfd=sfd;
					for(i=0;i<3;i++) {
						FD_ZERO(&tfds[i]);
						FD_ZERO(&wrfds[i]);
						if (how & 1<<i) { /* CB_R=1 CB_W=2 CB_X=4 */
							FD_SET(sfd,&tfds[i]);
							FD_SET(rfd,&wrfds[i]);
						}
					}
					if (localselect(sfd+1,&tfds[RX],&tfds[WX],&tfds[XX],&timeout0,pc) == 0) 
					{
						struct seldata *sd=(struct seldata *)malloc(sizeof(struct seldata));
						sd->wakemeup=WAKEONRFD;
						for (i=0;i<3;i++) 
							sd->wrfds[i]=wrfds[i];
						sd->rfdmax=rfd;
						/*sd->a_random_lfd= -1;  not needed FOR SC_SUSPENDED*/
						/* needed FOR SC_SOFTSUSP*/
						sd->a_random_lfd=fd2lfd(pcdata->fds,fd);

						pcdata->selset=sd;
						//printf("Suspended %d %d %d\n",pc->pid,fd,sd->a_random_lfd);
						um_setepoch(oldepoch);
						return SC_SUSPENDED;
						//pc->retval=fd;
						//return SC_SOFTSUSP;
					}
				}
			} else {
				/* use a pro-active service.
				 * select register calls a predefined function when new data is available.  */
				struct seldata *sd=(struct seldata *)malloc(sizeof(struct seldata));
				sd->wakemeup=WAKEONCB;
				if (local_select_register(select_wakeup_cb, &(sd->wakemeup), sfd, how, pc) == 0)
				{
					sd->rfdmax = -1;
					sd->a_random_lfd=fd2lfd(pcdata->fds,fd);
					for (i=0;i<3;i++) 
						FD_ZERO(&sd->wrfds[i]); /* unuseful, can be omitted */
					pcdata->selset=sd;
					um_setepoch(oldepoch);
					return SC_SUSPENDED;
				} else
					free(sd);
			}
		}
		um_setepoch(oldepoch);
	}
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

int wrap_in_select(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		char sercode, sysfun um_syscall)
{
	register int n=pc->arg0;
	struct seldata *sd=(struct seldata *)malloc(sizeof(struct seldata));
	int i,fd,count,countcb,signaled;
	int a_random_lfd = -1;
	int pfds[3];
	int rfdmax = -1;
	fd_set lfds[3]; /* local copy of the SC fds */
	fd_set tfds[3]; /* test for virtual files (one by one)*/
	fd_set wfds[3]; /* modified waiting fds virtual files are R-waiting on the FIFOs */ 
	fd_set wrfds[3]; /* waiting *real* fds virtual file sets for the main loop*/ 
	long ptimeout=getargn(4,pc);
	struct timeval *lptimeout;
	struct timeval ltimeout;
	//printf("SELECT %d PID %d\n",sc_number,pc->pid);

	/* Does three things:
	 * - empties the wrfds[i] sets
	 * - copies the sets passed as arguments to the syscall in lfds[i]
	 * - copies the same data on wfds[i] */
	for (i=0;i<3;i++) {
		FD_ZERO(&wrfds[i]);
		pfds[i]=getargn(i+1,pc);
		getfdset(pfds[i],pc,n,&lfds[i]);
		wfds[i]=lfds[i];
		//dumpfdset(n,stype_str[i],&lfds[i]);
	}

	/* Copies the timeout parameter too */
	if (ptimeout != umNULL) {
		umoven(pc,ptimeout,sizeof(struct timeval),&ltimeout);
		lptimeout=&ltimeout;
		//printf("ltimeout=%d %d\n",ltimeout.tv_sec,ltimeout.tv_usec);
	} else
		lptimeout=NULL;

	/* We know the higher fd present is n-1. Here we loop over all
	 * *possible* file descriptors (take car: some of them - most of them -
	 * may be not present at all in any sets) */
	/* check if there are already satisfied fd requests*/
	for(fd=0,count=0,countcb=0,signaled=0;fd<n;fd++) { /* maybe timeout==0 is a special case */

		/* find the service (if there is any) which manages this file
		 * descriptor */
		epoch_t oldepoch=um_getnestepoch();
		int sercode=service_fd(pcdata->fds,fd);
		/*fprint2("loop %d sercode %d\n", fd,sercode);*/
		int sfd;
		int rfd;
		/*if (FD_ISSET(fd,&lfds[0]) ||
		  FD_ISSET(fd,&lfds[1]) ||
		  FD_ISSET(fd,&lfds[2]))*/
		//printf("pid %d select on %d sercode %x\n",pc->pid,fd,sercode);

		/* all the management of this fd happens only if if the file
		 * descriptor is managed by us (that is, by a service) */
		if (sercode != UM_NONE && (sfd=fd2sfd(pcdata->fds,fd)) >= 0) {
#if defined(__x86_64__)
			sysfun localselect=service_syscall(sercode,uscno(__NR_select));
#else
			sysfun localselect=service_syscall(sercode,uscno(__NR__newselect));
#endif 
			sysfun local_select_register=service_select_register(sercode);
			/* do the management only is the service is interested
			 * in the fact (that is, at least one of the two
			 * management functions is present) */
			if (localselect != NULL || local_select_register != NULL) {
				int flag;
				int how=0;
				rfd=sfd;
				/* Does various things:
				 * - modifies tdfs such that contains only this
				 *   *service* file descriptor, contained in
				 *   all sets in which it has been used.
				 * - if local_select_register is not present,
				 *   fills wrfds with the *service* file
				 *   descriptors found.
				 * - puts all file descriptors in the RX set of
				 *   wfds
				 */
				for (i=0,flag=0;i<3;i++) {
					FD_ZERO(&tfds[i]);
					if (FD_ISSET(fd,&lfds[i])) {
						flag=1;
						how |= 1<<i;
						FD_SET(sfd,&tfds[i]);
						if (local_select_register == NULL)
							FD_SET(rfd,&wrfds[i]); 
						FD_SET(fd,&wfds[RX]);
						FD_CLR(fd,&wfds[WX]); /* needed? maybe no*/
						FD_CLR(fd,&wfds[XX]); /* needed? maybe no*/
						a_random_lfd=fd2lfd(pcdata->fds,fd);
					}
				}

				/* check that some file descriptor has been
				 * found (flag==1), and do this piece of
				 * management only one time for each select
				 * syscall (signaled==0) */
				if (flag==1 && signaled==0) {
					count++;
				//printf("test\n");
				//for (i=0;i<3;i++) {
				//	dumpfdset(n,stype_str[i],&lfds[i]);
				//}
					if (local_select_register == NULL) {
						/* use service provided select */
						if (rfd>rfdmax) rfdmax=rfd;
						/* do a select only for this service file descriptors: if
						 * succeedeed, tell there's some data to unblock for */
						if (localselect(sfd+1,&tfds[0],&tfds[1],&tfds[2],&timeout0,pc) > 0) {
							signaled++;
							//printf("signaled\n");
							lfd_signal(fd2lfd(pcdata->fds,fd));
						}
					} else /* if (local_select_register != NULL) */ {
					  /* use local register service function (call back when hit) */
						countcb++;
						/* how is a bitmask: 1=RX, 2=WX, 4=XX.  local_select_register, when
						 * called, inform the service that when some data is ready for
						 * service file descriptor 'sfd' for (read if how&RX, write for
						 * how&WX, exceptions for how&XX), he has to call given function
						 * (select_wakeup_cb) with given argument (&sd->wakemeup), and we
						 * will know that we have to wakeup */
						if (local_select_register(select_wakeup_cb, &(sd->wakemeup), sfd, how, pc) > 0) {
							/* if local_select_register returned with a nonzero value, it
							 * means there's *already* data! */
							signaled++;
							lfd_signal(fd2lfd(pcdata->fds,fd));
						}
					}
				}
				//printf("test done\n");
			}
		} /*else {
		    for (i=0;i<3;i++)
		    if (FD_ISSET(fd,&lfds[i]))
		    FD_SET(fd,&wfds[i]);
		    }*/
		um_setepoch(oldepoch);
	}
	//printf("count %d signaled %d\n", count, signaled);
	
	/* we are lucky: no fd is managed by us - make a normal system call! */
	if (count == 0) {
		free(sd);
		return STD_BEHAVIOR;
	} else {
		for (i=0;i<3;i++) { 
			putfdset(pfds[i],pc,n,&wfds[i]);
			//putfdset(pfds[i],pc->pid,&lfds[i]);
		}
		sd->wakemeup=WAKEONRFD;
		for (i=0;i<3;i++) {
			sd->sop.origfds[i]=lfds[i];
			if (signaled == 0)  /* waiting */
				sd->wrfds[i]=wrfds[i]; /* FD->sfd->waitfd! */
			else {
				FD_ZERO(&sd->wrfds[i]);
			}
		}
		/*printf("waiting! rfdmax %d %d   \n",rfdmax,signaled);
		  if (rfdmax >= 0)
		  {
		  int i;
		  for (i=0;i<3;i++) {
		  dumpfdset(rfdmax,stype_str[i],&wrfds[i]);
		  }
		  printf("\n");
		  } */
		if (signaled == 0) {
			if (count==countcb)
				sd->wakemeup=WAKEONCB;
			sd->rfdmax=rfdmax;
		} else
			sd->rfdmax= -1;
		//printf("a_random_lfd=%d\n",a_random_lfd);
		/* use one of the fake files (it is a fifo) to signal when 
		 * select must be unblocked*/
		sd->a_random_lfd=a_random_lfd;
		//printf("added %d %d\n",pc->pid,sd->rfdmax);
		pcdata->selset=sd;
		return SC_CALLONXIT;
	}
}

int wrap_out_select(int sc_number,struct pcb *pc,struct pcb_ext *pcdata)
{
	register int n=pc->arg0;
	int pfds[3];
	fd_set lfds[3]; /* local copy of the signaled SC fds */
	fd_set tfds[3]; /* test for virtual files */
	static struct timeval timeout0={0,0};
	struct seldata *sd=pcdata->selset;
	int i,fd,flag;
	pcdata->selset=NULL;
	//printf("wrap_out_select %d\n",pc->retval);
	pc->retval=getrv(pc);
	if (pc->retval >= 0 && sd != NULL) {
		//printf("wrap_out_select loop\n");
		for (i=0;i<3;i++) {
			pfds[i]=getargn(i+1,pc);
			getfdset(pfds[i],pc,n,&lfds[i]);
		}
		/* convert the return values of the real world select call
		 * to the correct values. */
		for(fd=0,pc->retval=0;fd<n;fd++) {
			epoch_t oldepoch=um_getnestepoch();
			int sercode=service_fd(pcdata->fds,fd);
			int sfd;
			int rfd;
			if (sercode != UM_NONE && (sfd=fd2sfd(pcdata->fds,fd)) >= 0) {
#if defined(__x86_64__)
				sysfun localselect=service_syscall(sercode,uscno(__NR_select));
#else
				sysfun localselect=service_syscall(sercode,uscno(__NR__newselect));
#endif
				sysfun local_select_register=service_select_register(sercode);
				if (localselect != NULL && local_select_register == NULL) {
					rfd=sfd;
					for (i=0,flag=0;i<3;i++) {
						FD_ZERO(&tfds[i]);
						if (FD_ISSET(fd,&sd->sop.origfds[i])) {
							flag=1;
							FD_SET(sfd,&tfds[i]);
						}
					}
					lfd_delsignal(fd2lfd(pcdata->fds,fd));
					if (flag && localselect(sfd+1,&tfds[0],&tfds[1],&tfds[2],&timeout0,pc) > 0) {
						pc->retval++;
						//printf("ADD %d virtual (max=%d)\n",fd,n);
						for (i=0;i<3;i++) {
							if (FD_ISSET(sfd,&tfds[i])) 
								FD_SET(fd,&lfds[i]);
							else
								FD_CLR(fd,&lfds[i]);
						}
					}
				} else if (local_select_register != NULL) {
					int how=0;
					int howret=0;
					for (i=0,flag=0;i<3;i++) {
						if (FD_ISSET(fd,&sd->sop.origfds[i])) {
							flag=1;
							how |= 1<<i;
						}
					}
					lfd_delsignal(fd2lfd(pcdata->fds,fd));
					if (flag && (howret=local_select_register(NULL, &(sd->wakemeup), sfd, how, pc)) > 0)
					{
						pc->retval++;
						for (i=0;i<3;i++) {
							if (howret & 1<<i) {
								FD_SET(fd,&lfds[i]);
							} else {
								FD_CLR(fd,&lfds[i]);
							}
						}
					}
				}
			} else {
				if (FD_ISSET(fd,&lfds[0]) || FD_ISSET(fd,&lfds[1]) || FD_ISSET(fd,&lfds[2]))
				{
					//printf("ADD %d real\n",fd);
					pc->retval++;
				}
			}
			um_setepoch(oldepoch);
		}
		for (i=0;i<3;i++) {
			//putargn(i+1,pc,lfds[i]);
			putfdset(pfds[i],pc,n,&lfds[i]);
		}
		putrv(pc->retval,pc);
		/*		printf("wrap_out_select %d   ",pc->retval);
				{
				int i;
				for (i=0;i<3;i++) {
				dumpfdset(n,stype_str[i],&lfds[i]);
				}
				printf("\n");
				}*/
	}
	if (sd != NULL) {
		//printf("eliminatso %d %d\n",pc->pid,norace->rfdmax);
		free(sd);
	}
	return STD_BEHAVIOR;
}


int wrap_in_poll(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		char sercode, sysfun um_syscall)
{
	struct pollfd *ufds; /*local copy*/
	struct seldata *sd=(struct seldata *)malloc(sizeof(struct seldata));
	int *origevents;
	fd_set wrfds[3];
	int i,count,countcb,signaled;
	int a_random_lfd = -1;
	int rfdmax = -1;
	unsigned long pufds=pc->arg0;
	unsigned int nfds=getargn(1,pc);
	/* {
		int timeout=getargn(2,pc);
		fprint2("POLL %x %d %d\n",pufds,nfds,timeout);
	} */
	ufds=alloca(nfds*sizeof(struct pollfd));
	origevents=alloca(nfds*sizeof(int));
	umoven(pc,pufds,nfds*sizeof(struct pollfd),ufds);
	for (i=0;i<3;i++)
		FD_ZERO(&wrfds[i]);

	/* for (i=0;i<nfds;i++) {
		fprint2("pollfdin %d %d %d\n",ufds[i].fd,ufds[i].events,ufds[i].revents);
	} */
	/* preliminary check: can we pass through the poll without blocking? */
	for(i=0,count=0,countcb=0,signaled=0;i<nfds;i++)
	{
		int fd=ufds[i].fd;
		int sfd;
		epoch_t oldepoch=um_getnestepoch();
		int sercode=service_fd(pcdata->fds,fd);
		origevents[i]=0;
		if (sercode != UM_NONE && (sfd=fd2sfd(pcdata->fds,fd)) >= 0) {
			sysfun localpoll=service_syscall(sercode,uscno(__NR_poll));
			sysfun local_select_register=service_select_register(sercode);
			/* fprint2("POLL fd %d sfd %d lfd %d service %d %x\n",
					fd,sfd,fd2lfd(pcdata->fds,fd),sercode,localpoll); */
			if (localpoll != NULL || local_select_register != NULL) {
				/* use service provided "poll"*/
				int rfd;
				int how=0;
				rfd=sfd;
				if (ufds[i].events != 0) {
					/* is hangup mapped onto select "can read" 0? */
					if (local_select_register == NULL) {
						if (ufds[i].events & (POLLIN | POLLHUP) )
							FD_SET(rfd,&wrfds[RX]);
						if (ufds[i].events & POLLOUT)
							FD_SET(rfd,&wrfds[WX]);
						if (ufds[i].events & (POLLPRI | POLLERR | POLLHUP) )
							FD_SET(rfd,&wrfds[XX]);
						if (rfd>rfdmax) rfdmax=rfd;
						origevents[i]=ufds[i].events;
						if (signaled == 0) {
							count++;
							a_random_lfd=fd2lfd(pcdata->fds,fd);
							ufds[i].fd=sfd;
							if (localpoll(&ufds[i],1,0)) {
								signaled++;
								//lfd_signal(fd2lfd(pcdata->fds,ufds[i].fd));
								lfd_signal(a_random_lfd);
							}
							ufds[i].fd=fd;
						}
					} else /* if (local_select_register != NULL) */ {
						/* use select register: the callback function get called
						 * when a relevant event occurs */
						if (ufds[i].events & (POLLIN | POLLHUP) )
							how |= 1;
						if (ufds[i].events & POLLOUT)
							how |= 2;
						if (ufds[i].events & (POLLPRI | POLLERR | POLLHUP) )
							how |= 4;
						origevents[i]=ufds[i].events;
						if (signaled == 0) {
							count++; countcb++;
							a_random_lfd=fd2lfd(pcdata->fds,fd);
							ufds[i].fd=fd;
							if (local_select_register(select_wakeup_cb, &(sd->wakemeup), sfd, how, pc) > 0) {
								signaled++;
								lfd_signal(a_random_lfd);
							}
						}
					}
					ufds[i].events=POLLIN;
				}
			}
			um_setepoch(oldepoch);
		}
	}
	if (count == 0) {
		/* all the fds are managed by the real kernel */
		free(sd);
		return STD_BEHAVIOR;
	} else {
		/*printf("POLL! add waitset for global select\n");*/
		ustoren(pc,pufds,nfds*sizeof(struct pollfd),ufds);
		sd->wakemeup=WAKEONRFD;
		sd->sop.origevents=(int *)malloc(nfds*sizeof(int));
		memcpy(sd->sop.origevents,origevents,nfds*sizeof(int));
		for (i=0;i<3;i++) {
			if (signaled == 0)  /* waiting */
				sd->wrfds[i]=wrfds[i]; /* FD->sfd->waitfd! */
			else {
				FD_ZERO(&sd->wrfds[i]);
			}
		}
		/*printf("waiting! rfdmax %d %d   \n",rfdmax,signaled);
		  if (rfdmax >= 0)
		  {
		  int i;
		  for (i=0;i<3;i++) {
		  dumpfdset(rfdmax,stype_str[i],&wrfds[i]);
		  }
		  printf("\n");
		  } */

		if (signaled == 0) {
			if (count==countcb)
				sd->wakemeup=WAKEONCB;
			sd->rfdmax=rfdmax;
		} else
			sd->rfdmax= -1;
		sd->a_random_lfd=a_random_lfd;
		/*printf("added %d %d\n",pc->pid,sd->rfdmax);*/
		pcdata->selset=sd;
		return SC_CALLONXIT;
	}

}

int wrap_out_poll(int sc_number,struct pcb *pc,struct pcb_ext *pcdata)
{
	struct pollfd *ufds;
	unsigned long pufds=pc->arg0;
	unsigned int nfds=getargn(1,pc);
	//int timeout=getargn(2,pc);
	struct seldata *sd=pcdata->selset;
	int i;
	pcdata->selset=NULL;
	pc->retval=getrv(pc);
	if (pc->retval >= 0 && sd != NULL) {
		ufds=alloca(nfds*sizeof(struct pollfd));
		umoven(pc,pufds,nfds*sizeof(struct pollfd),ufds);
		/*int i;
		  printf("pollfdoutin ");
		  for (i=0;i<nfds;i++) {
		  printf("%d %d %d -",ufds[i].fd,ufds[i].events,ufds[i].revents);
		  }
		  printf("\n");
		  */
		for(i=0,pc->retval=0;i<nfds;i++)
		{
			int fd=ufds[i].fd;
			int sfd;
			epoch_t oldepoch=um_getnestepoch();
			int sercode=service_fd(pcdata->fds,fd);
			if (sercode != UM_NONE && (sfd=fd2sfd(pcdata->fds,fd)) >= 0) {
				sysfun localpoll=service_syscall(sercode,uscno(__NR_poll));
				sysfun local_select_register=service_select_register(sercode);
				if (localpoll != NULL && local_select_register == NULL) {
					int rfd;
					rfd=sfd;
					if (ufds[i].events != 0) {
						ufds[i].events=sd->sop.origevents[i];
						lfd_delsignal(fd2lfd(pcdata->fds,ufds[i].fd));
						/* localpoll sets the revents! */
						ufds[i].fd=sfd;
						if (localpoll(&ufds[i],1,0) > 0)
							pc->retval++;
						ufds[i].fd=fd;
					}
				}
				else if (local_select_register != NULL) {
					int how=0;
					int howret=0;
					ufds[i].events=sd->sop.origevents[i];
					lfd_delsignal(fd2lfd(pcdata->fds,ufds[i].fd));
					if (sd->sop.origevents[i] & (POLLIN | POLLHUP) )
						how |= 1;
					if (sd->sop.origevents[i] & POLLOUT)
						how |= 2;
					if (sd->sop.origevents[i] & (POLLPRI | POLLERR | POLLHUP) )
						how |= 4;
					if ((howret=local_select_register(NULL, &(sd->wakemeup), sfd, how, pc)) > 0) {
						pc->retval++;
						ufds[i].revents=0;
						if ((sd->sop.origevents[i] & (POLLIN) ) &&
								(howret & 1))
							ufds[i].revents |= POLLIN;
						if ((sd->sop.origevents[i] & POLLOUT) &&
								(howret & 2))
							ufds[i].revents |= POLLOUT;
						if ((sd->sop.origevents[i] & POLLPRI) &&
								(howret & 4))
							ufds[i].revents |= POLLPRI;
						/* XXX ERR/HUP ??? */
					}
				}

			} else
				if (ufds[i].revents != 0)
					pc->retval++;
			um_setepoch(oldepoch);
		}
		/*int i;
		  printf("pollfdoutout ");
		  for (i=0;i<nfds;i++) {
		  printf("%d %d %d -",ufds[i].fd,ufds[i].events,ufds[i].revents);
		  }
		  printf("\n"); */
		ustoren(pc,pufds,nfds*sizeof(struct pollfd),ufds);
		putrv(pc->retval,pc);
	}
	if (sd != NULL) {
		//printf("//eliminato %d %d\n",pc->pid,norace->rfdmax);
		free(sd->sop.origevents);
		free(sd);
	}
	return STD_BEHAVIOR;
}

void select_init()
{
	int p=r_pipe(wakeupmainfifo);
	assert (p==0);
	r_fcntl(wakeupmainfifo[0],F_SETFL,O_NONBLOCK);
}
