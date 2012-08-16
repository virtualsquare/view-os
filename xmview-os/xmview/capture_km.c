/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   capture_km.c: capture layer for kmview
 *   
 *   Copyright 2008 Renzo Davoli University of Bologna - Italy
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
#include <sys/ioctl.h>

#include "capture_nested.h"

#include "defs.h"
#include "utils.h"
#include "gdebug.h"
#include "kmview.h"

#define NEVENTS 1
int kmversion;
int kmviewfd;
long kmflags;
struct kmview_event event[NEVENTS];
#define umpid2pcb(X) (pcbtab[(X)-1])
#define PCBSIZE 16
#define PCBSTEP 16

int first_child_exit_status = -1;
void (*first_child_init)(void);

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

static struct pcb **pcbtab;           /* capture_km pcb table */
int nprocs = 0;                       /* number of active processes */
static int pcbtabsize;                /* actual size of the pcb table */
static int pcbtabfree=-1;                /* actual size of the pcb table */

divfun scdtab[_UM_NR_syscalls];                 /* upcalls */
unsigned char scdnarg[_UM_NR_syscalls];  /*nargs*/
unsigned int scdtab_bitmap[INT_PER_MAXSYSCALL]; /* bitmap */
struct ghosthash64 ghostmounts={{GH_TERMINATE},{}};


#if __NR_socketcall != __NR_doesnotexist
divfun sockcdtab[19];                 /* upcalls */
#endif

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

static pid_t newpcb (pid_t pid,pid_t kmpid,pid_t umppid)
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
		 * umpid meaning is overloaded for O(1) free elements management: 
		 * newpcb->umpid of unused pcbs stores the index of the next unused entry
		 */
		struct pcb **newtab = (struct pcb **)
			realloc(pcbtab, (pcbtabsize+PCBSTEP) * sizeof pcbtab[0]);
		struct pcb *newpcbs = (struct pcb *) calloc(PCBSTEP, sizeof *newpcbs);
		if (newtab == NULL || newpcbs == NULL) {
			if (newtab != NULL)
				free(newtab);
			return -1;
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
	pcb->kmpid=kmpid;
	pcb->umpid=i+1; // umpid==0 is reserved for umview itself
	pcb->flags = PCB_INUSE;
	pcb->pp = (umppid < 0)?pcb:umpid2pcb(umppid);
	nprocs++;
	return i+1; /*umpid*/
}

static void freepcb(struct pcb *pc)
{
	int index=pc->umpid-1;
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
	for (i = 0; i < pcbtabsize; i++) {
		struct pcb *pc = pcbtab[i];
		if (pc->pid == pid && pc->flags & PCB_INUSE)
			return pc;
	}
	return NULL;
}

/* orphan processes must NULL-ify their parent process pointer */
static void _cut_pp(struct pcb *pc, struct pcb *delpc)
{
	if (pc->pp == delpc)
		pc->pp = NULL;
}

/* pcb deallocator */
static void droppcb(struct pcb *pc)
{
	/* the last process descriptor should stay "alive" for
	 * the termination of all modules */
	/* otherwise the "nesting" mechanism misunderstands
	 * the pcb by a npcb */
	/* XXX rd235 20090805: it seems not a problem any more
		 in the new version. deleted for dup delproc notication for proc #1 */
	nprocs--;
	forallpcbdo(_cut_pp,pc);
	pcb_destructor(pc,0/*flags*/,0);
#if 0
	if (nprocs > 0)
#endif
		pc->flags = 0; /*NOT PCB_INUSE */;
	freepcb(pc);
}

/* initial PCB table allocation */
static void allocatepcbtab()
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
}


/* Tracer core, executed any time an event occurs*/
void tracehand(void *useless)
{
	int i;
	for (i=0;i<NEVENTS;i++) {
		if (event[i].tag == KMVIEW_EVENT_NONE)
			break;
		switch(event[i].tag) {
			case KMVIEW_EVENT_NEWTHREAD:
				{
					struct kmview_ioctl_umpid ump;
					struct pcb *pc;
					ump.kmpid=event[i].x.newthread.kmpid;
					ump.umpid=newpcb(event[i].x.newthread.pid,event[i].x.newthread.kmpid,
							event[i].x.newthread.umppid);
					pc=umpid2pcb(ump.umpid);
					pcb_constructor(pc,event[i].x.newthread.flags,0);
					if (ump.umpid <= 1) {
						if (ump.umpid == 1) /* the root process is starting */
						{
							pthread_setspecific(pcb_key,pc);
							first_child_init();
						}
						else {
							printk("[pcb table full]\n");
							exit(1);
						}
					}
					r_ioctl(kmviewfd, KMVIEW_UMPID, &ump);
				}
				break;
			case KMVIEW_EVENT_TERMTHREAD:
				droppcb(umpid2pcb(event[i].x.termthread.umpid));
				break;
			case KMVIEW_EVENT_SYSCALL_ENTRY:
#if __NR_socketcall != __NR_doesnotexist
			case KMVIEW_EVENT_SOCKETCALL_ENTRY:
#endif
				{
					struct pcb *pc=umpid2pcb(event[i].x.syscall.x.umpid);
					divfun fun;
					long scno=event[i].x.syscall.scno;
					pthread_setspecific(pcb_key,pc);
					GDEBUG(3, "--> pid %d syscall %d (%s) @ %p", pc->pid, 
							scno, SYSCALLNAME(scno), 
							event[i].x.syscall.pc);
#if __NR_socketcall != __NR_doesnotexist
					if (event[i].tag == KMVIEW_EVENT_SOCKETCALL_ENTRY)
						fun=sockcdtab[scno];
					else
#endif
						fun=scdtab[scno];
					if (fun == NULL) {
						pc->behavior=STD_BEHAVIOR;
					} else {
#if __NR_socketcall != __NR_doesnotexist
						if (event[i].tag == KMVIEW_EVENT_SOCKETCALL_ENTRY) 
							memcpy(&pc->event, &(event[i].x), sizeof(struct kmview_event_socketcall));
						else {
							memcpy(&pc->event, &(event[i].x), sizeof(struct kmview_event_ioctl_syscall));
							pc->event.addr=0;
						}
#else
						memcpy(&pc->event, &(event[i].x), sizeof(struct kmview_event_ioctl_syscall));
#endif
						pc->behavior=fun(scno,IN,pc);
					}
					switch(pc->behavior) {
						case STD_BEHAVIOR:
							r_ioctl(kmviewfd,KMVIEW_SYSRESUME,pc->kmpid);
							break;
						case SC_FAKE:
							fun(scno,OUT,pc);
							pc->outevent.x.kmpid=pc->kmpid;
							r_ioctl(kmviewfd,KMVIEW_SYSVIRTUALIZED,&pc->outevent);
							break;
						case SC_CALLONXIT:
						case SC_TRACEONLY:
							pc->event.x.umpid=pc->kmpid; 
							r_ioctl(kmviewfd,KMVIEW_SYSMODIFIED,&pc->event);
							break;
						case SC_MODICALL:
							pc->event.x.umpid=pc->kmpid; 
							r_ioctl(kmviewfd,KMVIEW_SYSARGMOD,&pc->event);
							break;
						default: /*SUSPENDED*/
							/* do nothing. resume will restart it */
							break;
					}
					break;
				}
			case KMVIEW_EVENT_SYSCALL_EXIT:
				{
					struct pcb *pc=umpid2pcb(event[i].x.sysreturn.x.umpid);
					divfun fun;
					long scno=pc->event.scno;
					GDEBUG(3, "<-- pid %d syscall %d (%s) @ %p", pc->pid, 
							scno, SYSCALLNAME(scno), 
							event[i].x.sysreturn.retval);
#if __NR_socketcall != __NR_doesnotexist
					if (pc->event.addr)
						fun=sockcdtab[scno];
					else
#endif
						fun=scdtab[scno];
					if (fun == NULL) {
						pc->behavior=STD_BEHAVIOR;
					} else {
						memcpy(&pc->outevent, &(event[i].x), sizeof(struct kmview_event_ioctl_sysreturn));
						pc->behavior=fun(scno,OUT,pc);
					}
					if ((pc->behavior & SC_SUSPENDED) == 0) {
						pc->outevent.x.kmpid=pc->kmpid;
						r_ioctl(kmviewfd,KMVIEW_SYSRETURN,&pc->outevent);
					}
					break;
				}
		}
	}
}

/* pc can be resumed: there is data to unblock (maybe) its system call */
void sc_resume(struct pcb *pc)
{
	int scno=pc->event.scno;
	int inout=pc->behavior-SC_SUSPENDED;
	divfun fun;
	/* set the current process */
	pthread_setspecific(pcb_key,pc);
#if __NR_socketcall != __NR_doesnotexist
	if (pc->event.addr)
		fun=sockcdtab[scno];
	else
#endif
		fun=scdtab[scno];
	if (fun != NULL)
		pc->behavior=fun(scno,inout,pc);
  else
		pc->behavior=STD_BEHAVIOR;
	if (inout==IN) { /* resumed in IN phase */
		switch(pc->behavior) {
			case STD_BEHAVIOR:
				r_ioctl(kmviewfd,KMVIEW_SYSRESUME,pc->kmpid);
				break;
			case SC_FAKE:
				fun(scno,OUT,pc);
				pc->outevent.x.kmpid=pc->kmpid;
				r_ioctl(kmviewfd,KMVIEW_SYSVIRTUALIZED,&pc->outevent);
				break;
			case SC_CALLONXIT:
			case SC_TRACEONLY:
				/*maybe we are using a socketcall struct as it were a syscall*/
				pc->event.x.umpid=pc->kmpid; 
				r_ioctl(kmviewfd,KMVIEW_SYSMODIFIED,&pc->event);
				break;
			case SC_MODICALL:
				pc->event.x.umpid=pc->kmpid;
				r_ioctl(kmviewfd,KMVIEW_SYSARGMOD,&pc->event);
				break;
			default: /*SUSPENDED*/
				/* do nothing. resume will restart it */
				break;
		}
	} else {
		if ((pc->behavior & SC_SUSPENDED) == 0) {
			pc->outevent.x.kmpid=pc->kmpid;
			r_ioctl(kmviewfd,KMVIEW_SYSRETURN,&pc->outevent);
		}
	}
}

static void do_wait(int signal)
{
	int exitstatus;
	wait(&exitstatus);
	first_child_exit_status=WEXITSTATUS(exitstatus);
}

static void setsigaction()
{
	struct sigaction sa;

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
	sa.sa_handler=do_wait;
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

/* execvp implementation (to avoid pure_libc management) */
static int r_execvp(const char *file, char *const argv[]){
	if(strchr(file,'/') != NULL)
		return r_execve(file,argv,environ);
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

int capture_attach(struct pcb *pc,pid_t pid)
{ 
	return -ENOSYS;
}

void capture_execrc(const char *path,const char *argv1)
{
	if (access(path,X_OK)==0) {
		int pid;
		int status;
		switch (pid=fork()) {
			case -1: exit (2);
			case 0: execl(path,path,(char *)0);
							exit (2);
			default: waitpid(pid,&status,0);
							 if (!WIFEXITED(status))
								 exit (2);
		}
	}
}

/* ghostmount management */
/* hash sum and mod are separate functions:
	 hash sums are used to quicly elimiate false positives,
	 intermediate results can be completed during the scan */
static inline unsigned int hashadd (long prevhash, char c) {
	return prevhash ^ ((prevhash << 5) + (prevhash >> 2) + c);
}

static inline unsigned int hashsum (int sum,const char *path,int len) {
	int i;
	for (i=0;i<len;i++,path++)
		sum=hashadd(sum,*path);
	return sum;
}

static int gh2array(struct ghosthash64 *gh,
		unsigned short *tmplen, unsigned int *tmphash)
{
	int i,ntmp;
	short scanlen;
	for (i=0,ntmp=0,scanlen=0;i<GH_SIZE &&
			gh->deltalen[i] != GH_TERMINATE;i++) {
		scanlen += gh->deltalen[i];
		if (gh->deltalen[i] != GH_DUMMY) {
			tmplen[ntmp] = scanlen;
			tmphash[ntmp] = gh->hash[i];
			ntmp++;
		}
	}
	return ntmp;
}

static int array2gh(unsigned short *tmplen,unsigned int *tmphash,int ntmp,
		struct ghosthash64 *gh)
{
	int ngh;
	if (ntmp > 0) {
		ngh=(tmplen[0]/GH_DUMMY)+1;
		int i,j;
		short scanlen;
		for(i=1;i<ntmp;i++)
			ngh+=((tmplen[i]-tmplen[i-1])/GH_DUMMY)+1;
		if (ngh > GH_SIZE)
			return -ENOMEM;
		i=j=scanlen=0;
		while (i<ntmp) {
			if (tmplen[i] - scanlen >= GH_DUMMY) {
				gh->deltalen[j] = GH_DUMMY;
				scanlen += GH_DUMMY;
				gh->hash[j] = -1;
				j++;
			} else {
				gh->deltalen[j] = tmplen[i] - scanlen;
				gh->hash[j] = tmphash[i];
				scanlen=tmplen[i];
				i++;
				j++;
			}
		}
	} else
		ngh=0;
	if (ngh < GH_SIZE)
		gh->deltalen[ngh] = GH_TERMINATE;
	return ngh;
}

int ghosthash_add(const char *path,int len)
{
	unsigned short tmplen[GH_SIZE];
	unsigned int tmphash[GH_SIZE];
	unsigned short ntmp=gh2array(&ghostmounts,tmplen,tmphash);
	int pos,rv;
	if (ntmp >= GH_SIZE)
		return -ENOMEM;
	for (pos=0;pos<ntmp && tmplen[pos]<len;pos++)
		;
	memmove(&tmplen[pos+1],&tmplen[pos],(ntmp-pos)*sizeof(short));
	memmove(&tmphash[pos+1],&tmphash[pos],(ntmp-pos)*sizeof(int));
	ntmp++;
	tmplen[pos]=len;
	tmphash[pos]=hashsum(0,path,len);
	rv=array2gh(tmplen, tmphash, ntmp, &ghostmounts);
	if (rv >= 0 && kmversion >= 2)
		r_ioctl(kmviewfd, KMVIEW_GHOSTMOUNTS, &ghostmounts);
	return rv;
}

int ghosthash_del(const char *path,int len)
{
	unsigned int hash=hashsum(0,path,len);
	unsigned short tmplen[GH_SIZE];
	unsigned int tmphash[GH_SIZE];
	unsigned short ntmp=gh2array(&ghostmounts,tmplen,tmphash);
	int pos;
	for (pos=0;pos<ntmp && tmplen[pos]<=len && hash!=tmphash[pos];pos++)
		;
	if (pos<ntmp && len == tmplen[pos] &&  hash == tmphash[pos]) {
		int rv;
		memmove(&tmplen[pos],&tmplen[pos+1],(ntmp-pos-1)*sizeof(short));
		memmove(&tmphash[pos],&tmphash[pos+1],(ntmp-pos-1)*sizeof(int));
		ntmp--;
		rv=array2gh(tmplen, tmphash, ntmp, &ghostmounts);
		if (rv >= 0 && kmversion >= 2)
			r_ioctl(kmviewfd, KMVIEW_GHOSTMOUNTS, &ghostmounts);
		return rv;
	} else
		return -ENOENT;
}

static void scdtab_bitmap_init()
{
	register int i;
	scbitmap_fill(scdtab_bitmap);
	for (i=0; i<_UM_NR_syscalls; i++)
		if (scdtab[i] != NULL) 
			scbitmap_clr(scdtab_bitmap,i);
#if __NR_socketcall != __NR_doesnotexist
	scbitmap_clr(scdtab_bitmap,__NR_socketcall);
#endif
	/*for (i=0; i<MAXSYSCALL; i++)
		if (scbitmap_isset(scdtab_bitmap,i) == 0)
			printk("%d ",i);*/
}

void capture_km_kmpid_chroot(pid_t kmpid,int onoff)
{
	if (kmversion >= 2) {
		if (onoff)
			r_ioctl(kmviewfd, KMVIEW_SET_CHROOT, kmpid);
		else
			r_ioctl(kmviewfd, KMVIEW_CLR_CHROOT, kmpid);
	}
}

void capture_km_global_get_path_syscalls(void)
{
	if (kmversion >= 2) {
		kmflags &= ~KMVIEW_FLAG_PATH_SYSCALL_SKIP;
		r_ioctl(kmviewfd, KMVIEW_SET_FLAGS, kmflags);
	}
}

void capture_km_global_skip_path_syscalls(void)
{
	if (kmversion >= 2) {
		kmflags |= KMVIEW_FLAG_PATH_SYSCALL_SKIP;
		r_ioctl(kmviewfd, KMVIEW_SET_FLAGS, kmflags);
	}
}

/* main capture startup */
int capture_main(char **argv,void (*root_process_init)(void),char *rc)
{
	struct kmview_magicpoll mp={(long)&event,1};
	kmviewfd=r_open("/dev/kmview",O_RDONLY,0);
	if (kmviewfd < 0)
		return -1;
	kmversion=r_ioctl(kmviewfd,KMVIEW_GET_VERSION);
	r_ioctl(kmviewfd, KMVIEW_MAGICPOLL, &mp);
	kmflags =  KMVIEW_FLAG_FDSET|KMVIEW_FLAG_EXCEPT_FCHDIR;
#if __NR_socketcall != __NR_doesnotexist
	kmflags |= KMVIEW_FLAG_SOCKETCALL;
#endif
	if (kmversion >= 2)
		kmflags |= KMVIEW_FLAG_PATH_SYSCALL_SKIP;
	else
		kmflags |= KMVIEW_FLAG_EXCEPT_CLOSE;
	if (kmversion >= 2) {
		ghosthash_add("/proc/0",7);
		ghosthash_add("/proc/1",7);
		ghosthash_add("/proc/2",7);
		ghosthash_add("/proc/3",7);
		ghosthash_add("/proc/4",7);
		ghosthash_add("/proc/5",7);
		ghosthash_add("/proc/6",7);
		ghosthash_add("/proc/7",7);
		ghosthash_add("/proc/8",7);
		ghosthash_add("/proc/9",7);
	}

	r_ioctl(kmviewfd, KMVIEW_SET_FLAGS, kmflags);
	if (kmversion >= 2) {
		scdtab_bitmap_init();
		r_ioctl(kmviewfd, KMVIEW_SYSCALLBITMAP, scdtab_bitmap);
	}
	allocatepcbtab();
	switch (r_fork()) {
		case -1:
			GPERROR(0, "strace: fork");
			exit(1);
			break;
		case 0:
			unsetenv("LD_PRELOAD");
			/* try to set process priority back to standard prio (effective only when 
			 * umview runs in setuid mode), useless call elsewhere */
			r_setpriority(PRIO_PROCESS,0,0);
			r_ioctl(kmviewfd, KMVIEW_ATTACH, 0);
			r_close(kmviewfd);
			/* maybe it is better to use execvp instead of r_execvp.
			 * the former permits to use a (preloaded) module provided executable as startup process*/
			GDEBUG(8, "starting rc files");
			capture_execrc("/etc/viewosrc",(char *)0);
			if (rc != NULL && *rc != 0)
				capture_execrc(rc,(char *)0);
			GDEBUG(8, "starting %s",argv[0]);
			r_execvp(argv[0], argv);
			GPERROR(0, "strace: exec");
			_exit(1);
		default:
			/* KMVIEW TRACER startup */
			/* create the thread key */
			pthread_key_create(&pcb_key,vir_pcb_free);
			/* init the first child startup fun */
			first_child_init=root_process_init;
			/* set the pcb_key for this process */
			setsigaction();
	}
	return 0;
}
