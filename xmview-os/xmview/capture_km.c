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
int kmviewfd;
struct kmview_event event[NEVENTS];
#define umpid2pcb(X) (pcbtab[(X)-1])
#define PCBSIZE 10

int first_child_exit_status = -1;
void (*first_child_init)(void);

pthread_key_t pcb_key=0; /* key to grab the current thread pcb */

sfun native_syscall=syscall;

/* debugging output, (bypass pure_libc when loaded) */
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

static struct pcb **pcbtab;           /* capture_km pcb table */
int nprocs = 0;                       /* number of active processes */
static int pcbtabsize;                /* actual size of the pcb table */

divfun scdtab[_UM_NR_syscalls];                 /* upcalls */
char scdnarg[_UM_NR_syscalls];  /*nargs*/

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
			 * Messy it can be, this way pointers to pcbs still remain valid after
			 * a reallocation.
			 */
			struct pcb **newtab = (struct pcb **)
				realloc(pcbtab, 2 * pcbtabsize * sizeof pcbtab[0]);
			struct pcb *newpcbs = (struct pcb *) calloc(pcbtabsize, sizeof *newpcbs);
			if (newtab == NULL || newpcbs == NULL) {
				if (newtab != NULL)
					free(newtab);
				return -1;
			}
			for (j = pcbtabsize; j < 2 * pcbtabsize; ++j)
				newtab[j] = &newpcbs[j - pcbtabsize];
			pcbtabsize *= 2;
			pcbtab = newtab;
		}
		pcb=pcbtab[i];
		if (! (pcb->flags & PCB_INUSE)) {
			pcb->pid=pid;
			pcb->kmpid=kmpid;
			pcb->umpid=i+1; // umpid==0 is reserved for umview itself
			pcb->flags = PCB_INUSE;
			pcb->pp = (umppid < 0)?pcb:umpid2pcb(umppid);
			nprocs++;
			return i+1; /*umpid*/
		}
	}

	/* never reach here! */
	assert(0);
	return -1;
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


#if 0
/* pid 2 pcb conversion (by linear search) */
static struct pcb *pid2pcb(int pid)
{
	register int i;
	for (i = 0; i < pcbtabsize; i++) {
		struct pcb *pc = pcbtab[i];
		if (pc->pid == pid && pc->flags & PCB_INUSE)
			return pc;
	}
	return NULL;
}
#endif

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
#ifdef _PROC_MEM_TEST
	if (pc->memfd >= 0)
		close(pc->memfd);
#endif
	nprocs--;
	forallpcbdo(_cut_pp,pc);
	pcb_destructor(pc,0/*flags*/,0);
	if (nprocs > 0)
		pc->flags = 0; /*NOT PCB_INUSE */;
}

/* initial PCB table allocation */
static void allocatepcbtab()
{
	struct pcb *pc;

	/* Allocate the initial pcbtab.  */
	/* look at newpcb for some explanations about the structure */
	pcbtabsize = PCBSIZE;
	/* allocation of pointers */
	pcbtab = (struct pcb **) malloc (pcbtabsize * sizeof pcbtab[0]);
	/* allocation of PCBs */
	pcbtab[0] = (struct pcb *) calloc (pcbtabsize, sizeof *pcbtab[0]);
	/* each pointer points to the corresponding PCB */
	for (pc = pcbtab[0]; pc < &pcbtab[0][pcbtabsize]; ++pc)
		pcbtab[pc - pcbtab[0]] = &pcbtab[0][pc - pcbtab[0]];
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
					if (ump.umpid <= 1) {
						if (ump.umpid == 1) /* the root process is starting */
						{
							pthread_setspecific(pcb_key,pc);
							first_child_init();
						}
						else {
							fprint2("[pcb table full]\n");
							exit(1);
						}
					}
					r_ioctl(kmviewfd, KMVIEW_UMPID, &ump);
					pcb_constructor(pc,event[i].x.newthread.flags,0);
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

/* main capture startup */
int capture_main(char **argv,void (*root_process_init)(void))
{
	struct kmview_magicpoll mp={(long)&event,1};
	kmviewfd=r_open("/dev/kmview",O_RDONLY,0);
	long flags;
	if (kmviewfd < 0)
		return -1;
	r_ioctl(kmviewfd, KMVIEW_MAGICPOLL, &mp);
	flags =  KMVIEW_FLAG_FDSET|KMVIEW_FLAG_EXCEPT_CLOSE|KMVIEW_FLAG_EXCEPT_FCHDIR;
#if __NR_socketcall != __NR_doesnotexist
	flags |= KMVIEW_FLAG_SOCKETCALL;
#endif
	r_ioctl(kmviewfd, KMVIEW_SET_FLAGS, flags);
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
