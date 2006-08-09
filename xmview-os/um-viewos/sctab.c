/*   This is iart of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   sctab.c: um-ViewOS interface to capture_sc
 *   
 *   Copyright 2005 Renzo Davoli University of Bologna - Italy
 *   Modified 2005 Mattia Belletti, Ludovico Gardenghi, Andrea Gasparini
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
#include <sys/select.h>
#include <sched.h>
#include <asm/ptrace.h>
#include <asm/unistd.h>
#include <linux/net.h>
#include <errno.h>
#include <limits.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/sysctl.h>
//#include <pthread.h>

#include "defs.h"
#include "umproc.h"
#include "services.h"
#include "um_services.h"
#include "sctab.h"
#include "um_select.h"
#include "scmap.h"
#include "utils.h"
#include "canonicalize.h"
#include "capture_sc.h"
#include "capture_nested.h"
#include "gdebug.h"

void um_set_errno(struct pcb *pc,int i) {
	if (pc->flags && PCB_INUSE) 
		pc->erno=i;
	else {
		struct npcb *npc=(struct npcb *)pc;
		npc->erno=i;
	}
}

char *um_getcwd(struct pcb *pc,char *buf,int size) {
	if (pc->flags && PCB_INUSE) {
		strncpy(buf,((struct pcb_ext *)(pc->data))->fdfs->cwd,size);
		return buf;
	} else
		/* TO BE DECIDED! Modules should never use
		 * relative paths*/ 
		return NULL;
}

struct timestamp *um_x_gettst()
{
	struct pcb *pc=get_pcb();
	if (pc)
	{
		if (pc->flags && PCB_INUSE) {
			struct pcb_ext *pcdata = (struct pcb_ext *) pc->data;
			//fprint2("USER PROCESS %p\n",pc);
			if (pcdata) 
				return &(pcdata->tst);
			else
				return NULL;
		} else {
			struct npcb *npc=(struct npcb *)pc;
			//fprint2("NESTED PCB %p\n",npc);
			return &(npc->tst);
		}
	}
	else
		return NULL;
}

epoch_t um_getnestepoch()
{
	struct pcb *pc=get_pcb();
	if (pc->flags && PCB_INUSE) {
		struct pcb_ext *pcdata = (struct pcb_ext *) pc->data;
		return pcdata->nestepoch;
	} else {
		struct npcb *npc=(struct npcb *)pc;
		return npc->nestepoch;
	}
}

epoch_t um_setepoch(epoch_t epoch)
{
	struct pcb *pc=get_pcb();
	epoch_t oldepoch=0;
	if (pc->flags && PCB_INUSE) {
		struct pcb_ext *pcdata = (struct pcb_ext *) pc->data;
		if (pcdata) {
			oldepoch=pcdata->nestepoch;
			if (epoch > 0)
				pcdata->nestepoch=epoch;
		}
	} else {
		struct npcb *npc=(struct npcb *)pc;
		oldepoch=npc->nestepoch;
		if (epoch > 0)
			npc->nestepoch=epoch;
	}
	return oldepoch;
}

int um_x_access(char *filename, int mode, struct pcb *pc)
{
	service_t sercode;
	int retval;
	/*printf("-> um_x_access: %s\n",filename);*/
	long oldscno;
	epoch_t epoch;
	if (pc->flags && PCB_INUSE) {
		oldscno = pc->scno;
		pc->scno = __NR_access;
		epoch=((struct pcb_ext *)pc->data)->tst.epoch;
	} else {
		struct npcb *npc=(struct npcb *)pc;
		oldscno = npc->scno;
		npc->scno = __NR_access;
		epoch=npc->tst.epoch;
	}
	if ((sercode=service_check(CHECKPATH,filename,1)) == UM_NONE)
		retval = r_access(filename,mode);
	else{
		retval = service_syscall(sercode,uscno(__NR_access))(filename,mode,pc);
	}
	if (pc->flags && PCB_INUSE) {
		pc->scno = oldscno;
		((struct pcb_ext *)pc->data)->tst.epoch=epoch;
	} else  {
		((struct npcb *)pc)->scno = oldscno;
		((struct npcb *)pc)->tst.epoch = epoch;
	}
	return retval;
}
										 
int um_x_lstat64(char *filename, struct stat64 *buf, struct pcb *pc)
{
	service_t sercode;
	int retval;
	/*printf("-> um_lstat: %s\n",filename);*/
	long oldscno;
	epoch_t epoch;
	if (pc->flags && PCB_INUSE) {
		oldscno = pc->scno;
		pc->scno = NR64_stat;
		epoch=((struct pcb_ext *)pc->data)->tst.epoch;
	} else {
		struct npcb *npc=(struct npcb *)pc;
		oldscno = npc->scno;
		npc->scno = NR64_lstat;
		epoch=npc->tst.epoch;
	}
	if ((sercode=service_check(CHECKPATH,filename,1)) == UM_NONE)
		retval = r_lstat64(filename,buf);
	else{
		retval = service_syscall(sercode,uscno(NR64_stat))(filename,buf,pc);
	}
	if (pc->flags && PCB_INUSE) {
		pc->scno = oldscno;
		((struct pcb_ext *)pc->data)->tst.epoch=epoch;
	} else  {
		((struct npcb *)pc)->scno = oldscno;
		((struct npcb *)pc)->tst.epoch = epoch;
	}
	return retval;
}

int um_x_readlink(char *path, char *buf, size_t bufsiz, struct pcb *pc)
{
	service_t sercode;
	long oldscno = pc->scno;
	int retval;
	epoch_t epoch;
	if (pc->flags && PCB_INUSE) {
		oldscno = pc->scno;
		pc->scno = __NR_readlink;
		epoch=((struct pcb_ext *)pc->data)->tst.epoch;
	} else {
		struct npcb *npc=(struct npcb *)pc;
		oldscno = npc->scno;
		npc->scno = __NR_readlink;
		epoch=npc->tst.epoch;
	}
	if ((sercode=service_check(CHECKPATH,path,1)) == UM_NONE)
		retval = r_readlink(path,buf,bufsiz);
	else{
		retval = service_syscall(sercode,uscno(__NR_readlink))(path,buf,bufsiz,pc);
	}
	if (pc->flags && PCB_INUSE) {
		pc->scno = oldscno;
		((struct pcb_ext *)pc->data)->tst.epoch=epoch;
	} else  {
		((struct npcb *)pc)->scno = oldscno;
		((struct npcb *)pc)->tst.epoch = epoch;
	}
	return retval;
}


char um_patherror[]="PE";

char *um_getpath(long laddr,struct pcb *pc)
{
	char path[PATH_MAX];
	if (umovestr(pc,laddr,PATH_MAX,path) == 0)
		return strdup(path);
	else
		return um_patherror;
}

char *um_abspath(long laddr,struct pcb *pc,struct stat64 *pst,int dontfollowlink)
{
	char path[PATH_MAX];
	char newpath[PATH_MAX];
	if (umovestr(pc,laddr,PATH_MAX,path) == 0) {
			um_realpath(path,newpath,pst,dontfollowlink,pc);
		if (pc->erno)
			return um_patherror;	//error
		else
			return strdup(newpath);
	}
	else {
		pc->erno = EINVAL;
		return um_patherror;
	}
}

/* Common framework for the dsys_{megawrap,socketwrap,mmapwrap,...} - they all
 * do the usual work, but with different parameter handling.
 * What a dsys_* function do is, in general, receiving the notification of an
 * IN/OUT phase of syscall about a certain process, and decide what to do. What
 * it has to do is to deliver the notification to the correct functions.
 * This common framework asks for three more parameters to make such a
 * decision:
 * - An argument parser function (dcpa): this function extracts the arguments
 *   from the process registers/memory into our data structures (usually
 *   arg{0,1,...}, but also others - e.g., sockregs).
 * - An index function (dcif): returns the index inside the system call table
 *   that regards the current system call.
 * - A service call function (sc): the service code and system call number is
 *   given to this function, and it must return the function of the
 *   module/service which manage the syscall
 * - A system call table (sm): this is a table of sc_map entries - look at that
 *   structure for more informations.
 */
typedef void (*dsys_commonwrap_parse_arguments)(struct pcb *pc, struct pcb_ext *pcdata, int usc);
typedef int (*dsys_commonwrap_index_function)(struct pcb *pc, int usc);
typedef sysfun (*service_call)(service_t code, int scno);
int dsys_commonwrap(int sc_number,int inout,struct pcb *pc,
		dsys_commonwrap_parse_arguments dcpa,
		dsys_commonwrap_index_function dcif,
		service_call sc,
		struct sc_map *sm)
{
	struct pcb_ext *pcdata=(struct pcb_ext *)(pc->data);
	int usc=uscno(sc_number);
	if (__builtin_expect(pcdata->tmpfile2unlink_n_free!=NULL,0)) {
		r_unlink(pcdata->tmpfile2unlink_n_free);
		free(pcdata->tmpfile2unlink_n_free);
		pcdata->tmpfile2unlink_n_free=NULL;
	}
	/* -- IN phase -- */
	if (inout == IN) {
		service_t sercode;
		int index;
		/* timestamp the call */
		pcdata->tst.epoch=pcdata->nestepoch=get_epoch();
		/* extract argument */
		dcpa(pc, pcdata, usc);
		/* and get the index of the system call table
		 * regarding this syscall */
		index = dcif(pc, usc);
		//fprint2("nested_commonwrap %d -> %lld\n",sc_number,pcdata->tst.epoch);
		/* looks in the system call table what is the 'choice function'
		 * and ask it the service to manage */
		sercode=sm[index].scchoice(sc_number,pc,pcdata);
		/* something went wrong during a path lookup - fake the
		 * syscall, we do not want to make it run */
		if (pcdata->path == um_patherror) {
			pc->retval = -1;
			/*if(sc_number == __NR_execve)
				fprintf(stderr,"execve dice um_path_error!!\n"); 
				return STD_BEHAVIOR;
			else*/
			return SC_FAKE;
		}
		//fprint2("nested_commonwrap choice %d -> %lld %x\n",sc_number,pcdata->tst.epoch,sercode);
		/* if some service want to manage the syscall (or the ALWAYS
		 * flag is set), we process it */
		if (sercode != UM_NONE || (sm[index].flags & ALWAYS)) {
			/* suspend management:
			 * when howsusp has at least one bit set (CB_R, CB_W, CB_X) 
			 * the system checks with a select if the call is blocking or not.
			 * when the call would be blocking the process is suspended and an event
			 * event callback is loaded.
			 */
			int howsusp = sm[index].flags & 0x7;
			int what;
			if (howsusp != 0 && (what=check_suspend_on(pc, pcdata, 
							(sc_number == __NR_socketcall)?pc->arg2:pc->arg0,
							howsusp))!=STD_BEHAVIOR)
				return what;
			else
				/* normal management: call the wrapin function,
				 * with the correct service syscall function */
				return sm[index].wrapin(sc_number,pc,pcdata,sercode,sc(sercode,index));
		}
		else {
			/* we do not want to manage the syscall: free the path
			 * field in case, since we do not need it, and ask for
			 * a standard behavior */
			if (pcdata->path != NULL)
				free(pcdata->path);
			return STD_BEHAVIOR;
		}
	/* -- OUT phase -- */
	} else {
		if (pcdata->path != um_patherror) {
			/* ok, try to call the wrapout */
			int retval;
			/* and get the index of the system call table
			 * regarding this syscall */
			int index = dcif(pc, usc);
			/* call the wrapout */
			retval=sm[index].wrapout(sc_number,pc,pcdata);
			/* check if we can free the path (not NULL and not
			 * used) */
			if (pcdata->path != NULL && (retval & SC_SUSPENDED) == 0)
				free(pcdata->path);
			return retval;
		}
		else {
			/* during the IN phase something gone wrong (XXX: is
			 * this the point?) - simply pass return value and
			 * errno to the process */
			putrv(pc->retval,pc);
			puterrno(pc->erno,pc);
			return STD_BEHAVIOR;
		}
	}
}

#if (__NR_socketcall != __NR_doesnotexist)
void dsys_socketwrap_parse_arguments(struct pcb *pc, struct pcb_ext *pcdata, int usc)
{
	pc->arg0=getargn(0,pc); // arg0 is the current socket call
	pc->arg1=getargn(1,pc);
	pcdata->path = NULL;
	if (has_ptrace_multi) {
		struct ptrace_multi req[] = {{PTRACE_PEEKDATA, pc->arg1, &(pcdata->sockregs[0]), sockmap[pc->arg0].nargs}};
		errno=0;
		ptrace(PTRACE_MULTI,pc->pid,req,1);
		pc->arg2=pcdata->sockregs[0];
	}
	else
	{
		int i;
		pc->arg2=pcdata->sockregs[0]=ptrace(PTRACE_PEEKDATA,pc->pid,pc->arg1,0);
		for (i=1;i<sockmap[pc->arg0].nargs;i++)
			pcdata->sockregs[i]=ptrace(PTRACE_PEEKDATA,pc->pid,4*i+pc->arg1,0);
	}
}

int dsys_socketwrap_index_function(struct pcb *pc, int usc)
{
	return pc->arg0;
}

int dsys_socketwrap(int sc_number,int inout,struct pcb *pc)
{
	return dsys_commonwrap(sc_number, inout, pc,
			dsys_socketwrap_parse_arguments,
			dsys_socketwrap_index_function, service_socketcall,
			sockmap);
}
#endif

void dsys_um_sysctl_parse_arguments(struct pcb *pc, struct pcb_ext *pcdata, int usc)
{
	struct __sysctl_args sysctlargs;
	sysctlargs.name=NULL;
	sysctlargs.nlen=0;
	pcdata->path = NULL;
	pc->arg0 = getargn(0, pc);
	umoven(pc,pc->arg0,sizeof(sysctlargs),&sysctlargs);
	if (sysctlargs.name == NULL && sysctlargs.nlen != 0) {
		/* virtual system call */
		if (sysctlargs.newval != NULL && sysctlargs.newlen >0 &&
				sysctlargs.newlen <= 6)
			umoven(pc,(long)(sysctlargs.newval),sysctlargs.newlen * sizeof(long), &pcdata->sockregs[0]);
		pc->arg1 = sysctlargs.nlen;
	} else {
		/* real sysctl, mapped on 0 */
		pc->arg1 = 0;
	}
}

int dsys_um_sysctl_index_function(struct pcb *pc, int usc)
{
	return pc->arg1;
}

int dsys_um_sysctl(int sc_number,int inout,struct pcb *pc)
{
	return dsys_commonwrap(sc_number, inout, pc,
			dsys_um_sysctl_parse_arguments,
			dsys_um_sysctl_index_function, service_syscall,
			virscmap);
}

static void _reg_service(struct pcb *pc,service_t *pcode)
{
	service_addproc(*pcode,pc->umpid,pcbtablesize(),pc);
}

static int reg_service(service_t code)
{
	forallpcbdo(_reg_service,&code);
	return 0;
}

static void _dereg_service(struct pcb *pc,service_t *pcode)
{
	service_delproc(*pcode,pc->umpid,pc);
}

static int dereg_service(service_t code)
{
	forallpcbdo(_dereg_service,&code);
	return 0;
}

/* UM actions for a new process entering the game*/
static void um_proc_add(struct pcb *pc)
{
	service_addproc(UM_NONE,pc->umpid,pcbtablesize(),pc);
}

/* UM actions for a terminated process */
static void um_proc_del(struct pcb *pc)
{
	service_delproc(UM_NONE,pc->umpid,pc);
}

static mode_t local_getumask(void) {
	mode_t mask = r_umask(0);
	r_umask(mask);
	return mask;
}

void pcb_plus(struct pcb *pc,int flags,int maxtablesize)
{
	struct pcb_ext *pcpe;
	pc->data = (void *) (pcpe = (struct pcb_ext *) malloc(sizeof (struct pcb_ext)));
	/* CLONE_PARENT = I'm not your child, I'm your brother. So, parent is
	 * different from what we thought */
	if (flags & CLONE_PARENT)
		pc->pp=pc->pp->pp;
	/* CLONE_FS = share filesystem information */
	if (flags & CLONE_FS) {
		pcpe->fdfs = ((struct pcb_ext *)pc->pp->data)->fdfs;
		pcpe->fdfs->count++;
	} else {
		pcpe->fdfs =  (struct pcb_fs *) malloc(sizeof (struct pcb_fs));
		pcpe->fdfs->count=1;
	}
	if (pc->pp == pc) {
		char *path=malloc(PATH_MAX);
		r_getcwd(path,PATH_MAX);
		pcpe->fdfs->cwd=realloc(path,strlen(path));
		pcpe->fdfs->root=strdup("/");
		pcpe->fdfs->mask=local_getumask();
		r_umask(pcpe->fdfs->mask);
		pcpe->tst=tst_newfork(NULL);
		pcpe->tst=tst_newproc(&(pcpe->tst));
	} else {
		pcpe->fdfs->cwd=strdup(((struct pcb_ext *)(pc->pp->data))->fdfs->cwd);
		pcpe->fdfs->root=strdup(((struct pcb_ext *)(pc->pp->data))->fdfs->root);
		pcpe->fdfs->mask=((struct pcb_ext *)(pc->pp->data))->fdfs->mask;
		pcpe->tst=tst_newproc(&(((struct pcb_ext *)(pc->pp->data))->tst));
	}
	pcpe->path=pcpe->selset=pcpe->tmpfile2unlink_n_free=NULL;
	/* if CLONE_FILES, file descriptor table is shared */
	if (flags & CLONE_FILES)
		pcpe->fds = ((struct pcb_ext *)(pc->pp->data))->fds;
	lfd_addproc(&(pcpe->fds),flags & CLONE_FILES);
	um_proc_add(pc);
}

void pcb_minus(struct pcb *pc)
{
	struct pcb_ext *pcpe=pc->data;
	//printf("pcb_desctructor %d\n",pc->pid);
	lfd_delproc(pcpe->fds);
	um_proc_del(pc);
	assert (pcpe->fdfs != NULL);
	pcpe->fdfs->count--;
	if (pcpe->fdfs->count == 0) {
		free (pcpe->fdfs->cwd);
		free (pcpe->fdfs->root);
		free (pcpe->fdfs);
	}
	tst_delproc(&(pcpe->tst));
	free(pcpe);
	/*if (pc->data != NULL) {
		free(((struct pcb_ext *)pc->data)->fdfs->cwd);
		free(pc->data);
	}*/
}

int pcb_newfork(struct pcb *pc)
{
	struct pcb_ext *pcpe=pc->data;
	struct treepoch *te=pcpe->tst.treepoch;
	pcpe->tst=tst_newfork(&(pcpe->tst));
	return (te == pcpe->tst.treepoch)?-1:0;
}

int dsys_dummy(int sc_number,int inout,struct pcb *pc)
{
	if (inout == IN) {
		GDEBUG(1, "dummy diverted syscall pid %d call %d",pc->pid,sc_number);
		return STD_BEHAVIOR;
	} else {
	}
	return STD_BEHAVIOR;
}

int dsys_error(int sc_number,int inout,struct pcb *pc)
{
	GDEBUG(1, "dsys_error pid %d call %d",pc->pid,sc_number);
	pc->retval = -1;
	pc->erno = ENOSYS;
	return STD_BEHAVIOR;
}

service_t choice_fd(int sc_number,struct pcb *pc,struct pcb_ext *pcdata)
{
	int fd=(sc_number == __NR_socketcall)?pc->arg2:pc->arg0;
	return service_fd(pcdata->fds,fd);
}

/* choice sd (just the system call number is the choice parameter) */
service_t choice_sc(int sc_number,struct pcb *pc,struct pcb_ext *pcdata)
{
	int sc=sc_number;
	return service_check(CHECKSC,&sc,1);
}

/* choice mount (mount point must be defined + filesystemtype is used
 * instead of the pathname for service selection) */
char choice_mount(int sc_number,struct pcb *pc,struct pcb_ext *pcdata)
{
	pc->arg1=getargn(1,pc);
	pcdata->path=um_abspath(pc->arg1,pc,&(pcdata->pathstat),0); 
	
	if (pcdata->path!=um_patherror) {
		char filesystemtype[PATH_MAX];
		unsigned long fstype=getargn(2,pc);
		if (umovestr(pc,fstype,PATH_MAX,filesystemtype) == 0) {
			return service_check(CHECKFSTYPE,filesystemtype,1);
		}
		else
			return UM_NONE;
	} else
		return UM_NONE;
}

/* choice path (filename must be defined) */
service_t choice_path(int sc_number,struct pcb *pc,struct pcb_ext *pcdata)
{
	pcdata->path=um_abspath(pc->arg0,pc,&(pcdata->pathstat),0); 
	//printf("choice_path %d %s\n",sc_number,pcdata->path);
	
	if (pcdata->path==um_patherror){
/*		char buff[PATH_MAX];
		umovestr(pc,pc->arg0,PATH_MAX,buff);
        fprintf(stderr,"um_patherror: %s",buff);*/
		return UM_NONE;
	}
	else
		return service_check(CHECKPATH,pcdata->path,1);
}

/* choice link (dirname must be defined, basename can be non-existent) */
char choice_link(int sc_number,struct pcb *pc,struct pcb_ext *pcdata)
{
	pcdata->path=um_abspath(pc->arg0,pc,&(pcdata->pathstat),1); 
	//printf("choice_path %d %s\n",sc_number,pcdata->path);
	if (pcdata->path==um_patherror)
		return UM_NONE;
	else
		return service_check(CHECKPATH,pcdata->path,1);
}

/* choice link (dirname must be defined, basename can be non-existent second arg)*/
char choice_link2(int sc_number,struct pcb *pc,struct pcb_ext *pcdata)
{
	pc->arg1=getargn(1,pc);
	pcdata->path=um_abspath(pc->arg1,pc,&(pcdata->pathstat),1); 
	//printf("choice_path %d %s\n",sc_number,pcdata->path);
	if (pcdata->path==um_patherror)
		return UM_NONE;
	else
		return service_check(CHECKPATH,pcdata->path,1);
}

char choice_socket(int sc_number,struct pcb *pc,struct pcb_ext *pcdata)
{
	return service_check(CHECKSOCKET, &(pc->arg2),1);
}

/* choice device through major and minor number... it's a try, don't use it yet */
char choice_device(int sc_number,struct pcb *pc,struct pcb_ext *pcdata)
{
	pcdata->path=um_abspath(pc->arg1,pc,&(pcdata->pathstat),1);
	// CHECK is really st_rdev? it seems...
	return service_check(CHECKDEVICE, &((pcdata->pathstat).st_rdev),1);
}


char always_umnone(int sc_number,struct pcb *pc,struct pcb_ext *pcdata)
{
	return UM_NONE;
}

void dsys_megawrap_parse_arguments(struct pcb *pc, struct pcb_ext *pcdata, int usc)
{
	pcdata->path = NULL;
	pc->arg0 = getargn(0, pc);
#if (__NR_socketcall == __NR_doesnotexist)
	if (scmap[uscno(pc->scno)].setofcall & SOC_SOCKET)
	{
		int i;
		pc->arg1 = getargn(1, pc);
		pc->arg2 = pc->arg0;
		/*
		 * fprint2("=== %s %d (",SYSCALLNAME(pc->scno),scmap[uscno(pc->scno)].nargs);
		 * for (i=0;i<scmap[uscno(pc->scno)].nargs;i++) 
		 * fprint2 ("%x,",getargn(i,pc)); 
		 * fprint2("\n");
		 */
		for (i=0;i<scmap[uscno(pc->scno)].nargs;i++)
			pcdata->sockregs[i]=getargn(i, pc);
	}
#endif
}

int dsys_megawrap_index_function(struct pcb *pc, int usc)
{
	return usc;
}

int dsys_megawrap(int sc_number,int inout,struct pcb *pc)
{
	return dsys_commonwrap(sc_number, inout, pc,
			dsys_megawrap_parse_arguments,
			dsys_megawrap_index_function, service_syscall, scmap);
}

int um_mod_getpid()
{
	struct pcb *pc=get_pcb();
	return ((pc && (pc->flags & PCB_INUSE))?pc->pid:0);
}

int um_mod_umoven(long addr, int len, void *_laddr)
{
	struct pcb *pc=get_pcb();
	if (pc) {
		if (pc->flags && PCB_INUSE)
			return (umoven(pc,addr,len,_laddr));
		else {
			memcpy(_laddr,(void *)addr,len);
			return 0;
		}
	}
	else 
		return -1;
}

int um_mod_umovestr(long addr, int len, void *_laddr)
{
	struct pcb *pc=get_pcb();
	if (pc) {
		if (pc->flags && PCB_INUSE)
			return (umovestr(pc,addr,len,_laddr));
		else {
			strncpy((char *)_laddr,(char *)addr, len);
			return 0;
		}
	}
	else 
		return -1;
}

int um_mod_ustoren(long addr, int len, void *_laddr)
{
	struct pcb *pc=get_pcb();
	if (pc) {
		if (pc->flags && PCB_INUSE)
			return (ustoren(pc,addr,len,_laddr));
		else {
			memcpy((void *)addr,_laddr,len);
			return 0;
		}
	}
	else 
		return -1;
}

int um_mod_ustorestr(long addr, int len, void *_laddr)
{
	struct pcb *pc=get_pcb();
	if (pc) {
		if (pc->flags && PCB_INUSE)
			return (ustorestr(pc,addr,len,_laddr));
		else {
			strncpy((char *)addr,(char *)_laddr,len);
			return 0;
		}
	}
	else 
		return -1;
}

int um_mod_getsyscallno(void)
{
	struct pcb *pc=get_pcb();
	if (pc) {
		if (pc->flags && PCB_INUSE)
			return (pc->scno);
		else {
			struct npcb *npc=(struct npcb *)pc;
			return (npc->scno);
		}
	} else 
		return 0;
}

long *um_mod_getargs(void)
{
	struct pcb *pc=get_pcb();
	if (pc) {
		if (pc->flags && PCB_INUSE)
			return (getargp(pc));
		else {
			struct npcb *npc=(struct npcb *)pc;
			return (npc->args);
		}
	} else{
		return NULL;
	}
}

int um_mod_getumpid(void)
{
	struct pcb *pc=get_pcb();
	return ((pc && (pc->flags & PCB_INUSE))?pc->umpid:0);
}

struct stat64 *um_mod_getpathstat(void)
{
	struct pcb *pc=get_pcb();
	if (pc) {
		if (pc->flags && PCB_INUSE) {
			struct pcb_ext *pcdata = (struct pcb_ext *) pc->data;
			if (pcdata) {
				if (pcdata->pathstat.st_mode == 0)
					return NULL;
				else
					return &(pcdata->pathstat);
			}
			else
				return NULL;
		} else {
			struct npcb *npc=(struct npcb *)pc;
			if (npc->pathstat.st_mode == 0)
				return NULL;
			else
				return &(npc->pathstat);
		}
	}
	else
		return NULL;
}

char *um_mod_getpath(void)
{
	struct pcb *pc=get_pcb();
	if (pc) {
		struct pcb_ext *pcdata = (struct pcb_ext *) pc->data;
		if (pc->flags && PCB_INUSE) {
			if (pcdata) {
				return pcdata->path;
			}
			else
				return NULL;
		} else {
			struct npcb *npc=(struct npcb *)pc;
			return npc->path;
		}
	}
	else
		return NULL;
}

int um_mod_getsyscalltype(int scno)
{
	int usc=uscno(scno);
	if (usc >= 0) 
		return USC_TYPE(usc);
	else
		return -1;
}

void scdtab_init()
{
	register int i;
	pcb_constr=pcb_plus;
	pcb_destr=pcb_minus;
	_service_init((sysfun)reg_service,(sysfun)dereg_service);

#if (__NR_socketcall != __NR_doesnotexist)
	scdtab[__NR_socketcall]=dsys_socketwrap;
#endif

	scdtab[__NR__sysctl]=dsys_um_sysctl;

	init_scmap();
	for (i=0; i<scmap_scmapsize; i++) {
		int scno=scmap[i].scno;
		if (scno >= 0) 
			scdtab[scno]=dsys_megawrap;
	}
	um_proc_open();
	atexit(um_proc_close);
}
