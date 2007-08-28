/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   um_proc.c: process file table and fake files mgmt
 *   
 *   Copyright 2005 Renzo Davoli University of Bologna - Italy
 *   Modified 2005 Mattia Belletti
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
/* FILE management:
 * there are three different "file descriptors"
 * fd -> file descriptors seen by the processes
 * lfd -> local file descriptors fd of umview itself
 * sfd -> service fd, fd as seen by the service modules.
 * The three set are independent, sfd can be numbers created by modules, 
 * meaningless for umview, umview should just keep the mapping between
 * fd, lfd and sfd */
#include <assert.h>
#include <string.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <dirent.h>
#include <config.h>
#include "treepoch.h"
#include "sctab.h"
#include "umproc.h"
#include "scmap.h"
#include "defs.h"
#include "gdebug.h"
#define FAKECWD "fakecwd"

static char *um_proc_root;
static char *um_tmpfile;
static char *um_tmpfile_tail;
static int um_tmpfile_len;
#ifdef _UM_MMAP
int um_mmap_secret;
int um_mmap_pageshift;
#endif

struct lfd_vtable;

struct lfd_table {
	short count; /*how many pcbs have opened this lfd - look at dup implementation */
	service_t service; /*the service code */
	int sfd; /* the fd as seen from the service */
	int flags; /*open flags*/
	char *path; /* the real path */
	epoch_t epoch;
	struct lfd_vtable *pvtab;
};

struct lfd_vtable {
	int signaled;   /* set when there some data on the fifo, telling that
			   some blocking call have to be unblocked, not yet
			   read - a flag */
	char *filename; /* the fifo */
	int ififo,ofifo;
};

static short um_maxlfd=0;
static struct lfd_table **lfd_tab=NULL;

/* umproc initialization */
void um_proc_open()
{
	char path[PATH_MAX];
#ifdef _UM_MMAP
	long pagesize;
#endif
	/* path of the directory umview creates to store temporary and management
	 * files */
	snprintf(path,PATH_MAX,"/tmp/.umview%ld",(long int)r_getpid());
	//printf("um_proc_open %s\n",path);

	if(r_mkdir(path,0700) < 0) {
		perror("um_proc mkdir");
		exit (-1);
	}
	um_proc_root=strdup(path);
	strcpy(um_proc_root,path);
#ifdef _UM_MMAP
	/* open/create the mmap secret file, it is inherited by all the processes */
	strcat(path,"/lfd.um_mmap");
	um_mmap_secret = r_open(path,O_RDWR|O_TRUNC|O_CREAT,0700);
	/* compute the pageshift value  (log2(pagesize)) */
	pagesize = sysconf(_SC_PAGESIZE);
	for (um_mmap_pageshift = -1;pagesize > 0; um_mmap_pageshift++, pagesize >>= 1)
		;
#else
	strcat(path,"/lfd.xxXXXXX");
#endif
	/* set the um_tmpfile variable, it is used to (quickly) create
	 * tmp file names. The tail is overwritten each time */
	um_tmpfile=strdup(path);
	strcpy(um_tmpfile,path);
	um_tmpfile_tail=um_tmpfile+(strlen(path)-7);
	um_tmpfile_len=strlen(um_tmpfile);
	strcpy(um_tmpfile_tail,FAKECWD);
	if(r_mkdir(um_tmpfile,0700) < 0) {
		perror("um_proc mkdir");
		exit (-1);
	}
}

/* final cleanup: all the directory is deleted (something like rm -rf) */
static void rec_rm_all(char *name)
{
	int fd;
	fd = r_open(name,O_RDONLY | O_DIRECTORY,0);
	if (fd > 0) {
		char buf[1024];
		int size=0;
		int pos;
		struct dirent64 *this;
		while ((size=r_getdents64(fd,buf,1023))>0) {
			for (pos=0, this=(struct dirent64 *)buf; pos<size;
					pos+=this->d_reclen, this=(struct dirent64 *)(&(buf[pos]))) {
				if (strcmp(this->d_name,".") != 0 && strcmp(this->d_name,"..") != 0) {
					char *path;
					asprintf(&path,"%s/%s",name,this->d_name);
					if (this->d_type == DT_DIR) 
						rec_rm_all(path);
					else
						r_unlink(path);
					free(path);
				}
			}
		}
		r_close(fd);
		r_rmdir(name);
	}
}

/* um_proc destructor: all the files get closed and the dir removed */
void um_proc_close()
{
	//printf("um_proc_close %s\n",um_proc_root);
	lfd_closeall();
	rec_rm_all(um_proc_root);
}

char *um_proc_fakecwd()
{
  strcpy(um_tmpfile_tail,FAKECWD);
	return um_tmpfile;
}

/* create a temporary file name, unique names are guaranteed by using
 * service code+lfd index in the name */
static char *um_proc_tmpfile(service_t service, int lfd)
{
	snprintf(um_tmpfile_tail,um_tmpfile_len,"%02x%02d",service,lfd);
	//printf("um_proc_tmpfile %s\n",um_tmpfile);
	return um_tmpfile;
}

/* create a temporary file name, unique names are guaranteed by using
 * a counter */
#define NMAX 1000000
char *um_proc_tmpname()
{
	static int n;
	n = (n+1) % NMAX;
	snprintf(um_tmpfile_tail,um_tmpfile_len,"%06d",n);
	//printf("um_proc_tmpname %s\n",um_tmpfile);
	return um_tmpfile;
}

/* set up the umproc data structure needed by a new process */
void umproc_addproc(struct pcb *pc,int flags,int npcbflag)
{
	if (!npcbflag) {
		if (flags & CLONE_FILES) {
			pc->fds=pc->pp->fds;
			pc->fds->count++;
		} else {
			struct pcb_file *p=pc->fds=(struct pcb_file *)malloc(sizeof(struct pcb_file));
			p->count=1;
			p->nolfd=0;
			p->lfdlist=NULL;
		}
	}
}

void umproc_delproc(struct pcb *pc,int flags,int npcbflag)
{
	if (!npcbflag) {
		struct pcb_file *p=pc->fds;
		p->count--;
		/* if there are no processes left sharing this data structure
		 * free all the data */
		if (p->count == 0) {
			int i;
			for (i=0; i<p->nolfd;  i++) {
				register int lfd=p->lfdlist[i];
				if (lfd >= 0) {
					/*  if ((--lfd_tab[lfd]->count) == 0) {
					 *    register int service=lfd_tab[lfd]->service;
					 *    if (service != UM_NONE) {
					 *       service_syscall(service,uscno(__NR_close))(lfd_tab[lfd]->sfd);
					 *   }
					 *  } */
					//printf("CLOSE LFD %d\n",lfd);
					lfd_close(lfd);
				}
			}
			if (p->lfdlist != NULL)
				free(p->lfdlist);
			free(p);
		}
	}
}

/* open file/socket has two phases: the real open and the register.
 * in the second phase registers the map between the fd as seen by the process and
 * our lfd */
/* lfd table contains a record for each file opened by a process,
 * if it is not "virtualized" it is used to keep the path of the open file
 * (e.g. to manage a fchdir call!)
 * When the file is virtualized there is the pvtab part*/
int lfd_open (service_t service, int sfd, char *path, int flags, int nested)
{
	int lfd,fifo;
	GDEBUG(3, "lfd_open sfd %d, path %s, nested %d", sfd, path, nested);
	//printf("lfd_open %x sfd %d %s",service,sfd,(path==NULL)?"<null>":path);
	/* looks for a free local file descriptor */
	for (lfd=0; lfd<um_maxlfd && lfd_tab[lfd] != NULL ; lfd++)
		;
	/* if there are none, expands the lfd table */
	if (lfd >= um_maxlfd) {
		int i=um_maxlfd;
		//printf("lfd_tab realloc oldndf %d\n",um_maxlfd);
		um_maxlfd = (lfd + OLFD_STEP) & ~OLFD_STEP_1;
		//printf("lfd_tab realloc newnfd %d\n",um_maxlfd);
		lfd_tab=(struct lfd_table **) realloc (lfd_tab, (um_maxlfd * sizeof (struct lfd_table *)));
		assert (lfd_tab);

		/* Clean the new entries in lfd_tab or lfd_cleanall will not work properly */
		for (;i < um_maxlfd;i++)
		{
			lfd_tab[i]=NULL;
		}
	}
	assert(lfd_tab[lfd] == NULL);
	lfd_tab[lfd] = (struct lfd_table *)malloc (sizeof(struct lfd_table));
	assert(lfd_tab[lfd] != NULL);
	//printf("LEAK %x %x path=%s\n",lfd_tab,lfd_tab[lfd],path);
	lfd_tab[lfd]->path=(path==NULL)?NULL:strdup(path);
	lfd_tab[lfd]->service=service;
	lfd_tab[lfd]->sfd=sfd;
	lfd_tab[lfd]->flags=flags;
	lfd_tab[lfd]->epoch=um_setepoch(0);
	lfd_tab[lfd]->count=1;
	lfd_tab[lfd]->pvtab=NULL;
	if (service != UM_NONE && !nested) {
		char *filename;
		lfd_tab[lfd]->pvtab = (struct lfd_vtable *)malloc (sizeof(struct lfd_vtable));
		assert(lfd_tab[lfd]->pvtab != NULL);
		/* create the fifo to fake the file for the process,
		 * it will be used to give a fd to the process and to unblock
		 * select/pselect/poll/ppoll operations */
		filename=lfd_tab[lfd]->pvtab->filename=strdup(um_proc_tmpfile(service,lfd));
		fifo=mkfifo(filename,0600);
		assert(fifo==0);
		/* the fifo is opened on both ends input and output, so that
		 * 1- the call is not blocking
		 * 2- it is possible to reread the data after the process gets unblocked */
		lfd_tab[lfd]->pvtab->ififo=r_open(filename,O_RDONLY|O_NONBLOCK,0);
		assert(lfd_tab[lfd]->pvtab->ififo >= 0);
		lfd_tab[lfd]->pvtab->ofifo=r_open(filename,O_WRONLY,0);
		assert(lfd_tab[lfd]->pvtab->ofifo >= 0);
		lfd_tab[lfd]->pvtab->signaled=0;
	} else {
		//printf("add lfd %d file %s\n",lfd,lfd_tab[lfd]->path);
		lfd_tab[lfd]->pvtab=NULL;
	}
	//printf("lfd_open: lfd %d sfd %d file %s\n",lfd,sfd,lfd_tab[lfd]->path);
	return lfd;
}

/* close a file */
void lfd_close (int lfd)
{
	int rv;
	GDEBUG(5, "close %d %x",lfd,lfd_tab[lfd]);
	assert (lfd < 0 || (lfd < um_maxlfd && lfd_tab[lfd] != NULL));
	/* if this is the last reference to the lfd 
	 * close everything*/
	if (lfd >= 0 && --(lfd_tab[lfd]->count) == 0) {
		register int service;
		/* if it is a virtual fifo, close the fifo files, unlink
		 * the fifo itself, and free the malloc'ed data */
		if (lfd_tab[lfd]->pvtab != NULL) {
			rv=r_close(lfd_tab[lfd]->pvtab->ififo);
			assert(rv==0);
			rv=r_close(lfd_tab[lfd]->pvtab->ofifo);
			assert(rv==0);
			rv=r_unlink(lfd_tab[lfd]->pvtab->filename);
			assert(rv==0);
			free(lfd_tab[lfd]->pvtab->filename);
			free(lfd_tab[lfd]->pvtab);
		} 
		//else
			//printf("del lfd %d file %s\n",lfd,lfd_tab[lfd]->path);
		service=lfd_tab[lfd]->service;
		/* call the close method of the service module */
		if (service != UM_NONE && lfd_tab[lfd]->sfd >= 0) 
			service_syscall(service,uscno(__NR_close))(lfd_tab[lfd]->sfd); 
		/* free path and structure */
		if (lfd_tab[lfd]->path != NULL)
			free(lfd_tab[lfd]->path);
		free(lfd_tab[lfd]);
		lfd_tab[lfd]=NULL;
	}
}

/* dup: just increment the count, lfd is shared */
int lfd_dup(int lfd)
{
	if (lfd >= 0) {
		assert (lfd < um_maxlfd && lfd_tab[lfd] != NULL);
		return ++lfd_tab[lfd]->count;
	} else
		return 1;
}
	
/* access method to read how many process fd share the same lfd element */
int lfd_getcount(int lfd)
{
	assert (lfd < um_maxlfd && lfd_tab[lfd] != NULL);
	return lfd_tab[lfd]->count;
}

/* set sfd to null (to avoid double close) */
void lfd_nullsfd(int lfd)
{
	//printf("lfd_nullsfd %d %d %x\n",
			//lfd,um_maxlfd,lfd_tab[lfd]);
	assert (lfd < um_maxlfd && lfd_tab[lfd] != NULL);
	lfd_tab[lfd]->sfd= -1;
}

/* lfd 2 sfd conversion */
int lfd_getsfd(int lfd)
{
	assert (lfd < um_maxlfd && lfd_tab[lfd] != NULL);
	return lfd_tab[lfd]->sfd;
}
	
/* lfd: get the service code */
service_t lfd_getservice(int lfd)
{
	//fprint2("getservice %d -> %x\n",lfd,lfd_tab[lfd]);
	//assert (lfd < um_maxlfd && lfd_tab[lfd] != NULL);
	if (lfd >= um_maxlfd || lfd_tab[lfd] == NULL)
		return (UM_NONE);
	return lfd_tab[lfd]->service;
}
	
/* lfd: get the filename (of the fifo): for virtualized files*/
char *lfd_getfilename(int lfd)
{
	assert (lfd < um_maxlfd && lfd_tab[lfd] != NULL && lfd_tab[lfd]->pvtab != NULL);
	return lfd_tab[lfd]->pvtab->filename;
}

/* lfd: get the path */
char *lfd_getpath(int lfd)
{
	assert (lfd < um_maxlfd && lfd_tab[lfd] != NULL);
	return lfd_tab[lfd]->path;
}

/* management of FD flags stored in lfdlist
 * MST = invalid (usually closed fd are set to -1) i.e. <0 means invalid
 * MST-1 = FD_CLOEXEC
 * (for now there are no more flags, in case add here, provided the
 * space for fd is large enough)
 * Lower bits: lfd;
 */
#define X_FD_FLAGS   0xc0000000
#define X_FD_INVALID 0x80000000
#define X_FD_CLOEXEC 0x40000000
#define X_FD_NBITS 30
#define FD2LFD(p,fd) (((p)->lfdlist[(fd)]) & ~X_FD_FLAGS)
#define FD2FDFLAGS(p,fd) (((p)->lfdlist[(fd)]) >> X_FD_NBITS)

/* fd 2 ldf mapping (in a process file table) */
int fd2lfd(struct pcb_file *p, int fd)
{
	if (fd>=0 && fd < p->nolfd && p->lfdlist[fd]>=0)
		return FD2LFD(p,fd);
	else
		return -1;
}

/* fd set flags */
int fd_getfdfl(struct pcb_file *p, int fd)
{
	if (fd>=0 && fd < p->nolfd && p->lfdlist[fd]>=0)
		return FD2FDFLAGS(p,fd);
	else
		return -1;
}

/* fd get flags */
int fd_setfdfl(struct pcb_file *p, int fd, int val)
{
	if (fd>=0 && fd < p->nolfd && p->lfdlist[fd]>=0) {
		if (val & FD_CLOEXEC)
			p->lfdlist[fd] |= X_FD_CLOEXEC;
		else
			p->lfdlist[fd] &= ~X_FD_CLOEXEC;
		return 0;
	} else
		return -1;
}

int fd_getflfl(struct pcb_file *p, int fd) {
	if (fd>=0 && fd < p->nolfd && p->lfdlist[fd]>=0) {
		int lfd=FD2LFD(p,fd);
		return lfd_tab[lfd]->flags;
	} else
		return -1;
}

/* fd 2 path mapping (given the file table of a process) */
char *fd_getpath(struct pcb_file *p, int fd)
{
	if (fd>=0 && fd < p->nolfd) {
		int lfd=FD2LFD(p,fd);
		if (lfd >= 0 && lfd < um_maxlfd && lfd_tab[lfd] != NULL) {
			return lfd_tab[lfd]->path;
		} else {
			return NULL;
		}
	} else
		return NULL;
}

/* fd 2 sfd conversion (given the file table of a process) */
int fd2sfd(struct pcb_file *p, int fd)
{
	if (fd>=0 && fd < p->nolfd && p->lfdlist[fd] >= 0)
		return lfd_tab[FD2LFD(p,fd)]->sfd;
	else
		return -1;
}

/* tell the identifier of the service which manages given fd, or UM_NONE if no
 * service handle it */
service_t service_fd(struct pcb_file *p, int fd, int setepoch)
{
	//printf("service fd p=%x\n",p);
	//if (p != NULL)
	//	printf("service fd p->lfdlist=%x\n",p->lfdlist);
	/*if (fd < p->nolfd)
		printf("service fd p=%d %x\n",fd, p->lfdlist[fd]);
	else
		printf("service fd p=%d xxx\n",fd); */
#ifdef _UM_MMAP
  /* ummap secret file is not accessible by processes, it is just a 
	 * non-existent descriptor */
	if (fd == um_mmap_secret) 
		return UM_ERR;
	else 
#endif
		if (fd >= 0 && fd < p->nolfd && p->lfdlist[fd] >= 0) {
			/* XXX side effect: when service_fd finds a virtual file,
			 * it sets also the epoch */
			if (setepoch)
				um_setepoch(lfd_tab[FD2LFD(p,fd)]->epoch);
			return lfd_tab[FD2LFD(p,fd)]->service;
		} else
			return UM_NONE;
}
	
/* second phase of lfd_open: map the process fd to to lfd,
 * fd is known only after the kernel has completed its open
 * of the fifo */
void lfd_register (struct pcb_file *p, int fd, int lfd)
{
	//fprint2("lfd_register fd %d lfd %d\n",fd,lfd);
	if (fd >= p->nolfd) {
		int i=p->nolfd;
		/* adds about OLDFD_STEP=8 entries in the array */
		/* FIXME: if file descriptors aren't allocated linearly by
		 * Linux (e.g.: security extensions which gives random fds),
		 * very large arrays are allocated in this step. */
		p->nolfd = (fd + OLFD_STEP) & ~OLFD_STEP_1;
		p->lfdlist = (int *) realloc(p->lfdlist, p->nolfd * sizeof(int));
		assert (p->lfdlist);
		//printf("lfd_add realloc oldndf %d new %d\n",i,p->nolfd);
		if (p->lfdlist == NULL) {
			perror("no mem");
		}
		for (;i < p->nolfd; i++) 
			p->lfdlist[i]= -1;
	}
	p->lfdlist[fd]=lfd; /* CLOEXEC unset */
	//printf("lfd_register fd %d lfd %d path %s\n", fd, lfd, lfd_tab[lfd]->path);
}

/* when a process closes a file must be closed (lfd element) and deregistered
 * from the process file table */
void lfd_deregister_n_close(struct pcb_file *p, int fd)
{
	//fprint2("lfd_deregister_n_close %d %d %d\n",fd,p->nolfd,p->lfdlist[fd]);
	//assert(fd < p->nolfd && p->lfdlist[fd] != -1);
	if (p->lfdlist != NULL && fd < p->nolfd && p->lfdlist[fd] >= 0) {
		lfd_close(FD2LFD(p,fd));
		p->lfdlist[fd] = -1;
	}
}

/* final clean up of all the fifos */
void lfd_closeall()
{
	register int lfd;
	for (lfd=0; lfd<um_maxlfd; lfd++) {
		if (lfd_tab[lfd] != NULL && lfd_tab[lfd]->pvtab != NULL) {
			r_close(lfd_tab[lfd]->pvtab->ififo);
			r_close(lfd_tab[lfd]->pvtab->ofifo);
			r_unlink(lfd_tab[lfd]->pvtab->filename);
		}
	}
}

/* unblock a process waiting on a select/poll call */
void lfd_signal(int lfd)
{
	char ch=0;
	//fprint2("lfd_signal %d\n",lfd);
	//assert (lfd < um_maxlfd && lfd_tab[lfd]->pvtab != NULL);
	if  (lfd < um_maxlfd && lfd_tab[lfd] != NULL && lfd_tab[lfd]->pvtab != NULL) {
		if (lfd_tab[lfd]->pvtab->signaled == 0) {
			lfd_tab[lfd]->pvtab->signaled = 1;
			r_write(lfd_tab[lfd]->pvtab->ofifo,&ch,1);
		}
	}
}

/* when the process has restarted, empty the fifo for the next time */
void lfd_delsignal(int lfd)
{
	char buf[1024];
	assert (lfd < um_maxlfd && lfd_tab[lfd] != NULL && lfd_tab[lfd]->pvtab != NULL);
	if (lfd_tab[lfd]->pvtab->signaled == 1) {
		lfd_tab[lfd]->pvtab->signaled = 0;
		r_read(lfd_tab[lfd]->pvtab->ififo,buf,1024);
	}
}

/* sfd + service --2--> path conversion
 * linear scan, slow! */
char *sfd_getpath(service_t code, int sfd)
{
	int lfd;
	for (lfd=0; lfd<um_maxlfd; lfd++)
		if(lfd_tab[lfd] && lfd_tab[lfd]->service == code &&
				lfd_tab[lfd]->sfd == sfd)
			return lfd_tab[lfd]->path;
	return NULL;
}
