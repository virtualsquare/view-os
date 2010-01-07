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
#include "hashtab.h"
#include "gdebug.h"
#define FAKECWD "fakecwd"

static char *um_proc_root;
static char *um_tmpfile;
static char *um_tmpfile_tail;
static int um_tmpfile_len;
#ifdef _UM_MMAP
int um_mmap_secret;
int um_mmap_pageshift;
#define MMAP_SECRET_FD 1023
#endif

struct lfd_vtable;

struct lfd_table {
	short count; /*how many pcbs have opened this lfd - look at dup implementation */
	struct ht_elem *hte; /*the hash table element */
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

static int lfd_tabmax=0;
static struct lfd_table **lfd_tab=NULL;

#define O1LFD
#ifndef O1LFD
  /* look for a free local file descriptor */
static int lfd_alloc(void)
{
	int lfd;
	for (lfd=0; lfd<lfd_tabmax && lfd_tab[lfd] != NULL ; lfd++)
		;
	/* if there are none, expands the lfd table */
	if (lfd >= lfd_tabmax) {
		int i=lfd_tabmax;
		//printk("lfd_tab realloc oldndf %d\n",lfd_tabmax);
		lfd_tabmax = (lfd + OLFD_STEP) & ~OLFD_STEP_1;
		//printk("lfd_tab realloc newnfd %d\n",lfd_tabmax);
		lfd_tab=(struct lfd_table **) realloc (lfd_tab, (lfd_tabmax * sizeof (struct lfd_table *)));
		assert (lfd_tab);

		/* Clean the new entries in lfd_tab or lfd_cleanall will not work properly */
		for (;i < lfd_tabmax;i++)
		{
			lfd_tab[i]=NULL;
		}
	}
	assert(lfd_tab[lfd] == NULL);
	lfd_tab[lfd] = (struct lfd_table *)malloc (sizeof(struct lfd_table));
	assert(lfd_tab[lfd] != NULL);
	return lfd;
}

static inline void lfd_free(int lfd)
{
	free(lfd_tab[lfd]);
	lfd_tab[lfd]=NULL;
}

static inline void lfd_forall(void (*f)(int lfd,void *arg),void *arg)
{
	register int lfd;
	for (lfd=0; lfd<lfd_tabmax; lfd++) {
		if (lfd_tab[lfd] != NULL)
			f(lfd,arg);
	}
}

static inline void *lfd_forall_r(void *(*f)(int lfd,void *arg1,void *arg2),
		void *arg1,void *arg2)
{
	register int lfd;
	void *rv=NULL;
	for (lfd=0; lfd<lfd_tabmax; lfd++) {
		if (lfd_tab[lfd] != NULL) {
			if ((rv=f(lfd,arg1,arg2)) != NULL)
				return rv;
		}
	}
	return NULL;
}
#else

////static pthread_mutex_t lfd_tab_mutex = PTHREAD_MUTEX_INITIALIZER;

//static struct lfd_table **lfd_tab=NULL;
//static int lfd_tabmax=0;
static int lfd_tabsize=0;
static int lfd_tabfree=-1;

int lfd_alloc()
{
	int rv;
	//pthread_mutex_lock( &lfd_tab_mutex );
	if (lfd_tabfree>=0) {
		rv=lfd_tabfree;
		lfd_tabfree=(int)(lfd_tab[rv]);
	} else {
		rv=lfd_tabmax++;
		if (rv>=lfd_tabsize) {
			lfd_tabsize=(rv + OLFD_STEP) & ~OLFD_STEP_1;
			lfd_tab=realloc(lfd_tab,lfd_tabsize* sizeof(void *));
			assert(lfd_tab);
		}
	}
	lfd_tab[rv]=malloc(sizeof(struct lfd_table));
	assert(lfd_tab[rv]);
	//pthread_mutex_unlock( &lfd_tab_mutex );
	return rv;
}

void lfd_free(int lfd)
{
	free(lfd_tab[lfd]);
	//pthread_mutex_lock( &lfd_tab_mutex );
	lfd_tab[lfd]=(void *)lfd_tabfree;
	lfd_tabfree=lfd;
	//pthread_mutex_unlock( &lfd_tab_mutex );
}

static inline void lfd_forall(void (*f)(int lfd,void *arg),void *arg)
{
	int lfd;
	//pthread_mutex_lock( &lfd_tab_mutex );
	while (lfd_tabfree>=0) {
		lfd=lfd_tabfree;
		lfd_tabfree=(int)(lfd_tab[lfd]);
		lfd_tab[lfd]=NULL;
	}
	for (lfd=0; lfd<lfd_tabmax; lfd++) {
		if (lfd_tab[lfd] != NULL)
			f(lfd,arg);
		else {
			lfd_tab[lfd]=(void *)lfd_tabfree;
			lfd_tabfree=lfd;
		}
	}
	//pthread_mutex_unlock( &lfd_tab_mutex );
}

static inline void *lfd_forall_r(void *(*f)(int lfd,void *arg1,void *arg2),
		void *arg1,void *arg2)
{
	int lfd;
	void *rv=NULL;
	//pthread_mutex_lock( &lfd_tab_mutex );
	while (lfd_tabfree>=0) {
		lfd=lfd_tabfree;
		lfd_tabfree=(int)(lfd_tab[lfd]);
		lfd_tab[lfd]=NULL;
	}
	for (lfd=0; lfd<lfd_tabmax; lfd++) {
		if (lfd_tab[lfd] != NULL) {
			if (rv == NULL)
				rv=f(lfd,arg1,arg2);
		} else {
			lfd_tab[lfd]=(void *)lfd_tabfree;
			lfd_tabfree=lfd;
		} 
	}               
	//pthread_mutex_unlock( &lfd_tab_mutex );
	return rv;
}

#endif

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
	//printk("um_proc_open %s\n",path);

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
	unlink(path);
#ifdef MMAP_SECRET_FD
	if (r_dup2(um_mmap_secret,MMAP_SECRET_FD)>=0) {
		r_close(um_mmap_secret);
		um_mmap_secret = MMAP_SECRET_FD; 
	} 
#endif
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
	/* printk("um_proc_close %s\n",um_proc_root);*/
	lfd_closeall();
	rec_rm_all(um_proc_root);
}

char *um_proc_fakecwd()
{
  strcpy(um_tmpfile_tail,FAKECWD);
	return um_tmpfile;
}

/* create a temporary file name, unique names are guaranteed by using
 * service name+lfd index in the name */
static char *um_proc_tmpfile(struct ht_elem *hte, int lfd)
{
	snprintf(um_tmpfile_tail,um_tmpfile_len,"%s%02d",ht_get_servicename(hte),lfd);
	//printk("um_proc_tmpfile %s\n",um_tmpfile);
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
	//printk("um_proc_tmpname %s\n",um_tmpfile);
	return um_tmpfile;
}

/* set up the umproc data structure needed by a new process */
void umproc_addproc(struct pcb *pc,int flags,int npcbflag)
{
	//printk("umproc_addproc %d %x %x %d\n", npcbflag, flags, pc->pp, pc->pp->fds);
	//if (pc)
		//printk("umproc_addproc %d(%d) %d %x\n", pc->pid, (pc->pp)?pc->pp->pid:0, npcbflag, flags);
	if (!npcbflag) {
		if (flags & CLONE_FILES) {
			pc->fds=pc->pp->fds;
			pc->fds->count++;
		} else {
			struct pcb_file *p=pc->fds=(struct pcb_file *)malloc(sizeof(struct pcb_file));
			p->count=1;
			p->nolfd=0;
			p->lfdlist=NULL;
			if (pc->pp->fds->nolfd > 0) {
				int i;
				p->nolfd=pc->pp->fds->nolfd;
				p->lfdlist=(int *)malloc(p->nolfd * sizeof(int));
				memcpy(p->lfdlist,pc->pp->fds->lfdlist,p->nolfd * sizeof(int));
				for (i=0; i<p->nolfd; i++) {
					if (p->lfdlist[i] >=0 )
						++lfd_tab[p->lfdlist[i]]->count;
				}
			}
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
				register int lfd=fd2lfd(p,i);
				if (lfd >= 0) {
					pc->hte=lfd_tab[lfd]->hte;
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
int lfd_open (struct ht_elem *hte, int sfd, char *path, int flags, int nested)
{
	int lfd,fifo;
	GDEBUG(3, "lfd_open sfd %d, path %s, nested %d", sfd, path, nested);
	/*printk("lfd_open sfd %d, path %s, nested %d\n", sfd, path, nested);*/
	/*printk("lfd_open %s sfd %d %s",ht_get_servicename(hte),sfd,(path==NULL)?"<null>":path);*/
	lfd=lfd_alloc();
	if (hte)
		ht_count_plus1(hte);
	//printk("LEAK %x %x path=%s\n",lfd_tab,lfd_tab[lfd],path);
	lfd_tab[lfd]->path=(path==NULL)?NULL:strdup(path);
	lfd_tab[lfd]->hte=hte;
	lfd_tab[lfd]->sfd=sfd;
	lfd_tab[lfd]->flags=flags;
	lfd_tab[lfd]->epoch=um_setnestepoch(0);
	lfd_tab[lfd]->count=1;
	lfd_tab[lfd]->pvtab=NULL;
	if (hte != NULL && !nested) {
		char *filename;
		lfd_tab[lfd]->pvtab = (struct lfd_vtable *)malloc (sizeof(struct lfd_vtable));
		assert(lfd_tab[lfd]->pvtab != NULL);
		/* create the fifo to fake the file for the process,
		 * it will be used to give a fd to the process and to unblock
		 * select/pselect/poll/ppoll operations */
		filename=lfd_tab[lfd]->pvtab->filename=strdup(um_proc_tmpfile(hte,lfd));
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
		//printk("add lfd %d file %s\n",lfd,lfd_tab[lfd]->path);
		lfd_tab[lfd]->pvtab=NULL;
	}
	//printk("lfd_open: lfd %d sfd %d file %s\n",lfd,sfd,lfd_tab[lfd]->path);
	return lfd;
}

/* close a file */
void lfd_close (int lfd)
{
	int rv;
	GDEBUG(5, "close %d %x",lfd,lfd_tab[lfd]);
	//printk("lfd close %d %d %x %d %s\n",lfd_tab[lfd]->count,lfd,lfd_tabmax,lfd_tab[lfd],lfd_tab[lfd]->path);
	assert (lfd < 0 || (lfd < lfd_tabmax && lfd_tab[lfd] != NULL));
	/* if this is the last reference to the lfd 
	 * close everything*/
	if (lfd >= 0 && --(lfd_tab[lfd]->count) == 0) {
		register struct ht_elem *hte;
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
			//printk("del lfd %d file %s\n",lfd,lfd_tab[lfd]->path);
		hte=lfd_tab[lfd]->hte;
		/* call the close method of the service module */
		if (hte != NULL && lfd_tab[lfd]->sfd >= 0) 
			ht_syscall(hte,uscno(__NR_close))(lfd_tab[lfd]->sfd); 
		/* free path and structure */
		if (lfd_tab[lfd]->path != NULL)
			free(lfd_tab[lfd]->path);
		if (hte)
			ht_count_minus1(hte);
		lfd_free(lfd);
	}
}

/* dup: just increment the count, lfd is shared */
int lfd_dup(int lfd)
{
	if (lfd >= 0) {
		assert (lfd < lfd_tabmax && lfd_tab[lfd] != NULL);
		return ++lfd_tab[lfd]->count;
	} else
		return 1;
}
	
/* access method to read how many process fd share the same lfd element */
int lfd_getcount(int lfd)
{
	assert (lfd < lfd_tabmax && lfd_tab[lfd] != NULL);
	return lfd_tab[lfd]->count;
}

/* set sfd to null (to avoid double close) */
void lfd_nullsfd(int lfd)
{
	//printk("lfd_nullsfd %d %d %x\n",
			//lfd,lfd_tabmax,lfd_tab[lfd]);
	assert (lfd < lfd_tabmax && lfd_tab[lfd] != NULL);
	lfd_tab[lfd]->sfd= -1;
}

/* lfd 2 sfd conversion */
int lfd_getsfd(int lfd)
{
	assert (lfd < lfd_tabmax && lfd_tab[lfd] != NULL);
	return lfd_tab[lfd]->sfd;
}
	
/* lfd: get the hash table element */
struct ht_elem *lfd_getht(int lfd)
{
	//printk("getht %d -> %x\n",lfd,lfd_tab[lfd]);
	assert (lfd < lfd_tabmax && lfd_tab[lfd] != NULL);
	if (lfd >= lfd_tabmax || lfd_tab[lfd] == NULL)
		return NULL;
	return lfd_tab[lfd]->hte;
}
	
/* lfd: get the filename (of the fifo): for virtualized files*/
char *lfd_getfilename(int lfd)
{
	assert (lfd < lfd_tabmax && lfd_tab[lfd] != NULL && lfd_tab[lfd]->pvtab != NULL);
	return lfd_tab[lfd]->pvtab->filename;
}

/* lfd: get the path */
char *lfd_getpath(int lfd)
{
	assert (lfd < lfd_tabmax && lfd_tab[lfd] != NULL);
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
		//assert (lfd >= 0 && lfd < lfd_tabmax && lfd_tab[lfd] != NULL); 
		if (lfd >= 0 && lfd < lfd_tabmax && lfd_tab[lfd] != NULL) {
			return lfd_tab[lfd]->path;
		} else 
			return NULL;
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

/* tell the identifier of the service which manages given fd, or NULL if no
 * service handle it */
struct ht_elem *ht_fd(struct pcb_file *p, int fd, int setepoch)
{
	/*printk("service fd p=%x\n",p);
	if (p != NULL)
		printk("service fd p->lfdlist=%x\n",p->lfdlist);
	if (fd < p->nolfd)
		printk("service fd p=%d %x\n",fd, p->lfdlist[fd]);
	else
		printk("service fd p=%d xxx\n",fd); */
#ifdef _UM_MMAP
  /* ummap secret file is not accessible by processes, it is just a 
	 * non-existent descriptor */
	if (fd == um_mmap_secret) 
		return HT_ERR;
	else 
#endif
		if (fd >= 0 && fd < p->nolfd && p->lfdlist[fd] >= 0) {
			/* XXX side effect: when ht_fd finds a virtual file,
			 * it sets also the epoch */
			if (setepoch)
				um_setnestepoch(lfd_tab[FD2LFD(p,fd)]->epoch);
			return lfd_tab[FD2LFD(p,fd)]->hte;
		} else
			return NULL;
}
	
/* second phase of lfd_open: map the process fd to to lfd,
 * fd is known only after the kernel has completed its open
 * of the fifo */
void lfd_register (struct pcb_file *p, int fd, int lfd)
{
	//printk("lfd_register fd %d lfd %d\n",fd,lfd);
	if (fd >= p->nolfd) {
		int i=p->nolfd;
		/* adds about OLDFD_STEP=8 entries in the array */
		/* FIXME: if file descriptors aren't allocated linearly by
		 * Linux (e.g.: security extensions which gives random fds),
		 * very large arrays are allocated in this step. */
		p->nolfd = (fd + OLFD_STEP) & ~OLFD_STEP_1;
		p->lfdlist = (int *) realloc(p->lfdlist, p->nolfd * sizeof(int));
		assert (p->lfdlist);
		//printk("lfd_add realloc oldndf %d new %d\n",i,p->nolfd);
		if (p->lfdlist == NULL) {
			perror("no mem");
		}
		for (;i < p->nolfd; i++) 
			p->lfdlist[i]= -1;
	}
	p->lfdlist[fd]=lfd; /* CLOEXEC unset */
	//printk("lfd_register fd %d lfd %d %x\n", fd, lfd, lfd_tab[lfd]);
}

/* when a process closes a file must be closed (lfd element) and deregistered
 * from the process file table */
void lfd_deregister_n_close(struct pcb_file *p, int fd)
{
	//printk("lfd_deregister_n_close %d %d %d\n",fd,p->nolfd,p->lfdlist[fd]);
	//assert(fd < p->nolfd && p->lfdlist[fd] != -1);
	if (p->lfdlist != NULL && fd < p->nolfd && p->lfdlist[fd] >= 0) {
		//printk("lfd_deregister_n_close LFD %d\n",FD2LFD(p,fd));
		lfd_close(FD2LFD(p,fd));
		p->lfdlist[fd] = -1;
	}
}

/* final clean up of all the fifos */
static void lfd_closeall_item(int lfd, void *arg)
{
	if (lfd_tab[lfd]->pvtab != NULL) {
		r_close(lfd_tab[lfd]->pvtab->ififo);
		r_close(lfd_tab[lfd]->pvtab->ofifo);
		r_unlink(lfd_tab[lfd]->pvtab->filename);
	}
}

void lfd_closeall()
{
	lfd_forall(lfd_closeall_item,NULL);
}

/* unblock a process waiting on a select/poll call */
void lfd_signal(int lfd)
{
	char ch=0;
	//printk("lfd_signal %d\n",lfd);
	assert (lfd < lfd_tabmax && lfd_tab[lfd] != NULL);
	if  (lfd < lfd_tabmax && lfd_tab[lfd] != NULL && lfd_tab[lfd]->pvtab != NULL) {
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
	assert (lfd < lfd_tabmax && lfd_tab[lfd] != NULL && lfd_tab[lfd]->pvtab != NULL);
	if (lfd_tab[lfd]->pvtab->signaled == 1) {
		lfd_tab[lfd]->pvtab->signaled = 0;
		r_read(lfd_tab[lfd]->pvtab->ififo,buf,1024);
	}
}

/* sfd + service --2--> path conversion
 * linear scan, slow! */

static void *sfd_getpath_check(int lfd, void *arg1, void *arg2)
{
	struct ht_elem *hte=arg1;
	int *psfd=arg2;
	if (lfd_tab[lfd]->hte == hte && lfd_tab[lfd]->sfd == *psfd)
		return lfd_tab[lfd]->path;
	else
		return NULL;
}

char *sfd_getpath(struct ht_elem *hte, int sfd)
{
	return lfd_forall_r(sfd_getpath_check,hte,&sfd);
}
