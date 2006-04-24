/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   um_proc.c: process file table and fake files mgmt
 *   
 *   Copyright 2005 Renzo Davoli University of Bologna - Italy
 *   Modified 2005 Mattia Belletti
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
#include <limits.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include "umproc.h"
#include "scmap.h"
#include "defs.h"
#include "real_syscalls.h"

static char *um_proc_root;
static char *um_tmpfile;
static char *um_tmpfile_tail;
static int um_tmpfile_len;

struct lfd_table {
	short count; /*how many pcbs have opened this lfd - look at dup implementation */
	service_t service; /*the service code */
	int sfd; /* the fd as seen from the service */
	char *path; /* the real path */
};

struct lfd_vtable {
	int signaled;   /* set when there some data on the fifo, telling that
			   some blocking call have to be unblocked, not yet
			   read - a flag */
	char *filename; /* the fifo */
	int ififo,ofifo;
};

struct lfd_top {
	struct lfd_table *ptab;
	struct lfd_vtable *pvtab;
};

static short um_maxlfd=0;
static struct lfd_top *lfd_tab=NULL;

void um_proc_open()
{
	char path[PATH_MAX];
	snprintf(path,PATH_MAX,"/tmp/.umproc%ld",(long int)getpid());
	//printf("um_proc_open %s\n",path);

	if(mkdir(path,0700) < 0) {
		perror("um_proc makefile");
		exit (-1);
	}
	um_proc_root=strdup(path);
	strcpy(um_proc_root,path);
	strcat(path,"/lfd.xxXXXXX");
	um_tmpfile=strdup(path);
	strcpy(um_tmpfile,path);
	um_tmpfile_tail=um_tmpfile+(strlen(path)-7);
	um_tmpfile_len=strlen(um_tmpfile);
}

void um_proc_close()
{
	//printf("um_proc_close %s\n",um_proc_root);
	//rm all the remaining fifos and files XXX
	lfd_closeall();
	rmdir(um_proc_root);
}

static char *um_proc_tmpfile(service_t service, int lfd)
{
	snprintf(um_tmpfile_tail,um_tmpfile_len,"%02x%02d",service,lfd);
	//printf("um_proc_tmpfile %s\n",um_tmpfile);
	return um_tmpfile;
}

#define NMAX 1000000
char *um_proc_tmpname()
{
	static int n;
	n = (n+1) % NMAX;
	snprintf(um_tmpfile_tail,um_tmpfile_len,"%06d",n);
	//printf("um_proc_tmpname %s\n",um_tmpfile);
	return um_tmpfile;
}

void lfd_addproc (struct pcb_file **pp,int flag)
{
	//printf("ADDPROC %x\n",flag);
	/* flag => CLONE_FILES is set */
	if (flag) {
		struct pcb_file *p=*pp;
		assert (p != NULL);
		p->count++;
	} else {
		struct pcb_file *p=*pp=(struct pcb_file *)malloc(sizeof(struct pcb_file));
		p->count=1;
		p->nolfd=0;
		p->lfdlist=NULL;
	}
}

void lfd_delproc (struct pcb_file *p, void *umph)
{
	int i;
	//printf("DELPROC count %d nolfd %d\n",p->count,p->nolfd);
	p->count--;
	if (p->count == 0) {
		for (i=0; i<p->nolfd;  i++) {
			register int lfd=p->lfdlist[i];
			if (lfd >= 0) {
			/*	if ((--lfd_tab[lfd].ptab->count) == 0) {
					register int service=lfd_tab[lfd].ptab->service;
					if (service != UM_NONE) {
						service_syscall(service,uscno(__NR_close))(lfd_tab[lfd].ptab->sfd);
					}
				} */
				//printf("CLOSE LFD %d\n",lfd);
				lfd_close(lfd,umph);
			}
		}
		if (p->lfdlist != NULL)
			free(p->lfdlist);
		free(p);
	}
}

/* open file/socket has two phases: the real open and the register.
 * in the second phase registers the map between the fd as seen by the process and
 * our lfd */
int lfd_open (service_t service, int sfd, char *path)
{
	int lfd,fifo;
	//printf("lfd_open %x sfd %d %s",service,sfd,(path==NULL)?"<null>":path);
	/* looks for a free local file descriptor */
	for (lfd=0; lfd<um_maxlfd && lfd_tab[lfd].ptab != NULL ; lfd++)
		;
	/* if there are none, expands the lfd table */
	if (lfd >= um_maxlfd) {
		int i=um_maxlfd;
		//printf("lfd_tab realloc oldndf %d\n",um_maxlfd);
		um_maxlfd = (lfd + OLFD_STEP) & ~OLFD_STEP_1;
		//printf("lfd_tab realloc newnfd %d\n",um_maxlfd);
		lfd_tab=(struct lfd_top *) realloc (lfd_tab, (um_maxlfd * sizeof (struct lfd_top)));
		assert (lfd_tab);

		/* Clean the new entries in lfd_tab or lfd_cleanall will not work properly */
		for (;i < um_maxlfd;i++)
		{
			lfd_tab[i].pvtab=NULL;
			lfd_tab[i].ptab=NULL;
		}
	}
	assert(lfd_tab[lfd].ptab == NULL);
	lfd_tab[lfd].ptab = (struct lfd_table *)malloc (sizeof(struct lfd_table));
	assert(lfd_tab[lfd].ptab != NULL);
	//printf("LEAK %x %x path=%s\n",lfd_tab,lfd_tab[lfd].ptab,path);
	lfd_tab[lfd].ptab->path=(path==NULL)?NULL:strdup(path);
	lfd_tab[lfd].ptab->service=service;
	lfd_tab[lfd].ptab->sfd=sfd;
	lfd_tab[lfd].ptab->count=1;
	if (service != UM_NONE) {
		char *filename;
		lfd_tab[lfd].pvtab = (struct lfd_vtable *)malloc (sizeof(struct lfd_vtable));
		assert(lfd_tab[lfd].pvtab != NULL);
		filename=lfd_tab[lfd].pvtab->filename=strdup(um_proc_tmpfile(service,lfd));
		fifo=mkfifo(filename,0600);
		assert(fifo==0);
		lfd_tab[lfd].pvtab->ififo=open(filename,O_RDONLY|O_NONBLOCK);
		assert(lfd_tab[lfd].pvtab->ififo >= 0);
		lfd_tab[lfd].pvtab->ofifo=open(filename,O_WRONLY);
		assert(lfd_tab[lfd].pvtab->ofifo >= 0);
		lfd_tab[lfd].pvtab->signaled=0;
	} else {
		//printf("add lfd %d file %s\n",lfd,lfd_tab[lfd].ptab->path);
		lfd_tab[lfd].pvtab=NULL;
	}
	//printf("lfd_open: lfd %d sfd %d file %s\n",lfd,sfd,lfd_tab[lfd].ptab->path);
	return lfd;
}

void lfd_close (int lfd,void *umph)
{
	int rv;
	//printf("close %d %x\n",lfd,lfd_tab[lfd].ptab);
	assert (lfd < 0 || (lfd < um_maxlfd && lfd_tab[lfd].ptab != NULL));
	if (lfd >= 0 && --(lfd_tab[lfd].ptab->count) == 0) {
		if (lfd_tab[lfd].pvtab != NULL) {
			rv=close(lfd_tab[lfd].pvtab->ififo);
			assert(rv==0);
			rv=close(lfd_tab[lfd].pvtab->ofifo);
			assert(rv==0);
			rv=unlink(lfd_tab[lfd].pvtab->filename);
			assert(rv==0);
			free(lfd_tab[lfd].pvtab->filename);
			free(lfd_tab[lfd].pvtab);
		} 
		//else
			//printf("del lfd %d file %s\n",lfd,lfd_tab[lfd].ptab->path);
		register int service=lfd_tab[lfd].ptab->service;
		if (service != UM_NONE && lfd_tab[lfd].ptab->sfd >= 0) {
			service_syscall(service,uscno(__NR_close))(lfd_tab[lfd].ptab->sfd,umph); 
		}
		if (lfd_tab[lfd].ptab->path != NULL)
			free(lfd_tab[lfd].ptab->path);
		free(lfd_tab[lfd].ptab);
		lfd_tab[lfd].ptab=NULL;
	}
}

int lfd_dup(int lfd)
{
	if (lfd >= 0) {
		assert (lfd < um_maxlfd && lfd_tab[lfd].ptab != NULL);
		return ++lfd_tab[lfd].ptab->count;
	} else
		return 1;
}
	
int lfd_getcount(int lfd)
{
	assert (lfd < um_maxlfd && lfd_tab[lfd].ptab != NULL);
	return lfd_tab[lfd].ptab->count;
}

void lfd_nullsfd(int lfd)
{
	//printf("lfd_nullsfd %d %d %x\n",
			//lfd,um_maxlfd,lfd_tab[lfd].ptab);
	assert (lfd < um_maxlfd && lfd_tab[lfd].ptab != NULL);
	lfd_tab[lfd].ptab->sfd= -1;
}

int lfd_getsfd(int lfd)
{
	assert (lfd < um_maxlfd && lfd_tab[lfd].ptab != NULL);
	return lfd_tab[lfd].ptab->sfd;
}
	
service_t lfd_getservice(int lfd)
{
	//printf("getservice %d -> %x\n",lfd,lfd_tab[lfd].ptab);
	assert (lfd < um_maxlfd && lfd_tab[lfd].ptab != NULL);
	return lfd_tab[lfd].ptab->service;
}
	
char *lfd_getfilename(int lfd)
{
	assert (lfd < um_maxlfd && lfd_tab[lfd].pvtab != NULL);
	return lfd_tab[lfd].pvtab->filename;
}

char *lfd_getpath(int lfd)
{
	assert (lfd < um_maxlfd && lfd_tab[lfd].ptab != NULL);
	return lfd_tab[lfd].ptab->path;
}

int fd2lfd(struct pcb_file *p, int fd)
{
	if (fd>=0 && fd < p->nolfd)
		return p->lfdlist[fd];
	else
		return -1;
}
	
char *fd_getpath(struct pcb_file *p, int fd)
{
	if (fd>=0 && fd < p->nolfd) {
		int lfd=p->lfdlist[fd];
		if (lfd >= 0 && lfd < um_maxlfd && lfd_tab[lfd].ptab != NULL) {
			return lfd_tab[lfd].ptab->path;
		} else {
			return NULL;
		}
	} else
		return NULL;
}

int fd2sfd(struct pcb_file *p, int fd)
{
	if (fd>=0 && fd < p->nolfd && p->lfdlist[fd] >= 0)
		return lfd_tab[p->lfdlist[fd]].ptab->sfd;
	else
		return -1;
}

/* tell the identifier of the service which manages given fd, or UM_NONE if no
 * service handle it */
service_t service_fd(struct pcb_file *p, int fd)
{
	//printf("service fd p=%x\n",p);
	//if (p != NULL)
	//	printf("service fd p->lfdlist=%x\n",p->lfdlist);
	/*if (fd < p->nolfd)
		printf("service fd p=%d %x\n",fd, p->lfdlist[fd]);
	else
		printf("service fd p=%d xxx\n",fd); */
	if (fd >= 0 && fd < p->nolfd && p->lfdlist[fd] >= 0)
		return lfd_tab[p->lfdlist[fd]].ptab->service;
	else
		return UM_NONE;
}
	
void lfd_register (struct pcb_file *p, int fd, int lfd)
{
	//printf("lfd_register fd %d lfd %d\n",fd,lfd);
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
	p->lfdlist[fd]=lfd;
	//printf("lfd_register fd %d lfd %d path %s\n", fd, lfd, lfd_tab[lfd].ptab->path);
}

void lfd_deregister_n_close(struct pcb_file *p, int fd,void *umph)
{
	//printf("lfd_deregister_n_close %d %d \n",fd,p->nolfd);
	//assert(fd < p->nolfd && p->lfdlist[fd] != -1);
	if (p->lfdlist != NULL && fd < p->nolfd && p->lfdlist[fd] != -1) {
		lfd_close(p->lfdlist[fd],umph);
		p->lfdlist[fd] = -1;
	}
}

void lfd_closeall()
{
	register int lfd;
	for (lfd=0; lfd<um_maxlfd; lfd++) {
		if (lfd_tab[lfd].pvtab != NULL) {
			close(lfd_tab[lfd].pvtab->ififo);
			close(lfd_tab[lfd].pvtab->ofifo);
			unlink(lfd_tab[lfd].pvtab->filename);
		}
	}
}

void lfd_signal(int lfd)
{
	char ch=0;
	//printf("lfd_signal %d\n",lfd);
	assert (lfd < um_maxlfd && lfd_tab[lfd].pvtab != NULL);
	if (lfd_tab[lfd].pvtab->signaled == 0) {
		lfd_tab[lfd].pvtab->signaled = 1;
		write(lfd_tab[lfd].pvtab->ofifo,&ch,1);
	}
}

void lfd_delsignal(int lfd)
{
	char buf[1024];
	assert (lfd < um_maxlfd && lfd_tab[lfd].pvtab != NULL);
	if (lfd_tab[lfd].pvtab->signaled == 1) {
		lfd_tab[lfd].pvtab->signaled = 0;
		read(lfd_tab[lfd].pvtab->ififo,buf,1024);
	}
}

char *sfd_getpath(service_t code, int sfd)
{
	int lfd;
	for (lfd=0; lfd<um_maxlfd; lfd++)
		if(lfd_tab[lfd].ptab && lfd_tab[lfd].ptab->service == code &&
				lfd_tab[lfd].ptab->sfd == sfd)
			return lfd_tab[lfd].ptab->path;
	return NULL;
}
