/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   UMMISC: Virtual Miscellanea in Userspace
 *   (time/user/uname system call virtualization)
 *    Copyright (C) 2007  Renzo Davoli <renzo@cs.unibo.it>
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <dlfcn.h>
#include <pthread.h>
#include <sys/mount.h>

#include <config.h>
#include "module.h"
#include "libummod.h"
#include "ummisc.h"
#include "ummiscfun.h"

#define TRUE 1
#define FALSE 0

#define UMMISC_SERVICE_CODE 0x06

#ifndef __UMMISC_DEBUG_LEVEL__
#define __UMMISC_DEBUG_LEVEL__ 0
#endif

#ifdef __UMMISC_DEBUG__
#define PRINTDEBUG(level,args...) printdebug(level, __FILE__, __LINE__, __func__, args)
#else
#define PRINTDEBUG(level,args...)
#endif

static struct service s;

struct ummisc {
	char *path;
	int pathlen;
	void *dlhandle;
	struct timestamp tst;
	fd_set scset;
	struct ummisc_operations *ummisc_ops;
	void *private_data;
};

struct fileinfo {
	int count;        /* number of processes that opened the file */
	loff_t pos;        /* file offset */
	loff_t size;        /* file size */
	int flags;
	char *path;
	char *buf;
	struct fsentry *fse;
	struct ummisc *ummisc;
};

#define WORDLEN sizeof(int *)
#define WORDALIGN(X) (((X) + WORDLEN) & ~(WORDLEN-1))
#define SIZEDIRENT64NONAME (sizeof(__u64)+sizeof(__s64)+sizeof(unsigned short)+sizeof(unsigned char))

#define MNTTABSTEP 4 /* must be a power of two */
#define MNTTABSTEP_1 (MNTTABSTEP-1)
#define FILETABSTEP 4 /* must be a power of two */
#define FILETABSTEP_1 (FILETABSTEP-1)

#define EXACT 1
#define SUBSTR 0

static struct fileinfo **filetab=NULL;
static int filetabmax=0;

static struct ummisc **misctab=NULL;
static int misctabmax=0;

#if 0
static pthread_key_t mcontext_key;
struct misc *misc_get_context(void)
{
	return pthread_getspecific(mcontext_key);
}

static struct misc *misc_gs_context(struct misc *mc)
{
	struct misc *oldmc=(struct misc *) pthread_getspecific(mcontext_key);
	//fprint2("TRUE misc_gs_context %p old=%p %d\n",mc,oldmc,pthread_self());
	pthread_setspecific(mcontext_key, mc);
	return oldmc;
}

static void misc_set_context(struct misc *mc)
{
	//fprint2("TRUE misc_set_context %p %d\n",mc,pthread_self());
	pthread_setspecific(mcontext_key, mc);
}
#endif

static void cutdots(char *path)
{
	int l=strlen(path);
	l--;
	if (path[l]=='.') {
		l--;
		if(path[l]=='/') {
			if (l!=0) path[l]=0; else path[l+1]=0;
		} else if (path[l]=='.') {
			l--;
			if(path[l]=='/') {
				while(l>0) {
					l--;
					if (path[l]=='/')
						break;
				}
				if(path[l]=='/') {
					if (l!=0) path[l]=0; else path[l+1]=0;
				}
			}
		}
	}
}

static struct ummisc *searchmisc(char *path,int exact)
{
	register int i;
	struct ummisc *result=NULL;
	struct stat64 buf;
	epoch_t maxepoch=0;
	int maxi=-1;

	PRINTDEBUG(0,"SearchContext:%s\n",path);
	//fprint2("SearchContext:%s\n",path);
	cutdots(path);
	for (i=0;i<misctabmax;i++)
	{
		epoch_t e;
		if ((misctab[i] != NULL)) {
			epoch_t prevepoch=um_setepoch(misctab[i]->tst.epoch);
			//fprint2("%s %s %d\n",path,misctab[i]->path,exact);
			//fprint2("]]%d %d\n",strncmp(path,misctab[i]->path,misctab[i]->pathlen),tst_matchingepoch(&(misctab[i]->tst)));
			if (exact) {
				if ((strcmp(path,misctab[i]->path) == 0) &&
						((e=tst_matchingepoch(&(misctab[i]->tst))) > maxepoch)) {
					maxi=i;
					maxepoch=e;
				} 
			} else {
				int len=misctab[i]->pathlen;
				//fprint2("+%s %s %d\n",path,misctab[i]->path,len);
				if ((strncmp(path,misctab[i]->path,len) == 0 && (path[len] == '/' || path[len]=='\0')) &&
						((e=tst_matchingepoch(&(misctab[i]->tst))) > maxepoch)) {
					maxi=i;
					maxepoch=e;
				}
			}
			um_setepoch(prevepoch);
		}
	}
	if (maxi >= 0)
		result=misctab[maxi];
	//fprint2("SearchContext:%s -> %d\n",path,result);
	return result;
}

void *misc_getdl(struct ummisc *mh)
{
	return mh->dlhandle;
}

struct ummisc *searchmisc_sc(int scno)
{
	register int i;
	struct ummisc *result=NULL;
	epoch_t maxepoch=0;
	int maxi=-1;

	PRINTDEBUG(0,"SearchSC:%d\n",scno);
	for (i=0;i<misctabmax;i++)
	{
		epoch_t e;
		if ((misctab[i] != NULL)) {
			epoch_t prevepoch=um_setepoch(misctab[i]->tst.epoch);
			//fprint2("searchmisc_sc %d %d %lld\n",
			//scno,FD_ISSET(scno,&(misctab[i]->scset)),
			//tst_matchingepoch(&(misctab[i]->tst)));
			if (FD_ISSET(scno,&(misctab[i]->scset)) &&
					((e=tst_matchingepoch(&(misctab[i]->tst))) > maxepoch)) {
				maxi=i;
				maxepoch=e;
			}
			um_setepoch(prevepoch);
		}
	}
	if (maxi >= 0)
		result=misctab[maxi];
	return result;
}

/*insert a new context in the misc table*/ 
static struct ummisc *addmisctab(struct ummisc *new)
{
	register int i;
	//pthread_mutex_lock( &misctab_mutex );
	for (i=0;i<misctabmax && misctab[i] != NULL;i++)
		;
	if (i>=misctabmax) {
		register int j;
		register int misctabnewmax=(i + MNTTABSTEP) & ~MNTTABSTEP_1;
		misctab=(struct ummisc **)realloc(misctab,misctabnewmax*sizeof(struct ummisc *));
		assert(misctab);
		for (j=i;j<misctabnewmax;j++)
			misctab[j]=NULL;
		misctabmax=misctabnewmax;
	}
	misctab[i]=new;
	//pthread_mutex_unlock( &misctab_mutex );
	return misctab[i];
} 

/* execute a specific function (arg) for each misctab element */
static void forallmisctabdo(void (*fun)(struct ummisc *mc))
{
	register int i;
	for (i=0;i<misctabmax;i++) 
		if (misctab[i] != NULL)
			fun(misctab[i]);
} 

/*
 * delete the i-th element of the tab.
 * the table cannot be compacted as the index is used as id
 */
static void delmisctab(struct ummisc *mc)
{
	register int i;
	//pthread_mutex_lock( &misctab_mutex );
	for (i=0;i<misctabmax && mc != misctab[i];i++)
		;
	if (i<misctabmax)
		misctab[i]=NULL;
	else
		fprint2("delmnt inexistent entry\n");
	//pthread_mutex_unlock( &misctab_mutex );
}

/* add an element to the filetab (open file table)
 *  * each file has a fileinfo record
 *   */
static int addfiletab()
{
	register int i;
	//pthread_mutex_lock( &misctab_mutex );
	for (i=0;i<filetabmax && filetab[i] != NULL;i++)
		;
	if (i>=filetabmax) {
		register int j;
		filetabmax=(i + MNTTABSTEP) & ~MNTTABSTEP_1;
		filetab=(struct fileinfo **)realloc(filetab,filetabmax*sizeof(struct fileinfo *));
		assert(filetab);
		for (j=i;j<filetabmax;j++)
			filetab[j]=NULL;
	}
	filetab[i]=(struct fileinfo *)malloc(sizeof(struct fileinfo));
	assert(filetab[i]);
	//pthread_mutex_unlock( &misctab_mutex );
	return i;
}

/* delete an entry from the open file table.
 * RD: there is a counter managed by open and close calls */
static void delfiletab(int i)
{
	struct fileinfo *norace=filetab[i];
	filetab[i]=NULL;
	free(norace);
}

static epoch_t ummisc_check(int type, void *arg)
{
	if (type == CHECKPATH) {
		char *path=arg;
		struct ummisc *mc=searchmisc(path,SUBSTR);
		if ( mc != NULL) {
			return mc->tst.epoch;
		}
		else
			return FALSE;
	} else if (type == CHECKFSTYPE) {
		char *path=arg;
		return (strncmp(path,"ummisc",5) == 0);
	} else if (type == CHECKSC) {
		int scno=*((int *) arg);
		struct ummisc *mc=searchmisc_sc(scno);
		if ( mc != NULL) {
			return mc->tst.epoch;
		}
		else
			return FALSE;
	} else {
		return FALSE;
	}
}

static char *unwrap(struct ummisc *mh,char *path)
{
	char *reduced=path+mh->pathlen;
	if (*reduced=='/') reduced++;
	return(reduced);
}

static int strpathcmp(char *s1,char *s2)
{
	int c=0;
	while (*s1 && *s2 && c==0)
		c=s2-s1;
	if (*s1 == *s2 || *s1 == '/' || *s2 == '/')
		return 0;
	else
		return c;
}

static struct fsentry *recsearch(struct fsentry *fsdir,struct fsentry *fse,char *path)
{
	//fprint2("%p %p %s\n",fsdir,fse,path);
	if (*path == 0)
		return(fsdir);
	else{
		if (*path == '/')
			path++;
		if (fse==NULL || fse->name==NULL)
			return NULL;
		else {
			if (strpathcmp(fse->name,path) == 0)
			{
				path+=strlen(fse->name);
				return recsearch(fse,fse->subdir,path);
			} else
				return recsearch(fsdir,fse+1,path);
		}
	}
}

static struct fsentry *searchentry(struct ummisc *mh,char *path)
{
	return recsearch(&(mh->ummisc_ops->root),mh->ummisc_ops->root.subdir,path);
}

static struct fsentry nullroot[] = {
	  {NULL,NULL,NULL,0}};

static long ummisc_open(char *path, int flags, mode_t mode)
{
	struct ummisc *mh = searchmisc(path,SUBSTR);
	assert(mh);
	char *upath=unwrap(mh,path);
	//fprint2("open |%s| %d\n",upath,*upath);
	struct fsentry *fse=searchentry(mh,upath);
	if (fse != NULL) {
		int fi = addfiletab();
		int rv;
		filetab[fi]->count = 1;
		filetab[fi]->pos = 0;
		filetab[fi]->flags = flags & ~(O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC);
		filetab[fi]->path=strdup(upath);
		//fprint2("%d %lld %s\n",fi,filetab[fi]->pos,filetab[fi]->path);
		filetab[fi]->fse=fse;
		filetab[fi]->ummisc=mh;
		/* is a dir, root is always a dir! */
		if (fse->subdir != NULL || *upath==0) {
			if (fse->subdir==NULL)
				fse->subdir=nullroot;
			filetab[fi]->buf = NULL;
			filetab[fi]->size = 0;
		} else {
			filetab[fi]->buf = calloc(MISCFILESIZE,1);
			assert(filetab[fi]->buf != NULL);
			filetab[fi]->size=fse->getputfun(UMMISC_GET,filetab[fi]->buf,MISCFILESIZE,mh,
					filetab[fi]->fse->tag,filetab[fi]->path);
			if (flags & O_TRUNC) filetab[fi]->size=0;
		}
		return fi;
	} else {
		errno=ENOENT;
		return -1;
	}
}

static long ummisc_close(int fd)
{
	int rv;

	if (filetab[fd]==NULL) {
		errno=EBADF;
		return -1;
	} else {
		struct ummisc *mh = filetab[fd]->ummisc;
		//fprint2("close %s\n",filetab[fd]->path);
		filetab[fd]->count--;
		if (filetab[fd]->count == 0) {
			if (filetab[fd]->fse->getputfun != NULL &&
					filetab[fd]->flags & O_ACCMODE != 0) { /*O_WRONLY or O_RDWR */
				filetab[fd]->fse->getputfun(UMMISC_PUT,filetab[fd]->buf,filetab[fd]->size,mh,
						filetab[fd]->fse->tag,filetab[fd]->path);
			}
			if (filetab[fd]->buf != NULL)
				free(filetab[fd]->buf);
			free(filetab[fd]->path);
			delfiletab(fd);
		}
		return 0;
	}
}

static long ummisc_read(int fd, char *buf, size_t count)
{
	int rv;
	if (filetab[fd]==NULL) {
		errno=EBADF;
		return -1;
	} else {
		//fprint2("READIN %d c%d p%lld s%lld \n",rv,
		//count, filetab[fd]->pos, filetab[fd]->size);
		for (rv=0; rv< count; rv++) {
			if (filetab[fd]->pos > filetab[fd]->size)
				break;
			if (filetab[fd]->buf[filetab[fd]->pos] == 0)
				break;
			buf[rv]=filetab[fd]->buf[filetab[fd]->pos];
			filetab[fd]->pos++;
		}
		//fprint2("READ %d c%d p%lld s%lld %s\n",rv,
		//	count, filetab[fd]->pos, filetab[fd]->size, buf);
		return rv;
	}
}

static long ummisc_write(int fd, char *buf, size_t count)
{
	int rv;
	if (filetab[fd]==NULL ||
			filetab[fd]->flags & O_ACCMODE == 0) {
		errno=EBADF;
		return -1;
	} else {
		for (rv=0; rv< count; rv++) {
			if (filetab[fd]->pos >= MISCFILESIZE) /* it keeps one char for \0 */
				break;
			filetab[fd]->buf[filetab[fd]->pos]=buf[rv];
			filetab[fd]->pos++;
		}
		if (filetab[fd]->pos > filetab[fd]->size)
			filetab[fd]->size=filetab[fd]->pos;
		return rv;
	}
}

static setstat64(struct stat64 *buf64, int isdir)
{
	memset(buf64,0,sizeof(struct stat64));
	if (isdir)
		buf64->st_mode=S_IFDIR | 0555;
	else
		buf64->st_mode=S_IFREG | 0666;
	buf64->st_size=MISCFILESIZE;
}

static long ummisc_fstat64(int fd, struct stat64 *buf64)
{
	if (fd < 0 || filetab[fd] == NULL) {
		errno=EBADF;
		return -1;
	} else {
		setstat64(buf64,filetab[fd]->buf == NULL);
		return 0;
	}
}

static long ummisc_stat64(char *path, struct stat64 *buf64)
{
	struct ummisc *mh = searchmisc(path,SUBSTR);
	assert(mh);
	char *upath=unwrap(mh,path);
	struct fsentry *fse=searchentry(mh,upath);
	//fprint2("stat64 %s %p\n",path,fse);
	if (fse != NULL) {
		setstat64(buf64,fse->getputfun == NULL);
		return 0;
	} else {
		errno=ENOENT;
		return -1;
	}
}

/* TODO management of fcntl */
static long ummisc_fcntl64(int fd, int cmd, void *arg)
{
	//print2("ummisc_fcntl64\n");
	errno=0;
	return 0;
}

static long ummisc_fsync(int fd, int cmd, void *arg)
{
	//print2("ummisc_fcntl64\n");
	errno=0;
	return 0;
}

static long ummisc_access(char *path, int mode)
{
	struct ummisc *mh = searchmisc(path,SUBSTR);
	assert(mh);
	char *upath=unwrap(mh,path);
	struct fsentry *fse=searchentry(mh,upath);
	if (fse != NULL) {
		return 0;
	} else {
		errno=ENOENT;
		return -1;
	}
}

static loff_t ummisc_lseek(int fd, off_t offset, int whence)
{
	int rv;
	if (filetab[fd]==NULL) {
		errno=EBADF;
		return -1;
	} else {
		switch (whence) {
			case SEEK_SET: filetab[fd]->pos=offset; break;
			case SEEK_CUR: filetab[fd]->pos+=offset; break;
			case SEEK_END: filetab[fd]->pos=strlen(filetab[fd]->buf)+offset; break;
		}
		if (filetab[fd]->pos < 0) filetab[fd]->pos=0;
	}
	return 0;
}

static long dirsize(struct fsentry *fsdir)
{
	int size=0;
	if (fsdir != NULL) {
		while (fsdir->name != NULL) {
			//fprint2("dirsize add %s %d\n",fsdir->name,WORDALIGN(SIZEDIRENT64NONAME+strlen(fsdir->name)+1));
			size+=WORDALIGN(SIZEDIRENT64NONAME+strlen(fsdir->name)+1);
			fsdir++;
		}
	}
	return size;
}

static void dirpopulate(struct fsentry *fsdir,char *dirp)
{
	int off=0;
	if (fsdir != NULL) {
		while (fsdir->name != NULL) {
			struct dirent64 *this=(struct dirent64 *) dirp;
			//fprint2("dirpop add %s %d\n",fsdir->name,WORDALIGN(SIZEDIRENT64NONAME+strlen(fsdir->name)+1));
			this->d_ino=2;
			this->d_reclen=WORDALIGN(SIZEDIRENT64NONAME+strlen(fsdir->name)+1);
			off+=this->d_reclen;
			//off+=WORDALIGN(12+strlen(fsdir->name));;
			this->d_off=off;
			strcpy(this->d_name,fsdir->name);
			dirp+=this->d_reclen;
			fsdir++;
		}
	}
}

static long ummisc_getdents64(unsigned int fd, struct dirent64 *dirp, unsigned int count) {
	if (filetab[fd]==NULL) {
		errno=EBADF;
		return -1;
	} else if (filetab[fd]->fse->subdir == NULL) {
		errno=ENOTDIR;
		return -1;
	} else {
		int rv=0;
		struct dirent64 *this;
		if (filetab[fd]->buf==NULL) {
			filetab[fd]->size=dirsize(filetab[fd]->fse->subdir);
			//fprint2("ummisc_getdents64 size=%d\n",filetab[fd]->size);
			filetab[fd]->buf=malloc(filetab[fd]->size);
			assert(filetab[fd]->buf != NULL);
			dirpopulate(filetab[fd]->fse->subdir,filetab[fd]->buf);
			//fprint2("ummisc_dirpopulate size=%d\n",filetab[fd]->size);
		}
		while (rv+filetab[fd]->pos < filetab[fd]->size) {
			this=(struct dirent64 *)(filetab[fd]->buf+filetab[fd]->pos+rv);
			if (rv+filetab[fd]->pos > filetab[fd]->size)
				break;
			if (rv+this->d_reclen > count)
				break;
			rv+=this->d_reclen;
		}
		memcpy((char*) dirp, filetab[fd]->buf + filetab[fd]->pos, rv);
		filetab[fd]->pos += rv;
		//fprint2("getdents64 returns %d\n",rv);
		return rv;
	}
}

static long ummisc_mount(char *source, char *target, char *filesystemtype,
		unsigned long mountflags, void *data)
{
	void *dlhandle = openmodule(filesystemtype, RTLD_NOW);
	struct ummisc_operations *ummisc_ops;

	PRINTDEBUG(10, "MOUNT %s %s %s %x %s\n",source,target,filesystemtype,
			mountflags, (data!=NULL)?data:"<NULL>");

	if(dlhandle == NULL || (ummisc_ops=dlsym(dlhandle,"ummisc_ops")) == NULL) {
		fprint2("%s\n",dlerror());
		if(dlhandle != NULL)
			dlclose(dlhandle);
		errno=ENODEV;
		return -1;
	} else {
		struct ummisc *new = (struct ummisc *) malloc(sizeof(struct ummisc));
		struct stat64 *s64;
		int i;
		assert(new);
		s64=um_mod_getpathstat();
		new->path = strdup(target);
		new->pathlen = strlen(target);
		new->dlhandle=dlhandle;
		setscset(dlhandle,&(new->scset));
		new->ummisc_ops=ummisc_ops;
		new->private_data = NULL;
		if (new->ummisc_ops->init) 
			new->ummisc_ops->init(target,mountflags,data,new);
		new->tst=tst_timestamp();
		addmisctab(new);
		return 0;
	}
}

static long ummisc_umount2(char *target, int flags)
{
	struct ummisc *mh = searchmisc(target,EXACT);
	if (mh == NULL) {
		errno=EINVAL;
		return -1;
	} else {
		if (mh->ummisc_ops->fini) 
			mh->ummisc_ops->fini(mh);
		delmisctab(mh);
		free(mh->path);
		free(mh);
		return 0;
	}
}

static void contextclose(struct ummisc *mc)
{
	ummisc_umount2(mc->path,MNT_FORCE);
}   

void ummisc_setprivatedata(struct ummisc *mischandle, void *privatedata)
{
	if(mischandle)
		mischandle->private_data=privatedata;
}

void *ummisc_getprivatedata(struct ummisc *mischandle)
{
	if(mischandle)
		return mischandle->private_data;
}

	static void
	__attribute__ ((constructor))
init (void)
{
	fprint2("ummisc init\n");
	s.name="ummisc";
	s.code=UMMISC_SERVICE_CODE;
	s.checkfun=ummisc_check;
	//pthread_key_create(&mcontext_key,NULL);
	s.syscall=(sysfun *)calloc(scmap_scmapsize,sizeof(sysfun));
	s.socket=(sysfun *)calloc(scmap_sockmapsize,sizeof(sysfun));
	SERVICESYSCALL(s, mount, ummisc_mount);
	SERVICESYSCALL(s, umount2, ummisc_umount2);
	SERVICESYSCALL(s, open, ummisc_open);
	SERVICESYSCALL(s, read, ummisc_read);
	SERVICESYSCALL(s, write, ummisc_write);
	SERVICESYSCALL(s, close, ummisc_close);
	SERVICESYSCALL(s, stat64, ummisc_stat64);
	SERVICESYSCALL(s, lstat64, ummisc_stat64);
	SERVICESYSCALL(s, fstat64, ummisc_fstat64);
	SERVICESYSCALL(s, fcntl64, ummisc_fcntl64);
	SERVICESYSCALL(s, fsync, ummisc_fsync);
	SERVICESYSCALL(s, access, ummisc_access);
	SERVICESYSCALL(s, lseek, ummisc_lseek);
	SERVICESYSCALL(s, getdents64, ummisc_getdents64);

	initmuscno(&s);
	add_service(&s);
}

	static void
	__attribute__ ((destructor))
fini (void)
{
	free(s.syscall);
	free(s.socket);
	finimuscno();
	forallmisctabdo(contextclose);
	//pthread_key_delete(mcontext_key);
	fprint2("ummisc fini\n");
}
