/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   umviewos -> fuse gateway
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
#include <unistd.h>
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <utime.h>
#include <limits.h>
#include <sys/time.h>
#include <sys/mount.h>
#include <dlfcn.h>
#include <pthread.h>
#include <fuse/fuse.h>
#include <linux/types.h>
#include <linux/dirent.h>
#include <linux/unistd.h>
#include "module.h"
#include "libummod.h"
#include "umfusestd.h"

struct fuse {
	char *filesystemtype;
	char *path;
	short pathlen;
	void *dlhandle;
	pthread_t thread;
	pthread_cond_t endloop;
	pthread_mutex_t endmutex;
	struct fuse_operations fops;	
	int inuse;
};
/* values for INUSE and thread synchro */
#define WAITING_FOR_LOOP -1
#define EXITING -2
/* horrible! the only way to have some context to allow multiple mount is
 * a global var: XXX new solution needed. This is not thread-scalable */

static int umfuse_current_context;
static struct fuse_context **fusetab=NULL;
static int fusetabmax=0;

static pthread_mutex_t condition_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  startloop  = PTHREAD_COND_INITIALIZER;

#define WORDLEN sizeof(int *)
#define WORDALIGN(X) (((X) + WORDLEN) & ~(WORDLEN-1))
#define SIZEDIRENT64NONAME (sizeof(__u64)+sizeof(__s64)+sizeof(unsigned short)+sizeof(unsigned char))
#define SIZEDIRENT32NONAME (sizeof(long)+sizeof(__kernel_off_t)+sizeof(unsigned short))

struct umfuse_dirent64 {
	__u64             d_ino;
	__s64             d_off;
	unsigned short  d_reclen;
	unsigned char   d_type;
	char            *d_name;
};

struct umdirent {
	struct umfuse_dirent64 de;
	unsigned short d_reclen32;
	struct umdirent *next;
};

struct fileinfo {
	int context;
	char *path;
	int count;
	long long pos;
	struct fuse_file_info ffi;
	struct umdirent *dirinfo;
	struct umdirent *dirpos;
};

static struct fileinfo **filetab=NULL;
static int filetabmax=0;

#define MNTTABSTEP 4 /* must be a power of two */
#define MNTTABSTEP_1 (MNTTABSTEP-1)
#define FILETABSTEP 4 /* must be a power of two */
#define FILETABSTEP_1 (FILETABSTEP-1)

#define EXACT 1
#define SUBSTR 0
/* search a path, returns the context i.e. the index of info for mounted file
 * -1 otherwise */
static int searchcontext(const char *path,int exact)
{
	register int i;
	int result=-1;
	for (i=0;i<fusetabmax && result<0;i++)
	{
		if (fusetab[i] != NULL && fusetab[i]->fuse != NULL)
			if (exact) {
				if (strcmp(path,fusetab[i]->fuse->path) == 0)
					result=i;
			} else {
				int len=fusetab[i]->fuse->pathlen;
				if (strncmp(path,fusetab[i]->fuse->path,len) == 0 && (path[len] == '/' || path[len]=='\0'))
					result=i;
			}
	}
	return result;
}

static int addfusetab(struct fuse_context *new)
{
	register int i;
	for (i=0;i<fusetabmax && fusetab[i] != NULL;i++)
		;
	if (i>=fusetabmax) {
		register int j;
		fusetabmax=(i + MNTTABSTEP) & ~MNTTABSTEP_1;
		fusetab=(struct fuse_context **)realloc(fusetab,fusetabmax*sizeof(struct fuse_context *));
		assert(fusetab);
		for (j=i;j<fusetabmax;j++)
			fusetab[j]=NULL;
	}
	fusetab[i]=new;
	return i;
}

static void forallfusetabdo(void (*fun)(struct fuse_context *fc))
{
	register int i;
	for (i=0;i<fusetabmax && fusetab[i] != NULL;i++)
		if (fusetab[i] != NULL)
		     fun(fusetab[i]);
}

static void delmnttab(int i)
{
	fusetab[i]=NULL;
}

static int addfiletab()
{
	register int i;
	for (i=0;i<filetabmax && filetab[i] != NULL;i++)
		;
	if (i>=filetabmax) {
		register int j;
		filetabmax=(i + MNTTABSTEP) & ~MNTTABSTEP_1;
		filetab=(struct fileinfo **)realloc(filetab,filetabmax*sizeof(struct fileinfo *));
		assert(filetab);
		for (j=i;j<filetabmax;j++)
			filetab[i]=NULL;
	}
	filetab[i]=(struct fileinfo *)malloc(sizeof(struct fileinfo));
	assert(filetab[i]);
	return i;
}

static void delfiletab(int i)
{
	struct fileinfo *norace=filetab[i];
	filetab[i]=NULL;
	free(norace->path);
	free(norace);
}

struct startmainopt {
	struct fuse_context *new;
	char *source;
	unsigned long mountflags;
	void *data;
};

static char *mountflag2options(unsigned long mountflags, void *data)
{
	char opts[PATH_MAX];
	char *mountopts=data;
	opts[0]=0;
	if (mountflags & MS_REMOUNT)
		strcat(opts,"remount,");
	if (mountflags & MS_RDONLY)
		strcat(opts,"ro,");
	if (mountflags & MS_NOATIME)
		strcat(opts,"noatime,");
	if (mountflags & MS_NODEV)
		strcat(opts,"nodev,");
	if (mountflags & MS_NOEXEC)
		strcat(opts,"noexec,");
	if (mountflags & MS_NOSUID)
		strcat(opts,"nosuid,");
	if (mountflags & MS_SYNCHRONOUS)
		strcat(opts,"MS_SYNCHRONOUS,");
	if (data)
		strcpy(opts,mountopts);
	else if (*opts)
		opts[strlen(opts)-1]=0;
	else 
		strcpy(opts,"rw");
	printf("opts %s\n",opts);
	return(strdup(opts));
}

static void *startmain(void *vsmo)
{
	struct startmainopt *psmo=vsmo;
	int (*pmain)()=dlsym(psmo->new->fuse->dlhandle,"main");
	char *opts=mountflag2options(psmo->mountflags,psmo->data);
	char *argv[]={psmo->new->fuse->filesystemtype, 
		"-o", opts, psmo->source, psmo->new->fuse->path, (char *)0};
	pmain(5,argv);
	free(opts);
	pthread_exit(NULL);
	return NULL;
}

struct mount_flags {
	const char *opt;
	unsigned long flag;
	int on;
	int safe;
};

static struct mount_flags mount_flags[] = {
	{"rw",      MS_RDONLY,      0, 1},
	{"ro",      MS_RDONLY,      1, 1},
	{"suid",    MS_NOSUID,      0, 0},
	{"nosuid",  MS_NOSUID,      1, 1},
	{"dev",     MS_NODEV,       0, 0},
	{"nodev",   MS_NODEV,       1, 1},
	{"exec",    MS_NOEXEC,      0, 1},
	{"noexec",  MS_NOEXEC,      1, 1},
	{"async",   MS_SYNCHRONOUS, 0, 1},
	{"sync",    MS_SYNCHRONOUS, 1, 1},
	{"atime",   MS_NOATIME,     0, 1},
	{"noatime", MS_NOATIME,     1, 1},
	{NULL,      0,              0, 0}
};

static int find_mount_flag(const char *s, unsigned len, int *flag)
{
	int i;

	for (i = 0; mount_flags[i].opt != NULL; i++) {
		const char *opt = mount_flags[i].opt;
		if (strlen(opt) == len && strncmp(opt, s, len) == 0) {
			if (mount_flags[i].on)
				*flag |= mount_flags[i].flag;
			else
				*flag &= ~mount_flags[i].flag;
			return 1;
		}
	}
	return 0;
}



int fuse_mount(const char *mountpoint, const char *opts)
{
	int fd=searchcontext(mountpoint,1);
	/* fd == umfuse_current_context && mountpoint == fusetab[fd]->fuse->path */

	//printf("fuse_mount %d %d\n",fd,umfuse_current_context);
	return fd;
}


void fuse_unmount(const char *mountpoint)
{
	int fd=searchcontext(mountpoint,1);
	/* TODO to be completed ? */
}

static void fopsfill (struct fuse_operations *fops,size_t size)
{
	intfun *f=(intfun *)fops;
	intfun *std=(intfun *) &defaultservice;
	int i;
	int nfun=size/sizeof(intfun);
	for (i=0; i<nfun; i++)
		if (f[i] == NULL) {
			//printf("%d->std\n",i);
			f[i]=std[i];
		}
}

struct fuse *fuse_new(int fd, const char *opts,
		const struct fuse_operations *op, size_t op_size)
{
	//printf("%d %d %d %d\n",fd,umfuse_current_context,op_size,sizeof(struct fuse_operations));
	if (fd != umfuse_current_context || op_size != sizeof(struct fuse_operations))
		return NULL;
	else {
		fusetab[fd]->fuse->fops=*op;
		fopsfill(&fusetab[fd]->fuse->fops,op_size);
		return fusetab[fd]->fuse;
	}
}

void fuse_destroy(struct fuse *f)
{
}

int fuse_loop(struct fuse *f)
{
	//printf("loop signal\n");
	pthread_mutex_lock( &condition_mutex );
	pthread_cond_signal( &startloop );
	pthread_mutex_unlock( &condition_mutex );
	if (f != NULL) {
		f->inuse = 0;
		pthread_mutex_lock( &f->endmutex );
		//pthread_mutex_lock( &condition_mutex );
		if (f->inuse != EXITING)
			pthread_cond_wait( &f->endloop, &f->endmutex );
		//pthread_cond_wait( &f->endloop, &condition_mutex );
		pthread_mutex_unlock( &f->endmutex );
		//pthread_mutex_unlock( &condition_mutex );
		//printf("done loopPID %d TID %d \n",getpid(),pthread_self());
	}
	return 0;
}

void fuse_exit(struct fuse *f)
{
}

int fuse_loop_mt(struct fuse *f)
{
	fuse_loop(f);
}

struct fuse_context *fuse_get_context(void)
{
	return fusetab[umfuse_current_context];
}

int fuse_invalidate(struct fuse *f, const char *path)
{
}

int fuse_is_lib_option(const char *opt)
{
}

int fuse_main_real(int argc, char *argv[], const struct fuse_operations *op,
		size_t op_size)
{
	char *mountpoint=argv[argc-1];
	//printf("mountpoint=%s\n",mountpoint);
	struct fuse *f;
	char *opts=NULL;
	int fd=fuse_mount(mountpoint, "ro");
	f=fuse_new(fd, opts, op, op_size);
	fuse_loop(f);
}

static int umfuse_mount(char *source, char *target, char *filesystemtype,
		       unsigned long mountflags, void *data)
{
	/* TODO: ENOTDIR if it is not a directory */
	//printf("umfuse_mount %s\n",filesystemtype);
	void *dlhandle=dlopen(filesystemtype,RTLD_NOW);
	//printf("%x %x\n",dlhandle, dlsym(dlhandle,"main"));
	if(dlhandle==NULL || dlsym(dlhandle,"main")==NULL) {
		errno=ENODEV;
		return -1;
	} else {
		struct fuse_context *new=(struct fuse_context *)
			malloc(sizeof(struct fuse_context));
		assert(new);
		new->fuse=(struct fuse *)malloc(sizeof(struct fuse));
		assert(new->fuse);
		new->fuse->path=strdup(target);
		new->fuse->pathlen=strlen(target);
		new->fuse->filesystemtype=strdup(filesystemtype);
		new->fuse->dlhandle=dlhandle;
		memset(&new->fuse->fops,0,sizeof(struct fuse_operations));
		new->fuse->inuse= WAITING_FOR_LOOP;
		new->uid=new->gid=new->pid=0;
		new->private_data=NULL;
		umfuse_current_context=addfusetab(new);
		struct startmainopt smo;
		smo.new=new;
		smo.mountflags=mountflags;
		smo.source=source;
		smo.data=data;
		pthread_cond_init(&(new->fuse->endloop),NULL);
		pthread_mutex_init(&(new->fuse->endmutex),NULL);
		pthread_create(&(new->fuse->thread), NULL, startmain, (void *)&smo);

		//printf("PID %d TID %d \n",getpid(),pthread_self());
		pthread_mutex_lock( &condition_mutex );
		if (new->fuse->inuse== WAITING_FOR_LOOP)
			pthread_cond_wait( &startloop , &condition_mutex);
		pthread_mutex_unlock( &condition_mutex );
		return 0;
	}
}

static int umfuse_umount2(char *target, int flags) {
	umfuse_current_context=searchcontext(target,EXACT);
	if (umfuse_current_context<0) {
		errno=EINVAL;
		return(-1);
	} else {
		/* TODO check inuse and FORCE flag */
		struct fuse_context *fc_norace=fusetab[umfuse_current_context];
		delmnttab(umfuse_current_context);
		//printf("PID %d TID %d \n",getpid(),pthread_self());
		pthread_mutex_lock( &fc_norace->fuse->endmutex );
		//pthread_mutex_lock( &condition_mutex );
		fc_norace->fuse->inuse= EXITING;
		pthread_cond_signal(&fc_norace->fuse->endloop);
		pthread_mutex_unlock(&fc_norace->fuse->endmutex );
		//pthread_mutex_unlock( &condition_mutex );
		pthread_join(fc_norace->fuse->thread, NULL);
		//printf("JOIN done\n");
		dlclose(fc_norace->fuse->dlhandle);
		free(fc_norace->fuse->filesystemtype);
		free(fc_norace->fuse->path);
		free(fc_norace->fuse);
		free(fc_norace);
		return 0;
	}
}

struct fuse_dirhandle {
	struct umdirent *tail;
	long long offset;
};

static int umfusefilldir(fuse_dirh_t h, const char *name, int type, ino_t ino)
{
	if (name != NULL) {
		struct umdirent *new=(struct umdirent *)malloc(sizeof(struct umdirent));
		new->de.d_ino=ino;
		new->de.d_type=type;
		new->de.d_name=strdup(name);
		new->de.d_reclen=WORDALIGN(SIZEDIRENT64NONAME+strlen(name)+1);
		new->d_reclen32=WORDALIGN(SIZEDIRENT32NONAME+strlen(name)+1);
		/* virtualize the offset on a real file, 64bit ino+16len+8namlen+8type */
		new->de.d_off=h->offset=h->offset+WORDALIGN(12+strlen(name));
		if (h->tail==NULL) {
			new->next=new;
		} else {
			new->next=h->tail->next;
			h->tail->next=new;
		}
		h->tail=new;
	}
	return 0;
}

static struct umdirent *umfilldirinfo(struct fileinfo *fi)
{
	int rv;
	struct fuse_dirhandle dh;
	int cc=fi->context;
	dh.tail=NULL;
	dh.offset=0;
	rv=fusetab[cc]->fuse->fops.getdir(fi->path, &dh, umfusefilldir);
	if (rv < 0)
		return NULL;
	else 
		return dh.tail;
}

static void umcleandirinfo(struct umdirent *tail)
{
	if (tail != NULL) {
		while (tail->next != tail) {
			struct umdirent *tmp;
			tmp=tail->next;
			tail->next=tmp->next;
			free(tmp);
		}
		free(tail);
	}
}

static int um_getdents(unsigned int fd, struct dirent *dirp, unsigned int count)
{
	//printf("um_getdents!\n");
	if (filetab[fd]==NULL) {
		errno=ENOENT;
		return -1;
	} else {
		int cc=filetab[fd]->context; /* TODO check it is really a dir */
		int curoffs=0;
		if (filetab[fd]->dirinfo == NULL) {
			filetab[fd]->dirinfo = umfilldirinfo(filetab[fd]);
		} 
		/* TODO management of lseek on directories */

		
		if (filetab[fd]->dirinfo==NULL) 
			return 0;
		else {
			struct dirent *current;
			char *base=(char *)dirp;
			int last=0;
			if (filetab[fd]->dirpos==NULL)
				filetab[fd]->dirpos=filetab[fd]->dirinfo;
			else
				last=(filetab[fd]->dirpos==filetab[fd]->dirinfo);
			while (!last && curoffs + filetab[fd]->dirpos->next->d_reclen32 < count)
			{
				filetab[fd]->dirpos=filetab[fd]->dirpos->next;
				current=(struct dirent *)base;
				current->d_ino=filetab[fd]->dirpos->de.d_ino;
				current->d_off=filetab[fd]->dirpos->de.d_off;
				current->d_reclen=filetab[fd]->dirpos->d_reclen32;
				strcpy(current->d_name,filetab[fd]->dirpos->de.d_name);
				base+=filetab[fd]->dirpos->d_reclen32;
				curoffs+=filetab[fd]->dirpos->d_reclen32;
				last=(filetab[fd]->dirpos == filetab[fd]->dirinfo);
			}
		}
		return curoffs;
	}
}

static int um_getdents64(unsigned int fd, struct dirent64 *dirp, unsigned int count)
{
	//printf("um_getdents64!\n");
	if (filetab[fd]==NULL) {
		errno=ENOENT;
		return -1;
	} else {
		unsigned int curoffs=0;
		int cc=filetab[fd]->context; /* TODO check it is really a dir */
		if (filetab[fd]->dirinfo == NULL) {
			filetab[fd]->dirinfo = umfilldirinfo(filetab[fd]);
		} 
		/* TODO management of lseek on directories */

		if (filetab[fd]->dirinfo==NULL) 
			return 0;
		else {
			struct dirent64 *current;
			char *base=(char *)dirp;
			int last=0;
			if (filetab[fd]->dirpos==NULL)
				filetab[fd]->dirpos=filetab[fd]->dirinfo;
			else
				last=(filetab[fd]->dirpos==filetab[fd]->dirinfo);
			while (!last && curoffs + filetab[fd]->dirpos->next->de.d_reclen < count)
			{
				filetab[fd]->dirpos=filetab[fd]->dirpos->next;
				current=(struct dirent64 *)base;
				current->d_ino=filetab[fd]->dirpos->de.d_ino;
				current->d_off=filetab[fd]->dirpos->de.d_off;
				current->d_reclen=filetab[fd]->dirpos->de.d_reclen;
				current->d_type=filetab[fd]->dirpos->de.d_type;
				strcpy(current->d_name,filetab[fd]->dirpos->de.d_name);
				base+=filetab[fd]->dirpos->de.d_reclen;
				curoffs+=filetab[fd]->dirpos->de.d_reclen;
				last=(filetab[fd]->dirpos == filetab[fd]->dirinfo);
			}
		}
		return curoffs;
	}
}

#define TRUE 1
#define FALSE 0
static int alwaysfalse()
{
	return FALSE;
}

static epoch_t fuse_path(char *path)
{
	if(strncmp(path,"umfuse",6) == 0) /* a path with no leading / is a filesystemtype */
		return TRUE;
	else {
		umfuse_current_context=searchcontext(path,SUBSTR);
		if (umfuse_current_context >= 0) {
			return TRUE; 
		}
	}
	return FALSE;
}

static char *unwrap(struct fuse_context *fc,char *path)
{
	char *reduced=path+fc->fuse->pathlen;
	if (*reduced == 0)
		return("/");
	else
		return(reduced);
}

static int umfuse_open(char *path, int flags, mode_t mode)
{
	int cc=searchcontext(path,SUBSTR);
	int fi=addfiletab();
	int rv;
	//printf("OPEN %s %s\n",path,unwrap(fusetab[cc],path));
	filetab[fi]->context=cc;
	filetab[fi]->count=0;
	filetab[fi]->pos=0;
	filetab[fi]->ffi.flags=mode;
	filetab[fi]->ffi.writepage=0;
	filetab[fi]->dirinfo=NULL;
	filetab[fi]->dirpos=NULL;
	filetab[fi]->path=strdup(unwrap(fusetab[cc],path));
	assert(cc>=0);
	if ((rv=fusetab[cc]->fuse->fops.open(
			filetab[fi]->path,&filetab[fi]->ffi)) < 0) {
		delfiletab(fi);
		errno= -rv;
		return -1;
	} else {
		filetab[fi]->count+=1;
		/* TODO update fuse->inuse++ */
		return fi;
	}
}

static int umfuse_close(int fd)
{
	int rv;
	//printf("CLOSE\n");
	if (filetab[fd]==NULL) {
		errno=ENOENT;
		return -1;
	} else {
		int cc=filetab[fd]->context;
		rv=fusetab[cc]->fuse->fops.flush(
				filetab[fd]->path,
				&filetab[fd]->ffi);
		filetab[fd]->count--;
		//printf("->CLOSE %s %d\n",filetab[fd]->path, filetab[fd]->count);
		if (filetab[fd]->count == 0) {
			/* TODO update fuse->inuse-- */
			rv=fusetab[cc]->fuse->fops.release(
					filetab[fd]->path,
					&filetab[fd]->ffi);
			//free(filetab[fd]->path);
			umcleandirinfo(filetab[fd]->dirinfo);
			delfiletab(fd);
		}
		if (rv<0) {
			errno= -rv;
			return -1;
		} else {
			return rv;
		}
	}
}

static int umfuse_read(int fd, void *buf, size_t count)
{
	int rv;
	if (filetab[fd]==NULL) {
		errno=ENOENT;
		return -1;
	} else {
		int cc=filetab[fd]->context;
		umfuse_current_context=cc;
		rv=fusetab[cc]->fuse->fops.read(
				filetab[fd]->path,
				buf,
				count,
				filetab[fd]->pos,
				&filetab[fd]->ffi);
		if (rv<0) {
			errno= -rv;
			return -1;
		} else {
			filetab[fd]->pos += rv;
			return rv;
		}
	}
}

static int umfuse_fstat(int fd, struct stat *buf)
{
	if (filetab[fd]==NULL) {
		errno=ENOENT;
		return -1;
	} else {
		int rv;
		int cc=filetab[fd]->context;
		assert(cc>=0);
		umfuse_current_context=cc;
		rv= fusetab[cc]->fuse->fops.getattr(
				filetab[fd]->path,buf);
		if (rv<0) {
			errno= -rv;
			return -1;
		} else
			return rv;
	}
}

static stat2stat64(struct stat64 *s64,struct stat *s)
{
	s64->st_dev= s->st_dev;
	s64->st_ino= s->st_ino;
	s64->st_mode= s->st_mode;
	s64->st_nlink= s->st_nlink;
	s64->st_uid= s->st_uid;
	s64->st_gid= s->st_gid;
	s64->st_rdev= s->st_rdev;
	s64->st_size= s->st_size;
	s64->st_blksize= s->st_blksize;
	s64->st_blocks= s->st_blocks;
	s64->st_atim= s->st_atim;
	s64->st_mtim= s->st_mtim;
	s64->st_ctim= s->st_ctim;
	//s64->__unused4= s->__unused4;
	//s64->__unused5= s->__unused5;
}

static int umfuse_fstat64(int fd, struct stat64 *buf64)
{
	if (filetab[fd]==NULL) {
		errno=ENOENT;
		return -1;
	} else {
		int rv;
		int cc=filetab[fd]->context;
		struct stat buf;
		assert(cc>=0);
		umfuse_current_context=cc;
		rv= fusetab[cc]->fuse->fops.getattr(
				filetab[fd]->path,&buf);
		if (rv<0) {
			errno= -rv;
			return -1;
		} else {
			stat2stat64(buf64,&buf);
			return rv;
		}
	}
}

static int umfuse_stat(char *path, struct stat *buf)
{
	int cc=searchcontext(path,SUBSTR);
	int rv;
	assert(cc>=0);
	rv= fusetab[cc]->fuse->fops.getattr(
			unwrap(fusetab[cc],path),buf);
	if (rv<0) {
		errno= -rv;
		return -1;
	} else 
		return rv;
}

static int umfuse_lstat(char *path, struct stat *buf)
{
	int cc=searchcontext(path,SUBSTR);
	int rv;
	assert(cc>=0);
	rv= fusetab[cc]->fuse->fops.getattr(
			unwrap(fusetab[cc],path),buf);
	if (rv<0) {
		errno= -rv;
		return rv;
	} else 
		return rv;
}

static int umfuse_stat64(char *path, struct stat64 *buf64)
{
	int cc=searchcontext(path,SUBSTR);
	int rv;
	struct stat buf;
	assert(cc>=0);
	rv= fusetab[cc]->fuse->fops.getattr(
			unwrap(fusetab[cc],path),&buf);
	if (rv<0) {
		errno= -rv;
		return -1;
	} else {
		stat2stat64(buf64,&buf);
		return rv;
	}
}

static int umfuse_lstat64(char *path, struct stat64 *buf64)
{
	int cc=searchcontext(path,SUBSTR);
	int rv;
	struct stat buf;
	assert(cc>=0);
	rv= fusetab[cc]->fuse->fops.getattr(
			unwrap(fusetab[cc],path),&buf);
	if (rv<0) {
		errno= -rv;
		return -1;
	} else {
		stat2stat64(buf64,&buf);
		return rv;
	}
}

static int umfuse_readlink(char *path, char *buf, size_t bufsiz)
{
	int cc=searchcontext(path,SUBSTR);
	int rv;
	assert(cc>=0);
	rv= fusetab[cc]->fuse->fops.readlink(
			unwrap(fusetab[cc],path),buf,bufsiz);
	//printf("umfuse_readlink %s %s %d\n",unwrap(fusetab[cc],path),buf,rv);
	if (rv<0) {
		errno= -rv;
		return -1;
	}
	return rv;
}

static int umfuse_access(char *path, int mode)
{
	/* TODO dummy stub for access */
	return 0;
}

static int umfuse_mkdir(char *path, int mode)
{
	int cc=searchcontext(path,SUBSTR);
	int rv;
	assert(cc>=0);
	rv= fusetab[cc]->fuse->fops.mkdir(
			unwrap(fusetab[cc],path),mode);
	if (rv<0) {
		errno= -rv;
		return rv;
	}
}

static int umfuse_rmdir(char *path)
{
	int cc=searchcontext(path,SUBSTR);
	int rv;
	assert(cc>=0);
	rv= fusetab[cc]->fuse->fops.rmdir(
			unwrap(fusetab[cc],path));
	if (rv<0) {
		errno= -rv;
		return rv;
	}
}

static int umfuse_chmod(char *path, int mode)
{
}

static int umfuse_chown(char *path, uid_t owner, gid_t group)
{
}

static int umfuse_lchown(char *path, uid_t owner, gid_t group)
{
}

static int umfuse_unlink(char *path)
{
	int cc=searchcontext(path,SUBSTR);
	int rv;
	assert(cc>=0);
	rv= fusetab[cc]->fuse->fops.unlink(
			unwrap(fusetab[cc],path));
	if (rv<0) {
		errno= -rv;
		return rv;
	}
	if (rv<0) {
		errno= -rv;
		return rv;
	}
}

static int umfuse_link(char *oldpath, char *newpath)
{
}

static int umfuse_symlink(char *oldpath, char *newpath)
{
}

static int umfuse_utime(char *filename, struct utimbuf *buf)
{
}

static int umfuse_utimes(char *filename, struct timeval tv[2])
{
}

static ssize_t umfuse_pread(int fd, void *buf, size_t count, long long offset)
{
	off_t off=offset;
}

static ssize_t umfuse_pwrite(int fd, const void *buf, size_t count, long long offset)
{
	off_t off=offset;
}

/* TODO management of fcntl */
static int umfuse_fcntl32(int fd, int cmd, void *arg)
{
	//printf("umfuse_fcntl32\n");
	errno=0;
	return 0;
}

static int umfuse_fcntl64(int fd, int cmd, void *arg)
{
	//printf("umfuse_fcntl64\n");
	errno=0;
	return 0;
}

void contextclose(struct fuse_context *fc)
{
	umfuse_umount2(fc->fuse->path,MNT_FORCE);
}

static struct service s;

static void
__attribute__ ((constructor))
init (void)
{
	printf("umfuse init\n");
	s.name="umfuse fuse ";
	s.code=0x01;
	s.checkpath=fuse_path;
	s.checksocket=alwaysfalse;
	s.syscall=(intfun *)malloc(scmap_scmapsize * sizeof(intfun));
	s.socket=(intfun *)malloc(scmap_sockmapsize * sizeof(intfun));
	s.syscall[uscno(__NR_mount)]=umfuse_mount;
	s.syscall[uscno(__NR_umount)]=umfuse_umount2; /* umount must be mapped onto umount2 */
	s.syscall[uscno(__NR_umount2)]=umfuse_umount2;
	s.syscall[uscno(__NR_open)]=umfuse_open;
	s.syscall[uscno(__NR_creat)]=umfuse_open; /*creat must me mapped onto open*/
	s.syscall[uscno(__NR_read)]=umfuse_read;
	//s.syscall[uscno(__NR_write)]=write;
	//s.syscall[uscno(__NR_readv)]=readv;
	//s.syscall[uscno(__NR_writev)]=writev;
	s.syscall[uscno(__NR_close)]=umfuse_close;
	s.syscall[uscno(__NR_stat)]=umfuse_stat;
	s.syscall[uscno(__NR_lstat)]=umfuse_lstat;
	s.syscall[uscno(__NR_fstat)]=umfuse_fstat;
	s.syscall[uscno(__NR_stat64)]=umfuse_stat64;
	s.syscall[uscno(__NR_lstat64)]=umfuse_lstat64;
	s.syscall[uscno(__NR_fstat64)]=umfuse_fstat64;
	s.syscall[uscno(__NR_readlink)]=umfuse_readlink;
	s.syscall[uscno(__NR_getdents)]=um_getdents;
	s.syscall[uscno(__NR_getdents64)]=um_getdents64;
	s.syscall[uscno(__NR_access)]=umfuse_access;
	s.syscall[uscno(__NR_fcntl)]=umfuse_fcntl32;
	s.syscall[uscno(__NR_fcntl64)]=umfuse_fcntl64;
	//s.syscall[uscno(__NR__llseek)]=_llseek;
	//s.syscall[uscno(__NR_lseek)]= (intfun) lseek;
	//s.syscall[uscno(__NR_mkdir)]=umfuse_mkdir;
	//s.syscall[uscno(__NR_rmdir)]=umfuse_rmdir;
	//s.syscall[uscno(__NR_chown)]=umfuse_chown;
	//s.syscall[uscno(__NR_lchown)]=umfuse_lchown;
	//s.syscall[uscno(__NR_fchown)]=fchown;
	//s.syscall[uscno(__NR_chmod)]=umfuse_chmod;
	//s.syscall[uscno(__NR_fchmod)]=fchmod;
	//s.syscall[uscno(__NR_unlink)]=umfuse_unlink;
	//s.syscall[uscno(__NR_fsync)]=fsync;
	//s.syscall[uscno(__NR_fdatasync)]=fdatasync;
	//s.syscall[uscno(__NR__newselect)]=select;
	//s.syscall[uscno(__NR_link)]=umfuse_link;
	//s.syscall[uscno(__NR_symlink)]=umfuse_symlink;
	//s.syscall[uscno(__NR_pread64)]=umfuse_pread;
	//s.syscall[uscno(__NR_pwrite64)]=umfuse_pwrite;
	//s.syscall[uscno(__NR_utime)]=umfuse_utime;
	//s.syscall[uscno(__NR_utimes)]=umfuse_utimes;
	add_service(&s);
}

static void
__attribute__ ((destructor))
fini (void)
{
	free(s.syscall);
	free(s.socket);
	forallfusetabdo(contextclose);
	printf("umfuse fini\n");
}
