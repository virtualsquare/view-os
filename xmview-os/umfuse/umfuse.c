/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   umviewos -> fuse gateway
 *   
 *   Copyright 2005 Renzo Davoli University of Bologna - Italy
 *   Modified 2005 Paolo Angelelli, Andrea Seraghiti
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
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <utime.h>
#include <limits.h>
#include <sys/time.h>
#include <sys/mount.h>
#include <dlfcn.h>
#include <pthread.h>
#include <fuse.h>
#include <linux/types.h>
#include <linux/dirent.h>
#include <linux/unistd.h>
#include "module.h"
#include "libummod.h"
#include "umfusestd.h"
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/ipc.h>
#include <stdarg.h>
#include <math.h>
#include <values.h>


/* Enable Experimental code */
//#define __UMFUSE_EXPERIMENTAL__

#ifdef __UMFUSE_EXPERIMENTAL__
/* There are already some problems with dup. (e.g. output redirection)
 * TODO permission management and user management (who is the writer in the Virtual FS?)
 */
#endif

/* Enable umfuse own debug output */

//#define __UMFUSE_DEBUG__ 1   /* it is better to enable it from makefile */
//#define __UMFUSE_DEBUG_LEVEL__ 0

#ifdef __UMFUSE_DEBUG__
#define PRINTDEBUG(level,args...) printdebug(level, __FILE__, __LINE__, __func__, args)
#else
#define PRINTDEBUG(level,args...)
#endif


static struct service s;

struct fuse {
	char *filesystemtype;
	char *path;
	short pathlen;
	void *dlhandle;
	pthread_t thread;
	pthread_cond_t startloop;
	pthread_cond_t endloop;
	pthread_mutex_t endmutex;
	struct fuse_operations fops;	
	int inuse;
	unsigned long flags;
#ifdef NEW_SERVICE_LIST
	int service_no;
#endif
};

/* values for INUSE and thread synchro */
#define WAITING_FOR_LOOP -1
#define EXITING -2
#define FUSE_ABORT -3
static pthread_mutex_t condition_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t fusetab_mutex = PTHREAD_MUTEX_INITIALIZER;

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
	struct fuse_context *context;
	char *path;						
	int count;				/* number of processes that opened the file */
	long long pos;				/* file offset */
	long long size;				/* file offset */
	struct fuse_file_info ffi;		/* includes open flags, file handle and page_write mode  */
	struct umdirent *dirinfo;		/* conversion fuse-getdir into kernel compliant
						   dirent. Dir head pointer */
	struct umdirent *dirpos;		/* same conversion above: current pos entry */
};

static struct fileinfo **filetab=NULL;
static int filetabmax=0;

#define MNTTABSTEP 4 /* must be a power of two */
#define MNTTABSTEP_1 (MNTTABSTEP-1)
#define FILETABSTEP 4 /* must be a power of two */
#define FILETABSTEP_1 (FILETABSTEP-1)

#define EXACT 1
#define SUBSTR 0

/* CONTEXT MGMT: multiple threads support */

static pthread_key_t context_key;
static struct fuse_context **fusetab=NULL;
static int fusetabmax=0;

struct fuse_context *fuse_get_context(void)
{
	return pthread_getspecific(context_key);
}

static void fuse_set_context(struct fuse_context *fc)
{
	pthread_setspecific(context_key, fc);
}

/* static umfuse own debug function */
/* it accept a level of debug: higher level = more important messages only */

#ifdef __UMFUSE_DEBUG__
static void printdebug(int level, const char *file, const int line, const char *func, const char *fmt, ...) {
	va_list ap;
    
	if (level >= __UMFUSE_DEBUG_LEVEL__) {
		va_start(ap, fmt);
#ifdef _PTHREAD_H
		fprintf(stderr, "[%d:%lu] %s:%d %s(): ", getpid(), pthread_self(), file, line, func);
#else
		fprintf(stderr, "[%d] %s:%d %s(): ", getpid(), file, line, func);
#endif
		vfprintf(stderr, fmt, ap);
		fprintf(stderr, "\n");
		fflush(stderr);
		va_end(ap);
	}
}
#endif

static cutdots(char *path)
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

/* search a path, returns the context i.e. the index of info for mounted file
 * -1 otherwise */
static struct fuse_context *searchcontext(char *path,int exact)
{
	register int i;
	struct fuse_context *result=NULL;
	PRINTDEBUG(0,"SearchContext:%s-%s\n",path, exact?"EXACT":"SUBSTR");
	cutdots(path);
	for (i=0;i<fusetabmax && result==NULL;i++)
	{
		if ((fusetab[i] != NULL) && (fusetab[i]->fuse != NULL)) {
			if (exact) {
				if (strcmp(path,fusetab[i]->fuse->path) == 0)
					result=fusetab[i];
			} else {
				int len=fusetab[i]->fuse->pathlen;
				if (strncmp(path,fusetab[i]->fuse->path,len) == 0 && (path[len] == '/' || path[len]=='\0'))
					result=fusetab[i];
			}
		}
	}
	
	return result;
}

/*insert a new context in the fuse table*/
static struct fuse_context *addfusetab(struct fuse_context *new)
{
	register int i;
	pthread_mutex_lock( &fusetab_mutex );
	for (i=0;i<fusetabmax && fusetab[i] != NULL;i++)
		;
	if (i>=fusetabmax) {
		register int j;
		register int fusetabnewmax=(i + MNTTABSTEP) & ~MNTTABSTEP_1;
		fusetab=(struct fuse_context **)realloc(fusetab,fusetabnewmax*sizeof(struct fuse_context *));
		assert(fusetab);
		for (j=i;j<fusetabnewmax;j++)
			fusetab[j]=NULL;
		fusetabmax=fusetabnewmax;
	}
	fusetab[i]=new;
	pthread_mutex_unlock( &fusetab_mutex );
	return fusetab[i];
}

/* execute a specific function (arg) for each fusetab element */
static void forallfusetabdo(void (*fun)(struct fuse_context *fc))
{
	register int i;
	for (i=0;i<fusetabmax;i++)
		if (fusetab[i] != NULL)
		     fun(fusetab[i]);
}

/*
 * delete the i-th element of the tab.
 * the table cannot be compacted as the index is used as id
 */
static void delmnttab(struct fuse_context *fc)
{
	register int i;
	pthread_mutex_lock( &fusetab_mutex );
	for (i=0;i<fusetabmax && fc != fusetab[i];i++)
		;
	if (i<fusetabmax)
		 fusetab[i]=NULL;
	else
		fprintf(stderr,"delmnt inexistent entry\n");
	pthread_mutex_unlock( &fusetab_mutex );
}
 
#if ( FUSE_MINOR_VERSION <= 5 )
/*
 * delete the i-th element of the tab.
 * the table cannot be compacted as the index is used as id
 */
static int searchmnttab(struct fuse_context *fc)
{
	register int i;
	pthread_mutex_lock( &fusetab_mutex );
	for (i=0;i<fusetabmax && fc != fusetab[i];i++)
		;
	if (i >= fusetabmax) 
		i= -1;
	pthread_mutex_unlock( &fusetab_mutex );
	return i;
}
#endif

/* add an element to the filetab (open file table)
 * each file has a fileinfo record
 */
static int addfiletab()
{
	register int i;
	pthread_mutex_lock( &fusetab_mutex );
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
	pthread_mutex_unlock( &fusetab_mutex );
	return i;
}

/* delete an entry from the open file table.
 * RD: there is a counter managed by open and close calls */
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
	unsigned long *pmountflags;
	void *data;
};

static char *mountflag2options(unsigned long mountflags, void *data)
{
	char opts[PATH_MAX];
	char *mountopts=data;
	opts[0]=0;
	
	PRINTDEBUG(10,"mountflags: %x\n",mountflags);
	PRINTDEBUG(10,"data: %s\n",data);

	if (mountflags & MS_REMOUNT)
		strncat(opts,"remount,",PATH_MAX);
	if (mountflags & MS_RDONLY)
		strncat(opts,"ro,",PATH_MAX);
	if (mountflags & MS_NOATIME)
		strncat(opts,"noatime,",PATH_MAX);
	if (mountflags & MS_NODEV)
		strncat(opts,"nodev,",PATH_MAX);
	if (mountflags & MS_NOEXEC)
		strncat(opts,"noexec,",PATH_MAX);
	if (mountflags & MS_NOSUID)
		strncat(opts,"nosuid,",PATH_MAX);
	if (mountflags & MS_SYNCHRONOUS)
		strncat(opts,"sync,",PATH_MAX);
	
	/* if there are options trailing comma is removed,
	 * otherwise "rw" becomes a comment */
	if (data && *mountopts)
		strncat(opts,mountopts,PATH_MAX);
	else if (*opts)
		opts[strlen(opts)-1]=0;
	     else 
		strncpy(opts,"rw",PATH_MAX);
	PRINTDEBUG(10,"opts: %s\n",opts);
	return(strdup(opts));
}

static void *startmain(void *vsmo)
{
	struct startmainopt *psmo = vsmo;
	int (*pmain)() = dlsym(psmo->new->fuse->dlhandle,"main");
	char *opts;
	int newargc;
	char **newargv;
	if (pmain == NULL) {
		fprintf(stderr, "%s\n", dlerror());
		fflush(stderr);
	}
	/* handle -o options and specific filesystem options */
	opts = mountflag2options(*(psmo->pmountflags), psmo->data);
	fuse_set_context(psmo->new);
	newargc=fuseargs(psmo->new->fuse->filesystemtype,psmo->source, psmo->new->fuse->path,opts, &newargv, &(psmo->new), &(psmo->new->fuse->flags));
	free(opts);
	if (psmo->new->fuse->flags & FUSE_DEBUG) {
		fprintf(stderr, "UmFUSE Debug enabled\n");
		fprintf(stderr, "MOUNT=>filesystem:%s image:%s path:%s args:%s\n",
				psmo->new->fuse->filesystemtype, psmo->source, psmo->new->fuse->path,opts);
		fflush(stderr);		
	}
	if (pmain(newargc,newargv) != 0)
		umfuse_abort(psmo->new->fuse);
	int i;
	for (i=0;i<newargc;i++)
		free(newargv[i]);
	free(newargv);
	pthread_exit(NULL);
	return NULL;
}

/*TODO parse cmd, es dummy is rw or ro!*/
//see fuse_setup_common lib/helper.c
#if ( FUSE_MINOR_VERSION <= 5 )
int fuse_main_real(int argc, char *argv[], const struct fuse_operations *op,
		size_t op_size)
#else
int fuse_main_real(int argc, char *argv[], const struct fuse_operations *op,
		                   size_t op_size, void *user_data)
#endif
{
	struct fuse *f;
#if ( FUSE_MINOR_VERSION <= 5 )
	int fd = fuse_mount(NULL, NULL); //options have been already parsed
	f = fuse_new(fd, NULL, op, op_size);
#else
	struct fuse_chan *fuseargs = fuse_mount(NULL, NULL); //options have been already parsed
	f = fuse_new(fuseargs, NULL, op, op_size, user_data);
#endif
	//I cannot understand this comment. (renzo)
	//"now opts are lib_opts;debug,hard_remove,use_ino"
	fuse_loop(f);
	return ;	
}

/* fuse_mount and fuse_unmount are dummy functions, 
 * the real mount operation has been done in umfuse_mount */
#if ( FUSE_MINOR_VERSION <= 5 )
#if ( FUSE_MINOR_VERSION <= 4 )
int fuse_mount(const char *mountpoint, const char *opts)
#else
int fuse_mount(const char *mountpoint, struct fuse_args *args)
#endif
{
#ifdef __UMFUSE_DEBUG__
	 PRINTDEBUG(10,"fuse_mount %s\n",mountpoint);
#endif
	return searchmnttab(fuse_get_context());
}
#else
struct fuse_chan *fuse_mount(const char *mountpoint, struct fuse_args *args)
{
#ifdef __UMFUSE_DEBUG__
	 PRINTDEBUG(10,"fuse_mount %s\n",mountpoint);
#endif
	return (struct fuse_chan *) fuse_get_context();
}
#endif


#if ( FUSE_MINOR_VERSION <= 5 )
void fuse_unmount(const char *mountpoint)
#else
void fuse_unmount(const char *mountpoint, struct fuse_chan *ch)
#endif
{
}

/* set standard fuse_operations (umfusestd.c) for undefined fields in the
 * fuse_operations structure */
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

#if ( FUSE_MINOR_VERSION <= 5 )
#if ( FUSE_MINOR_VERSION <= 4 ) 
struct fuse *fuse_new(int fd, const char *opts,
		const struct fuse_operations *op, size_t op_size)
#else
struct fuse *fuse_new(int fd, struct fuse_args *args,
		const struct fuse_operations *op, size_t op_size)
#endif
{
	struct fuse_context *fc=fuse_get_context();
	PRINTDEBUG(10,"%d %d %d %d\n",fd,umfuse_current_context,op_size,sizeof(struct fuse_operations));
	if (op_size != sizeof(struct fuse_operations))
		fprintf(stderr, "Fuse module vs umfuse support version mismatch\n");
	
	if (fusetab[fd] != fc || op_size != sizeof(struct fuse_operations)){
		fc->fuse->inuse=FUSE_ABORT;
		return NULL;
	}
	else {
		fc->fuse->fops = *op;
		fopsfill(&fc->fuse->fops, op_size);
		return fc->fuse;
	}
}
#else
struct fuse *fuse_new(struct fuse_chan *ch, struct fuse_args *args,
		                      const struct fuse_operations *op, size_t op_size,
													void *user_data)
{
	struct fuse_context *fc=(struct fuse_context *)ch;
	PRINTDEBUG(10,"%p %p %d %d\n",fc,fuse_get_context(),op_size,sizeof(struct fuse_operations));
	if (op_size != sizeof(struct fuse_operations))
		fprintf(stderr, "Fuse module vs umfuse support version mismatch\n");
	if (fc != fuse_get_context() || op_size != sizeof(struct fuse_operations)){
		fc->fuse->inuse=FUSE_ABORT;
		return NULL;
	}
	else {
		fc->fuse->fops = *op;
		fc->private_data = user_data;
		fopsfill(&fc->fuse->fops, op_size);
		return fc->fuse;
	}
}
#endif


void fuse_destroy(struct fuse *f)
{
/*	**
 * Destroy the FUSE handle.
 *
 * The filesystem is not unmounted.
 *
 * @param f the FUSE handle
 */

}

int fuse_loop(struct fuse *f)
{
	if (f != NULL) {
#if 0
		if (f->fops.init != NULL) {
			struct fuse_context *fc=fuse_get_context();
#if ( FUSE_MINOR_VERSION <= 5 )
			fc->private_data=f->fops.init();
#else
			struct fuse_conn_info conn;
			fc->private_data=f->fops.init(&conn);
#endif
		}
#endif

		//printf("loop signal\n");
		pthread_mutex_lock( &condition_mutex );
		pthread_cond_signal( &f->startloop );
		pthread_mutex_unlock( &condition_mutex );
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

int umfuse_abort(struct fuse *f)
{
	//printf("ABORT!\n");
	f->inuse = FUSE_ABORT;
	pthread_mutex_lock( &condition_mutex );
	pthread_cond_signal( &f->startloop );
	pthread_mutex_unlock( &condition_mutex );
}

void fuse_exit(struct fuse *f)
{
	/**
 * Exit from event loop
 *
 * @param f the FUSE handle
 */

}

int fuse_loop_mt(struct fuse *f)
{
//in fuselib is FUSE event loop with multiple threads,
//but here is all with multiple threads ;-)
	return fuse_loop(f);
}

int fuse_invalidate(struct fuse *f, const char *path)
{
/**
 * Invalidate cached data of a file.
 *
 * Useful if the 'kernel_cache' mount option is given, since in that
 * case the cache is not invalidated on file open.
 *
 * @return 0 on success or -errno on failure
 */
	//return -errno
	return 0;
}

int fuse_is_lib_option(const char *opt)
{/**
 * Check whether a mount option should be passed to the kernel or the
 * library
 *
 * @param opt the option to check
 * @return 1 if it is a library option, 0 otherwise
 */
	return 0;
}

static int umfuse_mount(char *source, char *target, char *filesystemtype,
		       unsigned long mountflags, void *data, void *umph)
{
	/* TODO: ENOTDIR if it is not a directory */
	//void *newdata;
	void *dlhandle = dlopen(filesystemtype, RTLD_NOW);
	
	PRINTDEBUG(10, "MOUNT %s %s %s %x %s\n",source,target,filesystemtype,
			mountflags, (data!=NULL)?data:"<NULL>");

	if(dlhandle == NULL || dlsym(dlhandle,"main") == NULL) {
		fprintf(stderr, "%s\n",dlerror());
		fflush(stderr);
		errno=ENODEV;
		return -1;
	} else {
		struct fuse_context *new = (struct fuse_context *)
			malloc(sizeof(struct fuse_context));
		struct startmainopt smo;
		struct fuse_context *fc;
		assert(new);
		new->fuse = (struct fuse *)malloc(sizeof(struct fuse));
		assert(new->fuse);
		new->fuse->path = strdup(target);
		new->fuse->pathlen = strlen(target);
		new->fuse->filesystemtype = strdup(filesystemtype);
		new->fuse->dlhandle = dlhandle;
		memset(&new->fuse->fops,0,sizeof(struct fuse_operations));
		new->fuse->inuse = WAITING_FOR_LOOP;
		new->uid = getuid();
		new->gid = getgid();
		new->pid = um_mod_getpid(umph);
		new->private_data = NULL;
		new->fuse->flags = mountflags; /* all the mount flags + FUSE_DEBUG */
		
		/* parse mount options: split fuse options from 
		   filesystem options
		   and traslate options from mount syntax into fuse syntax */
		   
		fc = addfusetab(new);		
		fuse_set_context(fc);
		smo.new = new;
		smo.pmountflags = &(new->fuse->flags);
		smo.source = source;
		smo.data = data;
		pthread_cond_init(&(new->fuse->startloop),NULL);
		pthread_cond_init(&(new->fuse->endloop),NULL);
		pthread_mutex_init(&(new->fuse->endmutex),NULL);
		pthread_create(&(new->fuse->thread), NULL, startmain, (void *)&smo);
		
		PRINTDEBUG(10, "PID %d TID %d \n",getpid(),pthread_self());
		
		pthread_mutex_lock( &condition_mutex );
		if (new->fuse->inuse== WAITING_FOR_LOOP)
			pthread_cond_wait( &(new->fuse->startloop), &condition_mutex);
		pthread_mutex_unlock( &condition_mutex );
		if (new->fuse->inuse == FUSE_ABORT)
		{
			struct fuse_context *fc_norace=new;
			printf("UMOUNT ABORT\n");
			delmnttab(new);
			pthread_join(fc_norace->fuse->thread, NULL);
			dlclose(fc_norace->fuse->dlhandle);
			free(fc_norace->fuse->filesystemtype);
			free(fc_norace->fuse->path);
			free(fc_norace->fuse);
			errno = EIO;
			return -1;
		}
		if (new->fuse->fops.init != NULL) {
#if ( FUSE_MINOR_VERSION <= 5 )
			fc->private_data=new->fuse->fops.init();
#else
			struct fuse_conn_info conn;
		  fc->private_data=new->fuse->fops.init(&conn);
#endif
		}
#ifdef NEW_SERVICE_LIST
		new->fuse->service_no = gas_register_service(&s);
#endif
		return 0;
	}
}

static int umfuse_umount2(char *target, int flags,void *umph)
{
	struct fuse_context *fc;
	fc = searchcontext(target, EXACT);
	fuse_set_context(fc);
	if (fc == NULL) {
		errno=EINVAL;
		return -1;
	} else if (fc->fuse->inuse){
		/* TODO FORCE flag */
		errno=EBUSY;
		return -1;
	} else {
		struct fuse_context *fc_norace=fc;
		if (umph == NULL) 
			fc->pid=0;
		else
			fc->pid=um_mod_getpid(umph);
		if (fc->fuse->flags & FUSE_DEBUG) {
			fprintf(stderr, "UMOUNT => path:%s flag:%d\n",target, flags);
			fflush(stderr);
		}
#ifdef NEW_SERVICE_LIST
		if( gas_deregister_service(fc_norace->fuse->service_no) == 0 ){
			errno=EBUSY;
			return -1;
		}
#endif
		delmnttab(fc);
		//printf("PID %d TID %d \n",getpid(),pthread_self());
		pthread_mutex_lock( &fc_norace->fuse->endmutex );
		//pthread_mutex_lock( &condition_mutex );
		if (fc_norace->fuse->fops.destroy != NULL)
			fc_norace->fuse->fops.destroy(fc_norace->private_data);
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

/* Handle for a getdir() operation */
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

static int umfusefillreaddir(void *buf, const char *name, const struct stat *stbuf, off_t off)
{
	fuse_dirh_t h=buf;
	if (name != NULL) {
		struct umdirent *new=(struct umdirent *)malloc(sizeof(struct umdirent));
		if (stbuf == NULL) {
			new->de.d_ino=-1;
			new->de.d_type=0;
		} else {
			new->de.d_ino=stbuf->st_ino;
			new->de.d_type=stbuf->st_mode >> 12;
		}
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
	struct fuse_context *fc=fi->context;
	fuse_set_context(fc);
	dh.tail=NULL;
	dh.offset=0;
	if (fc->fuse->fops.readdir)
		rv=fc->fuse->fops.readdir(fi->path,&dh, umfusefillreaddir, 0, &fi->ffi);
	else
		rv=fc->fuse->fops.getdir(fi->path, &dh, umfusefilldir);
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

static int umfuse_getdents(unsigned int fd, struct dirent *dirp, unsigned int count)
{
	if (filetab[fd]==NULL) {
		errno=EBADF;
		return -1;
	} else {
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

static int umfuse_getdents64(unsigned int fd, struct dirent64 *dirp, unsigned int count)
{
	if (filetab[fd]==NULL) {
		errno=EBADF;
		return -1;
	} else {
		unsigned int curoffs=0;
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
				/* workaround: some FS do not set d_ino, but
				 * inode 0 is special and is skipped by libc */
				if (current->d_ino == 0)
					current->d_ino = 2;
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

static int umfuse_access(char *path, int mode, void *umph);

/*search the currect context depending on path
 * return 1 succesfull o 0 if an error occur*/

static int fuse_path(int type, void *arg)
{
	if (type == CHECKPATH) {
		char *path=arg;
		struct fuse_context *fc=searchcontext(path,SUBSTR);
		if ( fc != NULL) {
			fuse_set_context(fc);
			return TRUE; 
		}
		else
			return FALSE;
	} else if (type == CHECKFSTYPE) {
		char *path=arg;
		return (strncmp(path,"umfuse",6) == 0);/* a path with no leading / is a filesystemtype */
		return TRUE;
	} else {
		return FALSE;
	}
}

static char *unwrap(struct fuse_context *fc,char *path)
{
	char *reduced=path+fc->fuse->pathlen;
	if (*reduced == 0)
		return("/");
	else
		return(reduced);
}

static int umfuse_open(char *path, int flags, mode_t mode,void *umph)
{
	struct fuse_context *fc = searchcontext(path, SUBSTR);
	int fi = addfiletab();
	int rv;
	int exists_err;
	struct stat buf;
	assert(fc!=NULL);
	fc->pid=um_mod_getpid(umph);
	fuse_set_context(fc);

#ifdef __UMFUSE_DEBUG__
	PRINTDEBUG(10,"FLAGOPEN path:%s unwrap:%s\nFLAGS:0x%x MODE:%d\n",path,unwrap(fc,path),flags,mode);

	if(flags &  O_CREAT)
		PRINTDEBUG(10, "O_CREAT\n");
	if(flags & O_TRUNC)
		PRINTDEBUG(10, "O_TRUNC\n");
	if(flags &  O_RDONLY)
		PRINTDEBUG(10, "O_RDONLY:\n");
	if(flags &  O_APPEND)
		PRINTDEBUG(10, "O_APPEND\n");
	if(flags &  O_WRONLY)
		PRINTDEBUG(10, "O_WRONLY\n");
	if(flags &  O_RDWR)
		PRINTDEBUG(10, "O_RDWR\n");
	if(flags &  O_ASYNC)
		PRINTDEBUG(10, "O_ASYNC\n");
	if(flags &  O_DIRECT)
		PRINTDEBUG(10, "O_DIRECT\n");
	if(flags &  O_DIRECTORY)
		PRINTDEBUG(10, "O_DIRECTORY\n");
	if(flags &  O_EXCL)
		PRINTDEBUG(10, "O_EXCL\n");
	if(flags &  O_LARGEFILE)
		PRINTDEBUG(10, "O_LARGEFILE\n");
	if(flags &  O_DIRECT)
		PRINTDEBUG(10, "O_NOATIME\n");
	if(flags &  O_DIRECTORY)
		PRINTDEBUG(10, "O_NOCTTY\n");
	if(flags &  O_EXCL)
		PRINTDEBUG(10, "O_NOCTTY\n");
	if(flags &  O_NOFOLLOW)
		PRINTDEBUG(10, "O_NOFOLLOW\n");
	if(flags &  (O_NONBLOCK | O_NDELAY))
		PRINTDEBUG(10, "O_NONBLOCK o O_NDELAY\n");
	if(flags &  O_SYNC)
		PRINTDEBUG(10, "SYNC\n");
#endif

	filetab[fi]->context = fc;
	filetab[fi]->count = 0;
	filetab[fi]->pos = 0;
	filetab[fi]->ffi.flags = flags & ~(O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC);
	filetab[fi]->ffi.writepage = 0; //XXX do we need writepage != 0?
	filetab[fi]->dirinfo = NULL;
	filetab[fi]->dirpos = NULL;
	filetab[fi]->path = strdup(unwrap(fc, path));
	exists_err = fc->fuse->fops.getattr(filetab[fi]->path, &buf);
	filetab[fi]->size = buf.st_size;

	if ((flags & (O_CREAT | O_TRUNC | O_WRONLY | O_RDWR)) && (fc->fuse->flags & MS_RDONLY)) {
		free(filetab[fi]->path);
		errno = EROFS;
		return -1;
	}
	if(exists_err == 0 && (flags & O_TRUNC) && (flags & (O_WRONLY | O_RDWR))) {
		rv=fc->fuse->fops.truncate(filetab[fi]->path, 0);
		if (rv < 0) {
			free(filetab[fi]->path);
			errno = -rv;
			return -1;
		}
	}
#if ( FUSE_MINOR_VERSION >= 5 )
	if (flags == O_CREAT|O_WRONLY|O_TRUNC && fc->fuse->fops.create != NULL) {
			rv = fc->fuse->fops.create(filetab[fi]->path, mode, &filetab[fi]->ffi);
	} else
#endif
	{
		if (flags & O_CREAT) { 
			if (exists_err == 0) {
				if (flags & O_EXCL) {
					free(filetab[fi]->path);
					errno= EEXIST;
					return -1;
				} 
			} else {
				PRINTDEBUG(10, "umfuse open MKNOD call\n");
				rv = fc->fuse->fops.mknod(filetab[fi]->path, S_IFREG | mode, (dev_t) 0);
				if (rv < 0) {
					free(filetab[fi]->path);
					errno = -rv;
					return -1;
				}
			}
		}
		PRINTDEBUG(10,"open_fuse_filesystem CALL!\n");
		if ((flags & O_DIRECTORY) && fc->fuse->fops.readdir)
			rv = fc->fuse->fops.opendir(filetab[fi]->path, &filetab[fi]->ffi);
		else
			rv = fc->fuse->fops.open(filetab[fi]->path, &filetab[fi]->ffi);
	}

	if (rv < 0)
	{
		if (fc->fuse->flags & FUSE_DEBUG) {
        		fprintf(stderr, "OPEN[%d] ERROR => path:%s flags:0x%x\n",
				fi, path, flags);	
			fflush(stderr);
		}		
		delfiletab(fi);
		errno = -rv;
		return -1;
	} else {
		filetab[fi]->count += 1;
		if (fc->fuse->flags & FUSE_DEBUG) {
        		fprintf(stderr, "OPEN[%d] => path:%s flags:0x%x\n",
				fi, path, flags);
			fflush(stderr);
		}

		/* TODO update fuse->inuse++ */
		fc->fuse->inuse++;
		return fi;
	}
}

static int umfuse_close(int fd,void *umph)
{
	int rv;
	
	if (filetab[fd]==NULL) {
		errno=EBADF;
		return -1;
	} else {
		struct fuse_context *fc=filetab[fd]->context;
		fuse_set_context(fc);
		fc->pid=um_mod_getpid(umph);

		if (fc->fuse->flags & FUSE_DEBUG) {
        	        fprintf(stderr, "CLOSE[%d] %s %p\n",fd,filetab[fd]->path,fc);
                	fflush(stderr);
	        }
	
		if (!(filetab[fd]->ffi.flags & O_DIRECTORY))
			rv=fc->fuse->fops.flush(filetab[fd]->path, &filetab[fd]->ffi);
		
		if (fc->fuse->flags & FUSE_DEBUG) {
			fprintf(stderr, "FLUSH[%d] => path:%s\n",
				fd, filetab[fd]->path);
			fflush(stderr);
		}
	
		filetab[fd]->count--;
		PRINTDEBUG(10,"->CLOSE %s %d\n",filetab[fd]->path, filetab[fd]->count);
		if (filetab[fd]->count == 0) {			 
			fc->fuse->inuse--;
			if ((filetab[fd]->ffi.flags & O_DIRECTORY) && fc->fuse->fops.readdir)
				rv = fc->fuse->fops.releasedir(filetab[fd]->path, &filetab[fd]->ffi);
			else
				rv=fc->fuse->fops.release(filetab[fd]->path, &filetab[fd]->ffi);
			if (fc->fuse->flags & FUSE_DEBUG) {
        			fprintf(stderr, "RELEASE[%d] => path:%s flags:0x%x\n",
					fd, filetab[fd]->path, fc->fuse->flags);
				fflush(stderr);					
			}
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
	} return 0;
}

static int umfuse_read(int fd, void *buf, size_t count,void *umph)
{
	int rv;
	if (filetab[fd]==NULL) {
		errno=EBADF;
		return -1;
	} else if (filetab[fd]->pos == filetab[fd]->size)
		return 0;
	else {
		struct fuse_context *fc=filetab[fd]->context;
		fuse_set_context(fc);
	  fc->pid=um_mod_getpid(umph);
		rv = fc->fuse->fops.read(
				filetab[fd]->path,
				buf,
				count,
				filetab[fd]->pos,
				&filetab[fd]->ffi);
		if (fc->fuse->flags & FUSE_DEBUG) {
        		fprintf(stderr, "READ[%d] => path:%s count:%u\n",
				fd, filetab[fd]->path, count);
			fflush(stderr);
		}
		if (rv<0) {
			errno= -rv;
			return -1;
		} else {
			filetab[fd]->pos += rv;
			return rv;
		}
	}
}

static int umfuse_write(int fd, void *buf, size_t count,void *umph)
{
#ifdef __UMFUSE_EXPERIMENTAL__
//TODO write page?!
	int rv;

	if (filetab[fd]==NULL) {
		errno = EBADF;
		/*
		if (fc->fuse->flags & FUSE_DEBUG) {
			fprintf(stderr, "WRITE[%d] => Error File Not Found\n");	
			fflush(stderr);
		}*/
		return -1;
	} else {
		struct fuse_context *fc=filetab[fd]->context;
		fuse_set_context(fc);
		fc->pid=um_mod_getpid(umph);
		rv = fc->fuse->fops.write(filetab[fd]->path,
				buf, count, filetab[fd]->pos, &filetab[fd]->ffi);
		if (fc->fuse->flags & FUSE_DEBUG) {
			fprintf(stderr, "WRITE[%d] => path:%s count:0x%x\n",
				fd, filetab[fd]->path, count);
			fflush(stderr);
		}
	
		PRINTDEBUG(10,"WRITE rv:%d\n",rv); 

//		if (fc->fuse->flags & FUSE_DEBUG)
  //      		fprintf(stderr, "WRITE[%lu] => path:%s count:0x%x\n",
//				filetab[fd]->ffi.fh, filetab[fd]->path, count);
		//printf("WRITE%s[%lu] %u bytes to %llu\n",
                  // (arg->write_flags & 1) ? "PAGE" : "",
                  // (unsigned long) arg->fh, arg->size, arg->offset);
		if (rv<0) {
			errno= -rv;
			return -1;
		} else {
			filetab[fd]->pos += rv;
			return rv;
		}
	}
#else
	errno = EROFS;
	return -1;
#endif
}

static int stat2stat64(struct stat64 *s64, struct stat *s)
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
	return 0;
}

static int common_stat(struct fuse_context *fc, char *path,  struct stat *buf,void *umph,int wrapped)
{
	int rv;
	assert(fc != NULL);
	fuse_set_context(fc);
	fc->pid=um_mod_getpid(umph);
	memset(buf, 0, sizeof(struct stat));
	rv = fc->fuse->fops.getattr(
			(wrapped)?unwrap(fc,path):path,buf);
	if (fc->fuse->flags & FUSE_DEBUG) {
		fprintf(stderr, "stat->GETATTR => path:%s status: %s\n",
				path, rv ? "Error" : "Success");
		fflush(stderr);
	}
	if (rv<0) {
		errno= -rv;
		return -1;
	} else
		return rv;
}

static int common_stat64(struct fuse_context *fc, char *path,  struct stat64 *buf64,void *umph,int wrapped)
{
	int rv;
	struct stat buf;
	if ((rv=common_stat(fc,path,&buf,umph,wrapped))>=0)
		stat2stat64(buf64,&buf);
	return rv;
}

static int umfuse_fstat(int fd, struct stat *buf,void *umph)
{
	if (fd < 0 || filetab[fd] == NULL) {
		errno=EBADF;
		return -1;
	} else {
		struct fuse_context *fc=fuse_get_context();
		fuse_set_context(fc);
#if ( FUSE_MINOR_VERSION >= 5 )
		assert(fc != NULL);
		if (fc->fuse->fops.fgetattr == NULL)
			return common_stat(fc,filetab[fd]->path,buf,umph,0);
		else {
			int rv;
			fc->pid=um_mod_getpid(umph);
			rv = fc->fuse->fops.fgetattr(
					      filetab[fd]->path,buf,&filetab[fd]->ffi);
			if (fc->fuse->flags & FUSE_DEBUG) {
				fprintf(stderr, "ftat->FETATTR => path:%s status: %s\n",
						filetab[fd]->path, rv ? "Error" : "Success");
				fflush(stderr);
			}
			if (rv < 0) {
				errno = -rv;
				return -1;
			} else
				return rv;
		}
#else
		return common_stat(fc,filetab[fd]->path,buf,umph,0);
#endif
	}
}

static int umfuse_fstat64(int fd, struct stat64 *buf64,void *umph)
{
	if (filetab[fd]==NULL) {
		errno=EBADF;
		return -1;
	} else {
		int rv;
		struct stat buf;
		if ((rv=umfuse_fstat(fd,&buf,umph))>=0)
			stat2stat64(buf64,&buf);
		return rv;
	}
}

static int umfuse_stat(char *path, struct stat *buf,void *umph)
{
	return common_stat(searchcontext(path,SUBSTR),path,buf,umph,1);
}

static int umfuse_lstat(char *path, struct stat *buf,void *umph)
{
	return common_stat(searchcontext(path,SUBSTR),path,buf,umph,1);
}

static int umfuse_stat64(char *path, struct stat64 *buf64,void *umph)
{
	return common_stat64(searchcontext(path,SUBSTR),path,buf64,umph,1);
}

static int umfuse_lstat64(char *path, struct stat64 *buf64,void *umph)
{
	return common_stat64(searchcontext(path,SUBSTR),path,buf64,umph,1);
}

static int umfuse_readlink(char *path, char *buf, size_t bufsiz,void *umph)
{
	struct fuse_context *fc=fuse_get_context();
	int rv;
	assert(fc != NULL);
	fuse_set_context(fc);
	fc->pid=um_mod_getpid(umph);
	rv = fc->fuse->fops.readlink(
			unwrap(fc, path), buf, bufsiz);
	if (rv == 0)
		rv=strnlen(buf,bufsiz);
	PRINTDEBUG(10,"umfuse_readlink %s %s %d\n",unwrap(fc,path),buf,rv);
	if (rv < 0) {
		errno = -rv;
		return -1;
	} else
		return rv;
}

static int umfuse_access(char *path, int mode, void *umph)
{
	/* TODO dummy stub for access */

	struct fuse_context *fc=searchcontext(path, SUBSTR);
	int rv;
	struct stat buf;
	assert(fc!=NULL);
	fuse_set_context(fc);
	fc->pid=um_mod_getpid(umph);
	if (fc->fuse->flags & FUSE_DEBUG) {
        	fprintf(stderr, "ACCESS => path:%s mode:%s%s%s%s\n", path,
				(mode & R_OK) ? "R_OK": "",
				(mode & W_OK) ? "W_OK": "",
				(mode & X_OK) ? "X_OK": "",
				(mode & F_OK) ? "F_OK": "");
		fflush(stderr);
	}
#if ( FUSE_MINOR_VERSION >= 5 )
	/* "default permission" management */
	if (fc->fuse->fops.access != NULL)
		rv= fc->fuse->fops.access(unwrap(fc, path), mode);
	else
#endif
	{
		rv = fc->fuse->fops.getattr(unwrap(fc, path), &buf);
		/* XXX user permission management */
	}
	if (rv < 0) {
		errno = -rv;
		return -1;
	} else {
		errno = 0;
		return 0;
	}
}
/*
static int umfuse_mknod(const char *path, mode_t mode, dev_t dev)
{
	struct fuse_context *fc = searchcontext(path, SUBSTR);
	int rv;
	assert(fc != NULL);
	fuse_set_context(fc);
	if (fc->fuse->flags & FUSE_DEBUG)
        	fprintf(stderr, "MKNOD => path:%s\n",path);
	rv = fc->fuse->fops.mknod(
			unwrap(fc, path), mode, dev);
	if (rv < 0) {
		errno = -rv;
		return -1;
	}
	return rv;
}
*/
static int umfuse_mkdir(char *path, int mode, void *umph)
{
	struct fuse_context *fc=searchcontext(path, SUBSTR);
	int rv;
	assert(fc != NULL);
	fuse_set_context(fc);
	if (fc->fuse->flags & MS_RDONLY) {
		errno = EROFS;
		return -1;
	}
	fc->pid=um_mod_getpid(umph);
	if (fc->fuse->flags & FUSE_DEBUG) {
        	fprintf(stderr, "MKDIR => path:%s\n",path);
		fflush(stderr);
	}
	rv = fc->fuse->fops.mkdir(
			unwrap(fc, path), mode);
	if (rv < 0) {
		errno = -rv;
		return -1;
	} else
		return rv;
}

static int umfuse_rmdir(char *path,void *umph)
{
	struct fuse_context *fc= searchcontext(path, SUBSTR);
	int rv;
	assert(fc!=NULL);
	fuse_set_context(fc);
	if (fc->fuse->flags & MS_RDONLY) {
		errno = EROFS;
		return -1;
	}
	fc->pid=um_mod_getpid(umph);
	if (fc->fuse->flags & FUSE_DEBUG) {
        	fprintf(stderr, "RMDIR => path:%s\n",path);
		fflush(stderr);
	}
	rv= fc->fuse->fops.rmdir(
			unwrap(fc, path));
	if (rv < 0) {
		errno = -rv;
		return -1;
	} else
		return rv;
}

static int umfuse_chmod(char *path, int mode, void *umph)
{
	struct fuse_context *fc = searchcontext(path, SUBSTR);
	int rv;
	fuse_set_context(fc);
	assert(fc != NULL);
	if (fc->fuse->flags & MS_RDONLY) {
		errno = EROFS;
		return -1;
	}
	fc->pid=um_mod_getpid(umph);
	if (fc->fuse->flags & FUSE_DEBUG) {
        	fprintf(stderr, "CHMOD => path:%s\n",path);
		fflush(stderr);
	}
	rv= fc->fuse->fops.chmod(
			unwrap(fc ,path), mode);
	if (rv < 0) {
		errno = -rv;
		return -1;
	}
	return rv;
}

static int umfuse_chown(char *path, uid_t owner, gid_t group,void *umph)
{
	struct fuse_context *fc = searchcontext(path, SUBSTR);
	int rv;
	assert(fc != NULL);
	fuse_set_context(fc);
	if (fc->fuse->flags & MS_RDONLY) {
		errno = EROFS;
		return -1;
	}
	fc->pid=um_mod_getpid(umph);
	rv = fc->fuse->fops.chown(
			unwrap(fc, path), owner, group);
	if (rv < 0) {
		errno = -rv;
		return -1;
	} else
		return rv;
}

static int umfuse_lchown(char *path, uid_t owner, gid_t group,void *umph)
{
//	Do not follow symlinks
//		and call chown
}

static int umfuse_unlink(char *path,void *umph)
{
	struct fuse_context *fc=searchcontext(path, SUBSTR);
	int rv;
	assert(fc != NULL);
	fuse_set_context(fc);
	if (fc->fuse->flags & MS_RDONLY) {
		errno = EROFS;
		return -1;
	}
	fc->pid=um_mod_getpid(umph);
	if (fc->fuse->flags & FUSE_DEBUG)
        	fprintf(stderr, "UNLINK => path:%s\n",path);
	rv = fc->fuse->fops.unlink(
			unwrap(fc, path));
	if (rv < 0) {
		errno = -rv;
		return -1;
	} else
		return rv;
}

static int umfuse_link(char *oldpath, char *newpath,void *umph)
{
	struct fuse_context *fc= searchcontext(newpath, SUBSTR);
	int rv;
	assert(fc != NULL);
	fuse_set_context(fc);
	if (fc->fuse->flags & MS_RDONLY) {
		errno = EROFS;
		return -1;
	}
	fc->pid=um_mod_getpid(umph);

	if (fc->fuse->flags & FUSE_DEBUG)
        	fprintf(stderr, "LINK => oldpath:%s newpath:%s\n",oldpath, newpath);
	rv = fc->fuse->fops.link(
			unwrap(fc, oldpath),
			unwrap(fc, newpath));
	if (rv < 0) {
		errno = -rv;
		return -1;
	} else
		return rv;	
}

//see fuse.h: it is has not the same meaning of syscall
static int umfuse_fsync(int fd)
{
	struct fuse_context *fc=filetab[fd]->context;
	fuse_set_context(fc);
	if (fc->fuse->flags & FUSE_DEBUG) {
        	fprintf(stderr, "kernel FSYNC. It has a different semantics in fuse\n");
		fflush(stderr);
	}
			
	/*	//	rv = fc->fuse->fops.read
	//struct fuse_context *fc=searchcontext(oldpath, SUBSTR);
	int rv;
	assert(fc != NULL);
	if (fc->fuse->flags & FUSE_DEBUG)
        	fprintf(stderr, "FSYNC => path:%s:\n",filetab[fd]->path);
	rv = fc->fuse->fops.fsync(fd);
	if (rv < 0) {
		errno = -rv;
		return -1;
	} else
	        return rv;
*/
	return 0;
}

static int umfuse_rename(char *oldpath, char *newpath, void *umph)
{
	struct fuse_context *fc=searchcontext(newpath, SUBSTR);
	int rv;
	assert(fc != NULL);
	fc->pid=um_mod_getpid(umph);
	fuse_set_context(fc);
	if (fc->fuse->flags & FUSE_DEBUG) {
        	fprintf(stderr, "RENAME => %s ->%s\n",oldpath, newpath);
		fflush(stderr);
	}
	rv = fc->fuse->fops.rename(
			unwrap(fc, oldpath),
			unwrap(fc, newpath));
	if (rv < 0) {
		errno = -rv;
		return -1;
	} else
		return rv;	
}

static int umfuse_symlink(char *oldpath, char *newpath, void *umph)
{
	
	struct fuse_context *fc=searchcontext(newpath, SUBSTR);
	int rv;

	assert(fc != NULL);
	fuse_set_context(fc);
	if (fc->fuse->flags & MS_RDONLY) {
		errno = EROFS;
		return -1;
	}
	fc->pid=um_mod_getpid(umph);
	if (fc->fuse->flags & FUSE_DEBUG) {
        	fprintf(stderr, "SYMLINK => %s -> %s\n",
					newpath, oldpath);
		fflush(stderr);
	}
	rv = fc->fuse->fops.symlink(
			oldpath,
			unwrap(fc, newpath));
	if (rv < 0) {
		errno = -rv;
		return -1;
	} else
		return rv;	
}

static int umfuse_truncate(char *path, off_t length,void *umph)
{

	struct fuse_context *fc=searchcontext(path, SUBSTR);
	int rv;
	assert(fc != NULL);
	fuse_set_context(fc);
	if (fc->fuse->flags & MS_RDONLY) {
		errno = EROFS;
		return -1;
	}
	fc->pid=um_mod_getpid(umph);

	if (fc->fuse->flags & FUSE_DEBUG) {
        	fprintf(stderr, "TRUNCATE debug => path %s\n",path);		
		fflush(stderr);
	}
	rv = fc->fuse->fops.truncate(
			unwrap(fc, path),length);
	if (rv < 0) {
		errno = -rv;
		return -1;
	} else
		return rv;	
}

static int umfuse_ftruncate(int fd, off_t length, void *umph)
{
	if (filetab[fd]==NULL) {
		errno=EBADF;
		return -1;
	} else {
#if ( FUSE_MINOR_VERSION >= 5 )
		struct fuse_context *fc=filetab[fd]->context;
		assert(fc != NULL);
		fuse_set_context(fc);
		if (fc->fuse->flags & MS_RDONLY) {
			errno = EROFS;
			return -1;
		}
		if (fc->fuse->fops.ftruncate == NULL)
			return umfuse_truncate(filetab[fd]->path,length, umph);
		else {
			int rv;
			fc->pid=um_mod_getpid(umph);
			rv = fc->fuse->fops.ftruncate(
					filetab[fd]->path,length,&filetab[fd]->ffi);
			if (fc->fuse->flags & FUSE_DEBUG) {
				fprintf(stderr, "FTRUNCATE debug => path %s\n",filetab[fd]->path);		
				fflush(stderr);
			}
			if (rv < 0) {
				errno = -rv;
				return -1;
			} else
				return rv;	
		}
#else
		return umfuse_truncate(filetab[fd]->path,length, umph);
#endif
	}
}

/** Change the access and/or modification times of a file */
static int umfuse_utime(char *path, struct utimbuf *buf, void *umph)
{
	struct fuse_context *fc = searchcontext(path, SUBSTR);
	int rv;
	assert(fc != NULL);
	fuse_set_context(fc);
	if (fc->fuse->flags & MS_RDONLY) {
		errno = EROFS;
		return -1;
	}
	fc->pid=um_mod_getpid(umph);
	if (buf == NULL) {
		struct utimbuf localbuf;
		localbuf.actime=localbuf.modtime=time(NULL);
		rv = fc->fuse->fops.utime(unwrap(fc, path), &localbuf);
	} else
		rv = fc->fuse->fops.utime(unwrap(fc, path), buf);
	if (rv < 0) {
		errno = -rv;
		return -1;
	}
	return rv;	
}

static int umfuse_utimes(char *path, struct timeval tv[2], void *umph)
{
	//approximate solution. drop microseconds
	if (tv == NULL) {
		return umfuse_utime(path, NULL, umph);	
	} else {
		struct utimbuf buf;
		buf.actime=tv[0].tv_sec;
		buf.modtime=tv[1].tv_sec;
		return umfuse_utime(path, &buf, umph);
	}
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
static int umfuse_fcntl32(int fd, int cmd, void *arg, void *umph)
{
	//printf("umfuse_fcntl32\n");
	errno=0;
	return 0;
}

static int umfuse_fcntl64(int fd, int cmd, void *arg, void *umph)
{
	//printf("umfuse_fcntl64\n");
	errno=0;
	return 0;
}

static int umfuse_lseek(int fd, int offset, int whence, void *umph)
{
	if (filetab[fd]==NULL) {
		errno = EBADF; 
		return -1;
	} else {
		switch (whence) {
			case SEEK_SET:
				filetab[fd]->pos=offset;
				break;
			case SEEK_CUR:
				 filetab[fd]->pos += offset;
				 break;
			case SEEK_END:
				 {
				 struct stat buf;
				 int rv;
				 struct fuse_context *fc=filetab[fd]->context;
				 assert(fc != NULL);
				 fuse_set_context(fc);

				 fc->pid=um_mod_getpid(umph);
				 rv = fc->fuse->fops.getattr(filetab[fd]->path,&buf);
				 if (rv>=0) {
				 	filetab[fd]->pos = buf.st_size + offset;
				 } else {
					 errno=EBADF;
					 return -1;
				 }
				 }
				 break;
		}

		return filetab[fd]->pos;
	}
}

static int umfuse__llseek(unsigned int fd, unsigned long offset_high,  unsigned  long offset_low, loff_t *result, unsigned int whence, void *umph)
{
	PRINTDEBUG(10,"umfuse__llseek %d %d %d %d\n",fd,offset_high,offset_low,whence);
	if (result == NULL) {
		errno = EFAULT;
		return -1;
	} else if (offset_high != 0) {
		errno = EINVAL;
		return -1;
	} else {
		long rv;
		rv=umfuse_lseek(fd,offset_low,whence,umph);
		if (rv >= 0) {
			*result=rv;
			return 0;
		} else {
			errno = -rv;
			return -1;
		}
	}
}

void contextclose(struct fuse_context *fc)
{
	umfuse_umount2(fc->fuse->path,MNT_FORCE,NULL);
}


static void
__attribute__ ((constructor))
init (void)
{
	printf("umfuse init\n");
	s.name="umfuse fuse ";
	s.code=0x01;
	s.checkfun=fuse_path;
	pthread_key_create(&context_key,NULL);
	s.syscall=(intfun *)malloc(scmap_scmapsize * sizeof(intfun));
	s.socket=(intfun *)malloc(scmap_sockmapsize * sizeof(intfun));
	s.syscall[uscno(__NR_mount)]=umfuse_mount;
#if ! defined(__x86_64__)
	s.syscall[uscno(__NR_umount)]=umfuse_umount2; /* umount must be mapped onto umount2 */
#endif
	s.syscall[uscno(__NR_umount2)]=umfuse_umount2;
	s.syscall[uscno(__NR_open)]=umfuse_open;
	s.syscall[uscno(__NR_creat)]=umfuse_open; /*creat is an open with (O_CREAT|O_WRONLY|O_TRUNC)*/
	s.syscall[uscno(__NR_read)]=umfuse_read;
#ifdef __UMFUSE_EXPERIMENTAL__
	s.syscall[uscno(__NR_write)]=umfuse_write;
#endif
	//s.syscall[uscno(__NR_readv)]=readv;
	//s.syscall[uscno(__NR_writev)]=writev;
	s.syscall[uscno(__NR_close)]=umfuse_close;
	s.syscall[uscno(__NR_stat)]=umfuse_stat;
	s.syscall[uscno(__NR_lstat)]=umfuse_lstat;
	s.syscall[uscno(__NR_fstat)]=umfuse_fstat;
#if !defined(__x86_64__)
	s.syscall[uscno(__NR_stat64)]=umfuse_stat64;
	s.syscall[uscno(__NR_lstat64)]=umfuse_lstat64;
	s.syscall[uscno(__NR_fstat64)]=umfuse_fstat64;
#endif
	s.syscall[uscno(__NR_readlink)]=umfuse_readlink;
	s.syscall[uscno(__NR_getdents)]=umfuse_getdents;
	s.syscall[uscno(__NR_getdents64)]=umfuse_getdents64;
	s.syscall[uscno(__NR_access)]=umfuse_access;
	s.syscall[uscno(__NR_fcntl)]=umfuse_fcntl32;
#if ! defined(__x86_64__)
	s.syscall[uscno(__NR_fcntl64)]=umfuse_fcntl64;
	s.syscall[uscno(__NR__llseek)]=umfuse__llseek;
#endif
	s.syscall[uscno(__NR_lseek)]=umfuse_lseek;
	//s.syscall[uscno(__NR_mknod)]=umfuse_mknod;
#ifdef __UMFUSE_EXPERIMENTAL__
	s.syscall[uscno(__NR_mkdir)]=umfuse_mkdir;
	s.syscall[uscno(__NR_rmdir)]=umfuse_rmdir;
	s.syscall[uscno(__NR_chown)]=umfuse_chown;
	//s.syscall[uscno(__NR_lchown)]=umfuse_lchown;
	//s.syscall[uscno(__NR_fchown)]=fchown;
	s.syscall[uscno(__NR_chmod)]=umfuse_chmod;
	//s.syscall[uscno(__NR_fchmod)]=fchmod;
	s.syscall[uscno(__NR_unlink)]=umfuse_unlink;
	s.syscall[uscno(__NR_fsync)]=umfuse_fsync; //not the syscall meaning
	//s.syscall[uscno(__NR_fdatasync)]=fdatasync;
	//s.syscall[uscno(__NR__newselect)]=select;
	s.syscall[uscno(__NR_link)]=umfuse_link;
	s.syscall[uscno(__NR_symlink)]=umfuse_symlink;
	s.syscall[uscno(__NR_rename)]=umfuse_rename;
	s.syscall[uscno(__NR_truncate)]=umfuse_truncate;
	s.syscall[uscno(__NR_ftruncate)]=umfuse_ftruncate;
#endif
	//s.syscall[uscno(__NR_pread64)]=umfuse_pread;
	//s.syscall[uscno(__NR_pwrite64)]=umfuse_pwrite;
	s.syscall[uscno(__NR_utime)]=umfuse_utime;
	s.syscall[uscno(__NR_utimes)]=umfuse_utimes;
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

