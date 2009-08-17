/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   umviewos -> fuse gateway
 *   
 *   Copyright 2005 Renzo Davoli University of Bologna - Italy
 *   Modified 2005 Paolo Angelelli, Andrea Seraghiti
 *   Patched 2006 Paolo Beverini
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
#include <linux/unistd.h>
#include "module.h"
#include "libummod.h"
#include "umfusestd.h"
#include "gdebug.h"
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/ipc.h>
#include <stdarg.h>
#include <math.h>
#include <values.h>
#include <bits/wordsize.h>
#include <grp.h>
#include <pwd.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <config.h>

#if ( FUSE_MINOR_VERSION <= 5 )
#error UMFUSE NEEDS FUSE >= 2.6
#endif 

#define FUSE_SUPER_MAGIC 0x65735546

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
VIEWOS_SERVICE(s)

struct fuse {
	char *filesystemtype;
	char *path;
	char **exceptions;
	short pathlen;
	void *dlhandle;
	pthread_t thread;
	pthread_cond_t startloop;
	pthread_cond_t endloop;
	pthread_mutex_t endmutex;
	struct fuse_operations fops;	
	int inuse;
	unsigned long flags;
};

/* values for INUSE and thread synchro */
#define WAITING_FOR_LOOP -1
#define EXITING -2
#define FUSE_ABORT -3
static pthread_mutex_t condition_mutex = PTHREAD_MUTEX_INITIALIZER;

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
	//unsigned short d_reclen32;
	struct umdirent *next;
};

struct fileinfo {
	struct fuse_context *context;
	char *path;						
	long long pos;				/* file offset */
	long long size;				/* file offset */
	struct fuse_file_info ffi;		/* includes open flags, file handle and page_write mode  */
	struct umdirent *dirinfo;		/* conversion fuse-getdir into kernel compliant
																 dirent. Dir head pointer */
	struct umdirent *dirpos;		/* same conversion above: current pos entry */
};

struct fuse_context *fuse_get_context(void)
{
	//struct ht_elem *hte=um_mod_get_hte();
	//printk("fuse_get_context %p %p \n",hte,hte->private_data);
	struct fuse_context *context=um_mod_get_private_data();
	/* fs ids are more consistent than effective ids */
	um_mod_getfs_uid_gid(&(context->uid),&(context->gid));
	context->pid=um_mod_getpid();
	return um_mod_get_private_data();
}

/* static umfuse own debug function */
/* it accept a level of debug: higher level = more important messages only */

#ifdef __UMFUSE_DEBUG__
#if 0
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
#endif

/* search for exceptions returns 1 if it is an exception */
/* XXX EXPERIMENTAL TODO implemement this as negative mount! */

static inline int isexception(char *path, char **exceptions, struct fuse_context *fc)
{
	if (__builtin_expect((exceptions == NULL && !(fc->fuse->flags & FUSE_MERGE)),1))
		return 0;
	else {
		if (exceptions) {
			while (*exceptions != 0) {
				int len=strlen(*exceptions);
				if (strncmp(path,*exceptions,len) == 0 &&
						(path[len] == '/' || path[len]=='\0'))
					return 1;
				exceptions ++;
			}
		}
		if (fc->fuse->flags & FUSE_MERGE) {
			if (*path) {
				struct stat buf;
				int rv=fc->fuse->fops.getattr(path,&buf);
				return (rv < 0);
			} else
				return 0;
		}
		return 0;
	}
}

static inline void freeexceptions(char **exceptions)
{
	if (__builtin_expect((exceptions == NULL),1))
		return;
	else {
		char **excscan=exceptions;
		while (*excscan != 0) {
			free(*excscan);
			excscan++;
		}
		free(exceptions);
	}
}

static int umfuse_confirm(int type, void *arg, int arglen,
		struct ht_elem *ht)
{
	char *path=arg;
	struct fuse_context *fc=ht_get_private_data(ht);
	return !isexception(path+fc->fuse->pathlen,fc->fuse->exceptions,fc);
}

static char *unwrap(struct fuse_context *fc,char *path);
/*HUMAN MODE MGMT*/
#define MAY_EXEC 1
#define MAY_WRITE 2
#define MAY_READ 4

static int check_group(gid_t gid){
	static pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
	int res;
	struct fuse_context *fc;
	int i, ng=1;
	struct passwd pw;
	gid_t *groups = NULL;
	char *buf;
	size_t buflen;
	struct passwd *pwbufp;
	uid_t myuid;
	gid_t mygid;

	fc=um_mod_get_private_data();
	if (fc!=NULL) {
		myuid=fc->uid;
		mygid=fc->gid;
	} else {
		myuid=getuid();
		mygid=getgid();
	}

	pthread_mutex_lock( &m );
	buflen=sysconf(_SC_GETPW_R_SIZE_MAX);
	buf=malloc(buflen);
	if (myuid!=0){
		res=getpwuid_r(myuid, &pw,buf,buflen, &pwbufp);
		if (res==0) {
			res=-EACCES;
			groups = (gid_t *) malloc(ng * sizeof (gid_t));
			if (getgrouplist(pw.pw_name, pw.pw_gid, groups, &ng) < 0) {
				free(groups);
				groups = (gid_t *) malloc(ng * sizeof (gid_t));
				if (groups!=NULL) {
					getgrouplist(pw.pw_name, pw.pw_gid, groups, &ng);
					for(i = 0; i < ng; i++) {							
						if (groups[i]==gid) {res=0;break;}
					}
				}
			}
			free(groups); 
		}
	} else {res=0;}
	pthread_mutex_unlock( &m );
	return res;
}

static int check_permission(mode_t mode,uid_t uid,gid_t gid,int mask){
	struct fuse_context *fc=um_mod_get_private_data();
	int res=-EACCES;
	uid_t myuid;
	gid_t mygid;

	if (fc!=NULL) {
		myuid=fc->uid;
		mygid=fc->gid;
	} else {
		myuid=getuid();
		mygid=getgid();
	}

	if (myuid!=0){
		if (uid==myuid){
			if (mode & (mask<<6)) {res=0;}
		} else {
			if (res!=0){
				if (check_group(gid)==0){
					if (mode & (mask<<3)) {res=0;}
				} else  if (mode & mask) {res=0;}
			}
		}
	} else {res=0;}
	return res;
}

static int path_check_permission(char *path,int mask) {
	struct fuse_context *fc=um_mod_get_private_data();
	struct stat buf;
	int rv=fc->fuse->fops.getattr(path,&buf);
	if (rv>=0) rv=check_permission(buf.st_mode,buf.st_uid,buf.st_gid,mask);
	return rv;
}

static char *get_parent_path (char *path){
	char *ppath=strdup (path);
	int x=strlen (path)-1;
	while ((ppath[x]!='/') && (x>0)) x--;
	if (x==0) {
		ppath[0]='/';
		x++;
	}
	ppath[x]='\0';
	return ppath;
}

static int check_parent(char *path,int mask) {
	char *ppath=get_parent_path(path);
	struct fuse_context *fc=um_mod_get_private_data();
	int rv;
	if (strncmp(ppath,fc->fuse->path,fc->fuse->pathlen)==0) {
		rv=path_check_permission(unwrap(fc,ppath),mask);
	} else {
		struct stat buf;
		rv=stat(ppath,&buf);
		if (rv>=0) rv=check_permission(buf.st_mode,buf.st_uid,buf.st_gid,mask);
	}
	free(ppath);
	return rv;
}

int check_owner(char *path){
	struct stat buf;
	int rv;
	struct fuse_context  *fc=fuse_get_context();

	if (fc->fuse->fops.getattr) rv=fc->fuse->fops.getattr(path,&buf);
	if (rv<0) {
		PRINTDEBUG (10,"check_owner.Getattr failed:%s\n",path);
		return rv;
	}

	if ((fc->uid!=0) && (buf.st_uid != fc->uid)) {
		return -EACCES;
	}
}
/**/

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

	GDEBUG(10,"mountflags: %x",mountflags);
	GDEBUG(10,"data: %s",data);

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
	GDEBUG(10,"opts: %s",opts);
	return(strdup(opts));
}

static void *startmain(void *vsmo)
{
	struct startmainopt *psmo = vsmo;
	int (*pmain)() = dlsym(psmo->new->fuse->dlhandle,"main");
	char *opts;
	int newargc;
	char **newargv;
	char **newnewargv;
	int i;
	if (pmain == NULL) {
		GMESSAGE("%s", dlerror());
	}
	/* handle -o options and specific filesystem options */
	opts = mountflag2options(*(psmo->pmountflags), psmo->data);
	newargc=fuseargs(psmo->new->fuse->filesystemtype,psmo->source, psmo->new->fuse->path,opts, &newargv,psmo->new, &(psmo->new->fuse->flags), &(psmo->new->fuse->exceptions));
	free(opts);
	if (psmo->new->fuse->flags & FUSE_DEBUG) {
		GMESSAGE("UmFUSE Debug enabled");
		GMESSAGE("MOUNT=>filesystem:%s image:%s path:%s args:%s",
				psmo->new->fuse->filesystemtype, psmo->source, psmo->new->fuse->path,opts);
	}

	if (psmo->new->fuse->flags & FUSE_HUMAN)
		printk("UmFUSE Human mode\n");

	/* some modules could change argv! */
	if ((newnewargv=malloc(newargc * sizeof (char *))) != NULL) {
		for (i=0;i<newargc;i++) 
			newnewargv[i]=newargv[i];
		optind=1;
		if (pmain(newargc,newnewargv) != 0)
			umfuse_abort(psmo->new->fuse);
		free(newnewargv);
	}
	fusefreearg(newargc,newargv);
	pthread_exit(NULL);
	return NULL;
}

/*TODO parse cmd, es dummy is rw or ro!*/
//see fuse_setup_common lib/helper.c
int fuse_main_real(int argc, char *argv[], const struct fuse_operations *op,
		size_t op_size, void *user_data)
{
	struct fuse *f;
	struct fuse_chan *fuseargs = fuse_mount(NULL, NULL); //options have been already parsed
	f = fuse_new(fuseargs, NULL, op, op_size, user_data);
	//I cannot understand this comment. (renzo)
	//"now opts are lib_opts;debug,hard_remove,use_ino"
	return fuse_loop(f);
}

/* fuse_mount and fuse_unmount are dummy functions, 
 * the real mount operation has been done in umfuse_mount */
struct fuse_chan *fuse_mount(const char *mountpoint, struct fuse_args *args)
{
	GDEBUG(10,"fuse_mount %s",mountpoint);
	return (struct fuse_chan *) fuse_get_context();
}


void fuse_unmount(const char *mountpoint, struct fuse_chan *ch)
{
	GDEBUG(10,"fuse_umount %s",mountpoint);
}

/* set standard fuse_operations (umfusestd.c) for undefined fields in the
 * fuse_operations structure */
static void fopsfill (struct fuse_operations *fops,size_t size)
{
	sysfun *f=(sysfun *)fops;
	sysfun *std=(sysfun *) &defaultservice;
	int i;
	int nfun=size/sizeof(sysfun);
	for (i=0; i<nfun; i++)
		if (f[i] == NULL) {
			//printf("%d->std\n",i);
			f[i]=std[i];
		}
}

struct fuse *fuse_new(struct fuse_chan *ch, struct fuse_args *args,
		const struct fuse_operations *op, size_t op_size,
		void *user_data)
{
	struct fuse_context *fc=(struct fuse_context *)ch;
	GDEBUG(10,"%p %p %d %d",fc,fuse_get_context(),op_size,sizeof(struct fuse_operations));
	if (op_size != sizeof(struct fuse_operations))
		GMESSAGE("Fuse module vs umfuse support version mismatch");
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
			struct fuse_conn_info conn;
			fc->private_data=f->fops.init(&conn);
		}
#endif

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
	//printk("ABORT!\n");
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

static long umfuse_mount(char *source, char *target, char *filesystemtype,
		unsigned long mountflags, void *data)
{
	/* TODO: ENOTDIR if it is not a directory */
	void *dlhandle = openmodule(filesystemtype, RTLD_NOW);

	GDEBUG(10, "MOUNT %s %s %s %x %s",source,target,filesystemtype,
			mountflags, (data!=NULL)?data:"<NULL>");

	if(dlhandle == NULL || dlsym(dlhandle,"main") == NULL) {
		GMESSAGE("%s",dlerror());
		if (dlhandle != NULL)
			dlclose(dlhandle);
		errno=ENODEV;
		return -1;
	} else {
		struct fuse_context *new = (struct fuse_context *)
			malloc(sizeof(struct fuse_context));
		struct startmainopt smo;
		assert(new);
		new->fuse = (struct fuse *)malloc(sizeof(struct fuse));
		assert(new->fuse);
		new->fuse->path = strdup(target);
		new->fuse->exceptions = NULL;
		if (strcmp(target,"/")==0)
			new->fuse->pathlen = 0;
		else
			new->fuse->pathlen = strlen(target);
		new->fuse->filesystemtype = strdup(filesystemtype);
		new->fuse->dlhandle = dlhandle;
		memset(&new->fuse->fops,0,sizeof(struct fuse_operations));
		new->fuse->inuse = WAITING_FOR_LOOP;
		new->uid = getuid();
		new->gid = getgid();
		new->pid = um_mod_getpid();
		new->private_data = NULL;
		new->fuse->flags = mountflags; /* all the mount flags + FUSE_DEBUG */

		um_mod_set_hte(ht_tab_pathadd(CHECKPATH,source,target,filesystemtype,mountflags,data,&s,0,umfuse_confirm,new));

		smo.new = new;
		smo.pmountflags = &(new->fuse->flags);
		smo.source = source;
		smo.data = data;

		pthread_cond_init(&(new->fuse->startloop),NULL);
		pthread_cond_init(&(new->fuse->endloop),NULL);
		pthread_mutex_init(&(new->fuse->endmutex),NULL);
		pthread_create(&(new->fuse->thread), NULL, startmain, (void *)&smo);

		GDEBUG(10, "PID %d TID %d",getpid(),pthread_self());
		pthread_mutex_lock( &condition_mutex );
		if (new->fuse->inuse== WAITING_FOR_LOOP)
			pthread_cond_wait( &(new->fuse->startloop), &condition_mutex);
		pthread_mutex_unlock( &condition_mutex );

		if (new->fuse->inuse == FUSE_ABORT)
		{
			struct fuse_context *fc_norace=new;
			//GERROR("UMOUNT ABORT");
			ht_tab_invalidate(um_mod_get_hte());
			pthread_join(fc_norace->fuse->thread, NULL);
			dlclose(fc_norace->fuse->dlhandle);
			free(fc_norace->fuse->filesystemtype);
			freeexceptions(fc_norace->fuse->exceptions);
			free(fc_norace->fuse->path);
			free(fc_norace->fuse);
			ht_tab_del(um_mod_get_hte());
			errno = EIO;
			return -1;
		}
		if (new->fuse->fops.init != NULL) {
			struct fuse_conn_info conn;
			new->private_data=new->fuse->fops.init(&conn);
		}
		return 0;
	}
}

static void umfuse_umount_internal(struct fuse_context *fc, int flags)
{
	struct fuse_context *fc_norace=fc;
	char *target=fc->fuse->path;
	char *ppath;
	ht_tab_invalidate(um_mod_get_hte());
	fc_norace->pid=um_mod_getpid();
	//printk("umount %s\n",target);
	if (fc_norace->fuse->flags & FUSE_DEBUG) {
		GMESSAGE("UMOUNT => path:%s flag:%d",target, flags);
	}
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
	free(fc_norace->fuse->filesystemtype);
	freeexceptions(fc_norace->fuse->exceptions);
	free(fc_norace->fuse->path);
	dlclose(fc_norace->fuse->dlhandle);
	free(fc_norace->fuse);
	free(fc_norace);
}

static long umfuse_umount2(char *target, int flags)
{
	char *ppath;
	struct fuse_context *fc=um_mod_get_private_data();
	if (fc == NULL) {
		errno=EINVAL;
		return -1;
	} else if (fc->fuse->inuse){
		/* TODO FORCE flag */
		errno=EBUSY;
		return -1;
	} else {
		umfuse_umount_internal(fc,flags);
		ht_tab_del(um_mod_get_hte());
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

static int merge_newentry(char *name,struct umdirent *tail,struct umdirent *oldtail)
{
	if (oldtail) {
		do {
			struct umdirent *next=tail->next;
			if (strcmp(next->de.d_name,name)==0)
				return 0;
			tail=next;
		} while (tail != oldtail);
	}
	return 1;
}

static void um_mergedir(char *path,struct fuse_context *fc,fuse_dirh_t h)
{
	char *abspath;
	int fd;
	asprintf(&abspath,"%s%s",fc->fuse->path,path);
	fd=open(abspath,O_RDONLY|O_DIRECTORY);
	free(abspath);
	if (fd) {
		char buf[4096];
		int len;
		struct umdirent *oldtail=h->tail;
		while ((len=getdents64(fd,buf,4096)) > 0) {
			off_t off=0;
			while (off<len) {
				struct dirent64 *de=(struct dirent *)(buf+off);
				if (merge_newentry(de->d_name,h->tail,oldtail))
				{
					struct umdirent *new=(struct umdirent *)malloc(sizeof(struct umdirent));
					new->de.d_name=strdup(de->d_name);
					new->de.d_type=de->d_type;
					new->de.d_ino=de->d_ino;
					new->de.d_reclen=WORDALIGN(SIZEDIRENT64NONAME+strlen(de->d_name)+1);
					new->de.d_off=h->offset=h->offset+WORDALIGN(12+strlen(de->d_name));
					if (h->tail==NULL) {
						new->next=new;
					} else {
						new->next=h->tail->next;
						h->tail->next=new;
					}
					h->tail=new;
				}
				off+=de->d_reclen;
			}
		}
		close(fd);
	}
}

static struct umdirent *umfilldirinfo(struct fileinfo *fi)
{
	int rv;
	struct fuse_dirhandle dh;
	struct fuse_context *fc=fi->context;
	dh.tail=NULL;
	dh.offset=0;
	if (fc->fuse->fops.readdir)
		rv=fc->fuse->fops.readdir(fi->path,&dh, umfusefillreaddir, 0, &fi->ffi);
	else
		rv=fc->fuse->fops.getdir(fi->path, &dh, umfusefilldir);
	if (fc->fuse->flags & FUSE_MERGE && rv>=0) 
		um_mergedir(fi->path,fc,&dh);
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
			free(tmp->de.d_name);
			free(tmp);
		}
		free(tail);
	}
}

static long umfuse_getdents64(unsigned int fd, struct dirent64 *dirp, unsigned int count)
{
	struct fileinfo *ft=getfiletab(fd);
	unsigned int curoffs=0;
	if (ft->dirinfo == NULL) {
		ft->dirinfo = umfilldirinfo(ft);
	} 
	/* TODO management of lseek on directories */

	if (ft->dirinfo==NULL) 
		return 0;
	else {
		struct dirent64 *current;
		char *base=(char *)dirp;
		int last=0;
		if (ft->dirpos==NULL)
			ft->dirpos=ft->dirinfo;
		else
			last=(ft->dirpos==ft->dirinfo);
		while (!last && curoffs + ft->dirpos->next->de.d_reclen < count)
		{
			ft->dirpos=ft->dirpos->next;
			current=(struct dirent64 *)base;
			current->d_ino=ft->dirpos->de.d_ino;
			current->d_off=ft->dirpos->de.d_off;
			current->d_reclen=ft->dirpos->de.d_reclen;
			current->d_type=ft->dirpos->de.d_type;
			strcpy(current->d_name,ft->dirpos->de.d_name);
			/* workaround: some FS do not set d_ino, but
			 * inode 0 is special and is skipped by libc */
			if (current->d_ino == 0)
				current->d_ino = 2;
			base+=ft->dirpos->de.d_reclen;
			curoffs+=ft->dirpos->de.d_reclen;
			last=(ft->dirpos == ft->dirinfo);
		}
	}
	return curoffs;
}

#define TRUE 1
#define FALSE 0

static int alwaysfalse()
{
	return FALSE;
}

static long umfuse_access(char *path, int mode);

static char *unwrap(struct fuse_context *fc,char *path)
{
	char *reduced=path+fc->fuse->pathlen;
	if (*reduced == 0)
		return("/");
	else
		return(reduced);
}

static long umfuse_open(char *path, int flags, mode_t mode)
{
	struct fuse_context *fc = um_mod_get_private_data();
	int fd = addfiletab(sizeof(struct fileinfo));
	struct fileinfo *ft=getfiletab(fd);
	int rv;
	int exists_err;
	struct stat buf;
	assert(fc!=NULL);
	fc->pid=um_mod_getpid();

#ifdef __UMFUSE_DEBUG__
	GDEBUG(10,"FLAGOPEN path:%s unwrap:%s\nFLAGS:0x%x MODE:%d\n",path,unwrap(fc,path),flags,mode);

	if(flags &  O_CREAT)
		GDEBUG(10, "O_CREAT\n");
	if(flags & O_TRUNC)
		GDEBUG(10, "O_TRUNC\n");
	if((flags &  O_ACCMODE) == O_RDONLY)
		GDEBUG(10, "O_RDONLY:\n");
	if(flags &  O_APPEND)
		GDEBUG(10, "O_APPEND\n");
	if((flags & O_ACCMODE) ==  O_WRONLY)
		GDEBUG(10, "O_WRONLY\n");
	if((flags & O_ACCMODE) ==  O_RDWR)
		GDEBUG(10, "O_RDWR\n");
	if(flags &  O_ASYNC)
		GDEBUG(10, "O_ASYNC\n");
	if(flags &  O_DIRECT)
		GDEBUG(10, "O_DIRECT\n");
	if(flags &  O_DIRECTORY)
		GDEBUG(10, "O_DIRECTORY\n");
	if(flags &  O_EXCL)
		GDEBUG(10, "O_EXCL\n");
	if(flags &  O_LARGEFILE)
		GDEBUG(10, "O_LARGEFILE\n");
	if(flags &  O_DIRECT)
		GDEBUG(10, "O_NOATIME\n");
	if(flags &  O_DIRECTORY)
		GDEBUG(10, "O_NOCTTY\n");
	if(flags &  O_EXCL)
		GDEBUG(10, "O_NOCTTY\n");
	if(flags &  O_NOFOLLOW)
		GDEBUG(10, "O_NOFOLLOW\n");
	if(flags &  (O_NONBLOCK | O_NDELAY))
		GDEBUG(10, "O_NONBLOCK o O_NDELAY\n");
	if(flags &  O_SYNC)
		GDEBUG(10, "SYNC\n");
#endif

	ft->context = fc;
	ft->pos = 0;
	ft->ffi.flags = flags & ~(O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC);
	ft->ffi.writepage = 0; //XXX do we need writepage != 0?
	ft->dirinfo = NULL;
	ft->dirpos = NULL;
	ft->path = strdup(unwrap(fc, path));
	exists_err = fc->fuse->fops.getattr(ft->path, &buf);
	ft->size = buf.st_size;

	if ((flags & O_ACCMODE) != O_RDONLY && fc->fuse->flags & MS_RDONLY) {
		errno = EROFS;
		goto error;
	}

	if ( (flags & (O_DIRECTORY)) && (!S_ISDIR(buf.st_mode))) {
		errno=ENOTDIR;
		goto error;
	}

	if ((flags & O_ACCMODE) != O_RDONLY && (S_ISDIR(buf.st_mode))) {
		errno=EISDIR;
		goto error;
	}

	/* HUMAN */
	if ((fc->fuse->flags & FUSE_HUMAN) && (exists_err == 0))
	{
		int mask=MAY_READ | MAY_WRITE;
		if ((flags & O_ACCMODE) == (O_RDONLY)) mask=MAY_READ;
		if ((flags & O_ACCMODE) == (O_WRONLY)) mask=MAY_WRITE;
		rv=check_permission (buf.st_mode,buf.st_uid,buf.st_gid,mask);
		if (rv<0) {
			errno = -rv;
			goto error;
		}
	}

	if(exists_err == 0 && (flags & O_TRUNC) && (flags & O_ACCMODE)!= O_RDONLY) {
		rv=fc->fuse->fops.truncate(ft->path, 0);
		if (rv < 0) {
			errno = -rv;
			goto error;
		}
	}
	if (flags == (O_CREAT|O_WRONLY|O_TRUNC) && fc->fuse->fops.create != NULL) {
		rv = fc->fuse->fops.create(ft->path, mode, &ft->ffi);
	} else
	{
		if (flags & O_CREAT) { 
			if (exists_err == 0) {
				if (flags & O_EXCL) {
					errno= EEXIST;
					goto error;
				} 
			} else {
				GDEBUG(10, "umfuse open MKNOD call\n");
				rv = fc->fuse->fops.mknod(ft->path, S_IFREG | mode, (dev_t) 0);
				if (rv < 0) {
					errno = -rv;
					goto error;
				}
			}
		}
		GDEBUG(10,"open_fuse_filesystem CALL!\n");
		if ((flags & O_DIRECTORY) && fc->fuse->fops.readdir)
			rv = fc->fuse->fops.opendir(ft->path, &ft->ffi);
		else 
			rv = fc->fuse->fops.open(ft->path, &ft->ffi);
	}

	if (rv < 0)
	{
		if (fc->fuse->flags & FUSE_DEBUG) {
			GERROR("OPEN[%s:%d] ERROR => path:%s flags:0x%x Err:%d\n",
					fc->fuse->path, fd, path, flags, -rv);	
		}		
		errno = -rv;
		goto error;
	} else {
		if (fc->fuse->flags & FUSE_DEBUG) {
			GMESSAGE("OPEN[%s:%d] => path:%s flags:0x%x\n",
					fc->fuse->path, fd, path, flags);
		}

		/* TODO update fuse->inuse++ */
		fc->fuse->inuse++;
		return fd;
	}
error:
	free(ft->path);
	delfiletab(fd);
	return -1;
}

static long umfuse_close(int fd)
{
	int rv;
	struct fileinfo *ft=getfiletab(fd);

	struct fuse_context *fc=ft->context;
	fc->pid=um_mod_getpid();

	if (fc->fuse->flags & FUSE_DEBUG) {
		GMESSAGE("CLOSE[%s:%d] %s %p\n",fc->fuse->path,fd,ft->path,fc);
	}

	if (!(ft->ffi.flags & O_DIRECTORY)) {
		rv=fc->fuse->fops.flush(ft->path, &ft->ffi);

		if (fc->fuse->flags & FUSE_DEBUG) {
			GMESSAGE("FLUSH[%s:%d] => path:%s\n",
					fc->fuse->path, fd, ft->path);
		}
	}

	GDEBUG(10,"->CLOSE %s %d\n",ft->path, ft->count);
	fc->fuse->inuse--;
	if ((ft->ffi.flags & O_DIRECTORY) && fc->fuse->fops.readdir)
		rv = fc->fuse->fops.releasedir(ft->path, &ft->ffi);
	else
		rv=fc->fuse->fops.release(ft->path, &ft->ffi);
	if (fc->fuse->flags & FUSE_DEBUG) {
		GMESSAGE("RELEASE[%s:%d] => path:%s flags:0x%x\n",
				fc->fuse->path, fd, ft->path, fc->fuse->flags);
	}
	umcleandirinfo(ft->dirinfo);
	free(ft->path);
	delfiletab(fd);
	if (rv<0) {
		errno= -rv;
		return -1;
	} else {
		return rv;
	}
}

static long umfuse_read(int fd, void *buf, size_t count)
{
	int rv;
	struct fileinfo *ft=getfiletab(fd);
	if ( (ft->ffi.flags & O_ACCMODE) == O_WRONLY) {
		errno=EBADF;
		return -1;
	} else if (ft->pos == ft->size)
		return 0;
	else {
		struct fuse_context *fc=ft->context;
		fc->pid=um_mod_getpid();
		rv = fc->fuse->fops.read(
				ft->path,
				buf,
				count,
				ft->pos,
				&ft->ffi);
		if (fc->fuse->flags & FUSE_DEBUG) {
			GMESSAGE("READ[%s:%d] => path:%s count:%u rv:%d\n",
					fc->fuse->path,fd, ft->path, count, rv);
		}
		if (rv<0) {
			errno= -rv;
			return -1;
		} else {
			ft->pos += rv;
			return rv;
		}
	}
}

static long umfuse_lseek(int fd, int offset, int whence);
static long umfuse_write(int fd, void *buf, size_t count)
{
	//TODO write page?!
	int rv=0;
	struct fileinfo *ft=getfiletab(fd);

	if ( (ft->ffi.flags & O_ACCMODE) == O_RDONLY) {
		errno = EBADF;
		/*
			 if (fc->fuse->flags & FUSE_DEBUG) {
			 fprintf(stderr, "WRITE[%d] => Error File Not Found\n");	
			 fflush(stderr);
			 }*/
		return -1;
	} else {
		struct fuse_context *fc=ft->context;
		fc->pid=um_mod_getpid();
		if (ft->ffi.flags & O_APPEND)
			rv=umfuse_lseek(fd,0,SEEK_END);
		if (rv!=-1) {
			rv = fc->fuse->fops.write(ft->path,
					buf, count, ft->pos, &ft->ffi);
		}
		if (fc->fuse->flags & FUSE_DEBUG) {
			GMESSAGE("WRITE[%s:%d] => path:%s count:0x%x rv:%d\n",
					fc->fuse->path, fd, ft->path, count, rv);
		}

		GDEBUG(10,"WRITE rv:%d\n",rv); 

		//		if (fc->fuse->flags & FUSE_DEBUG)
		//      		fprintf(stderr, "WRITE[%lu] => path:%s count:0x%x\n",
		//				ft->ffi.fh, ft->path, count);
		//printf("WRITE%s[%lu] %u bytes to %llu\n",
		// (arg->write_flags & 1) ? "PAGE" : "",
		// (unsigned long) arg->fh, arg->size, arg->offset);
		if (rv<0) {
			errno= -rv;
			return -1;
		} else {
			ft->pos += rv;
			return rv;
		}
	}
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

/*heuristics for file system which does not set st_ino */
static inline unsigned long hashnodeid (const char *s) {
	unsigned long sum=0;
	while (*s) {
		sum=sum ^ ((sum << 5) + (sum >> 2) + *s);
		s++;
	}
	return sum;
}

static inline int common_stat(char *path,  struct stat *buf)
{
	int rv;
	struct fuse_context *fc=um_mod_get_private_data();
	//printk("FUSESTAT%s\n",path);
	assert(fc != NULL);
	fc->pid=um_mod_getpid();
	memset(buf, 0, sizeof(struct stat));
	rv = fc->fuse->fops.getattr(unwrap(fc,path),buf);
	if (fc->fuse->flags & FUSE_DEBUG) {
		GMESSAGE("%s: stat->GETATTR => path:%s status: %s Err:%d\n",
				fc->fuse->path, path, rv ? "Error" : "Success", (rv < 0) ? -rv : 0);
	}
	/*heuristics for file system which does not set st_ino */
	if (buf->st_ino == 0)
		buf->st_ino=(ino_t) hashnodeid(path);
	/*heuristics for file system which does not set st_dev */
	if (buf->st_dev == 0)
		buf->st_dev=(dev_t) fc;
	if (rv<0) {
		errno= -rv;
		return -1;
	} else
		return rv;
}

static long umfuse_lstat64(char *path, struct stat64 *buf64)
{
	int rv;
	struct stat buf;
	if ((rv=common_stat(path,&buf))>=0)
		stat2stat64(buf64,&buf);
	return rv;
}

static long umfuse_readlink(char *path, char *buf, size_t bufsiz)
{
	struct fuse_context *fc=um_mod_get_private_data();
	int rv;
	assert(fc != NULL);
	fc->pid=um_mod_getpid();
	rv = fc->fuse->fops.readlink(
			unwrap(fc, path), buf, bufsiz);
	if (rv == 0)
		rv=strnlen(buf,bufsiz);
	GDEBUG(10,"umfuse_readlink %s %s %d\n",unwrap(fc,path),buf,rv);
	if (rv < 0) {
		errno = -rv;
		return -1;
	} else
		return rv;
}

static long umfuse_access(char *path, int mode)
{

	struct fuse_context *fc=um_mod_get_private_data();
	int rv=0;
	struct stat buf;
	assert(fc!=NULL);
	fc->pid=um_mod_getpid();
	if (fc->fuse->flags & FUSE_DEBUG) {
		GMESSAGE("ACCESS [%s] => path:%s mode:%s%s%s%s\n", fc->fuse->path, path,
				(mode & R_OK) ? "R_OK": "",
				(mode & W_OK) ? "W_OK": "",
				(mode & X_OK) ? "X_OK": "",
				(mode & F_OK) ? "F_OK": "");
	}

	/* HUMAN */
	if (fc->fuse->flags & FUSE_HUMAN) {
		int mask=0;
		switch (mode) {
			case R_OK: mask=MAY_READ;break;
			case W_OK: mask=MAY_WRITE;break;
			case X_OK: mask=MAY_EXEC;break;
		}

		if (mask) rv=path_check_permission(unwrap(fc,path),mask);
		if (rv<0) {
			errno=-rv;
			return -1;
		}
	}

	/* "default permission" management */
	if (fc->fuse->fops.access != NULL)
		rv= fc->fuse->fops.access(unwrap(fc, path), mode);
	else
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

static long umfuse_mknod(const char *path, mode_t mode, dev_t dev)
{
	struct fuse_context *fc = um_mod_get_private_data();
	int rv;
	assert(fc != NULL);
	if (fc->fuse->flags & FUSE_DEBUG)
		fprintf(stderr, "MKNOD [%s] => path:%s %d %d\n",fc->fuse->path,path,
				major(dev),minor(dev));
	rv = fc->fuse->fops.mknod(
			unwrap(fc, path), mode, dev);
	if (rv < 0) {
		errno = -rv;
		return -1;
	}
	return rv;
}

static long umfuse_mkdir(char *path, int mode)
{
	struct fuse_context *fc=um_mod_get_private_data();
	int rv=0;
	assert(fc != NULL);
	if (fc->fuse->flags & MS_RDONLY) {
		errno = EROFS;
		return -1;
	}

	/* HUMAN */
	if (fc->fuse->flags & FUSE_HUMAN) 
	{
		rv=check_parent(path,MAY_WRITE);
		if (rv<0) {
			PRINTDEBUG (10,"Not MAY_WRITE on %s\n",get_parent_path(path));
			errno=-rv;
			return -1;
		}
	}

	fc->pid=um_mod_getpid();
	if (fc->fuse->flags & FUSE_DEBUG) {
		GMESSAGE("MKDIR [%s] => path:%s\n",fc->fuse->path,path);
	}
	rv = fc->fuse->fops.mkdir(
			unwrap(fc, path), mode);
	if (rv < 0) {
		errno = -rv;
		return -1;
	} else
		return rv;
}

static long umfuse_rmdir(char *path)
{
	struct fuse_context *fc= um_mod_get_private_data();
	int rv;
	assert(fc!=NULL);
	if (fc->fuse->flags & MS_RDONLY) {
		errno = EROFS;
		return -1;
	}

	/* HUMAN */
	if (fc->fuse->flags & FUSE_HUMAN) 
	{
		rv=check_parent(path,MAY_WRITE);
		if (rv>=0) rv=check_owner(unwrap(fc,path));
		if (rv<0) {
			errno=-rv;
			return -1;
		}
	}

	fc->pid=um_mod_getpid();
	if (fc->fuse->flags & FUSE_DEBUG) {
		GMESSAGE("RMDIR [%s] => path:%s\n",fc->fuse->path,path);
	}
	rv= fc->fuse->fops.rmdir(
			unwrap(fc, path));
	if (rv < 0) {
		errno = -rv;
		return -1;
	} else
		return rv;
}

static long umfuse_chmod(char *path, int mode)
{
	struct fuse_context *fc = um_mod_get_private_data();
	int rv;
	assert(fc != NULL);
	if (fc->fuse->flags & MS_RDONLY) {
		errno = EROFS;
		return -1;
	}

	/* HUMAN */
	if (fc->fuse->flags & FUSE_HUMAN) {
		rv=check_owner(unwrap(fc,path));
		if (rv<0) {
			errno=-rv;
			return -1;
		}
	}

	fc->pid=um_mod_getpid();
	if (fc->fuse->flags & FUSE_DEBUG) {
		GMESSAGE("CHMOD [%s] => path:%s\n",fc->fuse->path,path);
	}
	rv= fc->fuse->fops.chmod(
			unwrap(fc ,path), mode);
	if (rv < 0) {
		errno = -rv;
		return -1;
	}
	return rv;
}

static long umfuse_lchown(char *path, uid_t owner, gid_t group)
{
	struct fuse_context *fc = um_mod_get_private_data();
	int rv=0;
	assert(fc != NULL);
	if (fc->fuse->flags & MS_RDONLY) {
		errno = EROFS;
		return -1;
	}

	/* HUMAN */
	if (fc->fuse->flags & FUSE_HUMAN) {
		if ( (fc->uid != 0) && (fc->uid != owner)) rv=-EPERM;
		if (rv>=0) rv=check_owner(unwrap(fc,path));
		if (rv>=0) rv=check_group(group);
		if (rv<0) {
			errno=-rv;
			return -1;
		}
	}

	fc->pid=um_mod_getpid();
	rv = fc->fuse->fops.chown(
			unwrap(fc, path), owner, group);
	if (rv < 0) {
		errno = -rv;
		return -1;
	} else
		return rv;
}

static long umfuse_unlink(char *path)
{
	struct fuse_context *fc=um_mod_get_private_data();
	int rv=0;
	assert(fc != NULL);
	if (fc->fuse->flags & MS_RDONLY) {
		errno = EROFS;
		return -1;
	}

	/* HUMAN */
	if (fc->fuse->flags & FUSE_HUMAN) {
		rv=check_owner(unwrap(fc,path));
		if (rv<0) {
			errno=-rv;
			return -1;
		}

		rv=check_parent(path,MAY_WRITE);
		if (rv<0) {
			PRINTDEBUG (10,"NO MAY_WRITE on %s\n",get_parent_path(path));
			errno=-rv;
			return -1;
		}
	}

	fc->pid=um_mod_getpid();
	if (fc->fuse->flags & FUSE_DEBUG)
		GMESSAGE("UNLINK [%s] => path:%s\n",fc->fuse->path,path);
	rv = fc->fuse->fops.unlink(
			unwrap(fc, path));
	if (rv < 0) {
		errno = -rv;
		return -1;
	} else
		return rv;
}

static long umfuse_link(char *oldpath, char *newpath)
{
	struct fuse_context *fc= um_mod_get_private_data();
	int rv=0;
	assert(fc != NULL);
	if (fc->fuse->flags & MS_RDONLY) {
		errno = EROFS;
		return -1;
	}

	/* HUMAN */
	if (fc->fuse->flags & FUSE_HUMAN) {
		rv=check_parent(newpath,MAY_WRITE);
		if (rv<0) {
			PRINTDEBUG (10,"not MAY_WRITE on %s\n",get_parent_path(newpath));
			errno=-rv;
			return -1;
		}
	}

	fc->pid=um_mod_getpid();

	if (fc->fuse->flags & FUSE_DEBUG)
		GMESSAGE("LINK [%s] => oldpath:%s newpath:%s\n",fc->fuse->path,oldpath, newpath);
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
static long umfuse_fsync(int fd)
{
	struct fileinfo *ft=getfiletab(fd);
	struct fuse_context *fc=ft->context;
	if (fc->fuse->flags & FUSE_DEBUG) {
		GMESSAGE("kernel FSYNC. It has a different semantics in fuse\n");
	}

	/*	//	rv = fc->fuse->fops.read
	//struct fuse_context *fc=um_mod_get_private_data();
	int rv;
	assert(fc != NULL);
	if (fc->fuse->flags & FUSE_DEBUG)
	fprintf(stderr, "FSYNC => path:%s:\n",ft->path);
	rv = fc->fuse->fops.fsync(fd);
	if (rv < 0) {
	errno = -rv;
	return -1;
	} else
	return rv;
	 */
	return 0;
}

static long umfuse_rename(char *oldpath, char *newpath)
{
	struct fuse_context *fc=um_mod_get_private_data();
	int rv=0;
	assert(fc != NULL);
	fc->pid=um_mod_getpid();
	if (fc->fuse->flags & FUSE_DEBUG) {
		GMESSAGE("RENAME [%s] => %s ->%s\n",fc->fuse->path,oldpath, newpath);
	}

	/* HUMAN */
	if (fc->fuse->flags & FUSE_HUMAN) {
		rv=check_parent(newpath,MAY_WRITE);
		if (rv<0) {
			PRINTDEBUG ("no MAY_WRITE on %s\n",get_parent_path(newpath));
			errno=-rv;
			return -1;
		}
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

static long umfuse_symlink(char *oldpath, char *newpath)
{

	struct fuse_context *fc=um_mod_get_private_data();
	int rv=0;

	assert(fc != NULL);
	if (fc->fuse->flags & MS_RDONLY) {
		errno = EROFS;
		return -1;
	}

	/* HUMAN */
	if (fc->fuse->flags & FUSE_HUMAN) {
		rv=check_parent(newpath,MAY_WRITE);
		if (rv<0) {
			PRINTDEBUG ("no MAY_WRITE on %s\n",get_parent_path(newpath));
			errno=-rv;
			return -1;
		}
	}

	fc->pid=um_mod_getpid();
	if (fc->fuse->flags & FUSE_DEBUG) {
		GMESSAGE("SYMLINK [%s] => %s -> %s\n",
				fc->fuse->path,newpath, oldpath);
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

static long umfuse_truncate64(char *path, loff_t length)
{

	struct fuse_context *fc=um_mod_get_private_data();
	int rv;

	/* FUSE defines length as off_t, so we will not truncate a file
	 * if the desired length can't be contained in an off_t.
	 * Please ask FUSE developers to define length as loff_t. */
	if (length != (loff_t)((off_t)length))
	{
		errno = EINVAL;
		return -1;
	}

	assert(fc != NULL);
	if (fc->fuse->flags & MS_RDONLY) {
		errno = EROFS;
		return -1;
	}

	/* HUMAN */
	if (fc->fuse->flags & FUSE_HUMAN) {
		rv=path_check_permission (unwrap(fc,path),MAY_WRITE);
		if (rv<0) {
			PRINTDEBUG ("no MAY_WRITE on %s\n",get_parent_path(path));
			errno=-rv;
			return -1;
		}
	}

	fc->pid=um_mod_getpid();

	if (fc->fuse->flags & FUSE_DEBUG) {
		GMESSAGE("TRUNCATE [%s] debug => path %s\n",fc->fuse->path,path);		
	}
	rv = fc->fuse->fops.truncate(
			unwrap(fc, path),(off_t)length);
	if (rv < 0) {
		errno = -rv;
		return -1;
	} else
		return rv;	
}

static long umfuse_ftruncate64(int fd, off_t length)
{
	struct fileinfo *ft=getfiletab(fd);
	/* FUSE defines length as off_t, so we will not truncate a file
	 * if the desired length can't be contained in an off_t.
	 * Please ask FUSE developers to define length as loff_t. */
	if (length != (loff_t)((off_t)length))
	{
		errno = EINVAL;
		return -1;
	}

	struct fuse_context *fc=ft->context;
	assert(fc != NULL);
	if (fc->fuse->flags & MS_RDONLY) {
		errno = EROFS;
		return -1;
	}
	if (fc->fuse->fops.ftruncate == NULL)
		return umfuse_truncate64(ft->path,length);
	else {
		int rv;
		fc->pid=um_mod_getpid();
		rv = fc->fuse->fops.ftruncate(
				ft->path,(off_t)length,&ft->ffi);
		if (fc->fuse->flags & FUSE_DEBUG) {
			GMESSAGE("FTRUNCATE [%s] debug => path %s\n",fc->fuse->path,ft->path);		
		}
		if (rv < 0) {
			errno = -rv;
			return -1;
		} else
			return rv;	
	}
}

/** Change the access and/or modification times of a file */
static long umfuse_utime(char *path, struct utimbuf *buf)
{
	struct fuse_context *fc = um_mod_get_private_data();
	int rv;
	assert(fc != NULL);
	if (fc->fuse->flags & MS_RDONLY) {
		errno = EROFS;
		return -1;
	}

	/* HUMAN */
	if (fc->fuse->flags & FUSE_HUMAN) {
		rv=path_check_permission(unwrap(fc,path),MAY_WRITE);
		if (rv<0) {
			PRINTDEBUG ("utime:no MAY_WRITE on %s\n",unwrap(fc,path));
			errno=-rv;
			return -1;
		}
	}

	fc->pid=um_mod_getpid();
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

static long umfuse_utimes(char *path, struct timeval tv[2])
{
	//approximate solution. drop microseconds
	if (tv == NULL) {
		return umfuse_utime(path, NULL);	
	} else {
		struct utimbuf buf;
		buf.actime=tv[0].tv_sec;
		buf.modtime=tv[1].tv_sec;
		return umfuse_utime(path, &buf);
	}
}

static ssize_t umfuse_pread64(int fd, void *buf, size_t count, long long offset)
{
	int rv;
	struct fileinfo *ft=getfiletab(fd);
	if ( (ft->ffi.flags & O_ACCMODE) == O_WRONLY) {
		errno=EBADF;
		return -1;
	} else if (offset >= ft->size)
		return 0;
	else {
		struct fuse_context *fc=ft->context;
		fc->pid=um_mod_getpid();
		rv = fc->fuse->fops.read(
				ft->path,
				buf,
				count,
				offset,
				&ft->ffi);
		if (fc->fuse->flags & FUSE_DEBUG) {
			GMESSAGE("PREAD[%s:%d] => path:%s count:%u pos:%lld rv:%d\n",
					fc->fuse->path,fd, ft->path, count, offset, rv);
		}
		if (rv<0) {
			errno= -rv;
			return -1;
		} else {
			return rv;
		}
	}
}

static ssize_t umfuse_pwrite64(int fd, const void *buf, size_t count, long long offset)
{
	int rv;
	struct fileinfo *ft=getfiletab(fd);

	if ( (ft->ffi.flags & O_ACCMODE) == O_RDONLY) {
		errno = EBADF;
		return -1;
	} else {
		struct fuse_context *fc=ft->context;
		fc->pid=um_mod_getpid();
		rv = fc->fuse->fops.write(ft->path,
				buf, count, offset, &ft->ffi);
		if (fc->fuse->flags & FUSE_DEBUG) {
			GMESSAGE("PWRITE[%s:%d] => path:%s count:%u pos:%lld rv:%d\n",
					fc->fuse->path, fd, ft->path, count, offset, rv);
		}
		if (rv<0) {
			errno= -rv;
			return -1;
		} else {
			return rv;
		}
	}
}

/* TODO management of fcntl */
static long umfuse_fcntl32(int fd, int cmd, void *arg)
{
	//printf("umfuse_fcntl32\n");
	errno=0;
	return 0;
}

static long umfuse_fcntl64(int fd, int cmd, void *arg)
{
	//printf("umfuse_fcntl64\n");
	errno=0;
	return 0;
}

static long umfuse_lseek(int fd, int offset, int whence)
{
	struct fileinfo *ft=getfiletab(fd);
	switch (whence) {
		case SEEK_SET:
			ft->pos=offset;
			break;
		case SEEK_CUR:
			ft->pos += offset;
			break;
		case SEEK_END:
			{
				struct stat buf;
				int rv;
				struct fuse_context *fc=ft->context;
				assert(fc != NULL);

				fc->pid=um_mod_getpid();
				rv = fc->fuse->fops.getattr(ft->path,&buf);
				if (rv>=0) {
					ft->pos = buf.st_size + offset;
				} else {
					errno=EBADF;
					return -1;
				}
			}
			break;
	}

	return ft->pos;
}

static long umfuse__llseek(unsigned int fd, unsigned long offset_high,  unsigned  long offset_low, loff_t *result, unsigned int whence)
{
	//GDEBUG(10,"umfuse__llseek [%s] %d %d %d %d\n",
	//		fc->fuse->path,fd,offset_high,offset_low,whence);
	if (result == NULL) {
		errno = EFAULT;
		return -1;
	} else if (offset_high != 0) {
		errno = EINVAL;
		return -1;
	} else {
		long rv;
		rv=umfuse_lseek(fd,offset_low,whence);
		if (rv >= 0) {
			*result=rv;
			return 0;
		} else {
			errno = -rv;
			return -1;
		}
	}
}

static long umfuse_statfs64 (const char *file, struct statfs64 *buf)
{
	long rv;
	struct fuse_context *fc = um_mod_get_private_data();
	struct statvfs svfs;
	memset (&svfs, 0, sizeof(struct statvfs));
	fc->pid=um_mod_getpid();
	if (fc->fuse->fops.statfs) {
		rv=fc->fuse->fops.statfs(file, &svfs);
		if (rv >= 0) {
			buf->f_type = FUSE_SUPER_MAGIC;
			buf->f_bsize = svfs.f_bsize;
			buf->f_blocks = svfs.f_blocks;
			buf->f_bfree = svfs.f_bfree;
			buf->f_bavail = svfs.f_bavail;
			buf->f_files = svfs.f_files;
			buf->f_ffree = svfs.f_ffree;
			buf->f_namelen =svfs.f_namemax;
			buf->f_frsize =svfs.f_frsize;
			/* fsid is left zero */
			return rv;
		} else {
			errno = -rv;
			return -1;
		} 
	}
	else {
		errno = ENOSYS;
		return -1;
	}
}

static void umfuse_destructor(int type,struct ht_elem *mp)
{
	switch (type) {
		case CHECKPATH:
			um_mod_set_hte(mp);
			umfuse_umount_internal(um_mod_get_private_data(), MNT_FORCE);
	}
}

	static void
	__attribute__ ((constructor))
init (void)
{
	GMESSAGE("umfuse init");
	s.name="umfuse";
	s.description="virtual file systems (user level FUSE)";
	s.destructor=umfuse_destructor;
	s.syscall=(sysfun *)calloc(scmap_scmapsize,sizeof(sysfun));
	s.socket=(sysfun *)calloc(scmap_sockmapsize,sizeof(sysfun));
	SERVICESYSCALL(s, mount, umfuse_mount);
	SERVICESYSCALL(s, umount2, umfuse_umount2);
	SERVICESYSCALL(s, open, umfuse_open);
	SERVICESYSCALL(s, read, umfuse_read);
	SERVICESYSCALL(s, write, umfuse_write);
	SERVICESYSCALL(s, close, umfuse_close);
#if __WORDSIZE == 32 //TODO: verify that ppc64 doesn't have these
	SERVICESYSCALL(s, lstat64, umfuse_lstat64);
	SERVICESYSCALL(s, statfs64, umfuse_statfs64);
#else 
	SERVICESYSCALL(s, lstat, umfuse_lstat64);
	SERVICESYSCALL(s, statfs, umfuse_statfs64);
#endif
	SERVICESYSCALL(s, readlink, umfuse_readlink);
	SERVICESYSCALL(s, getdents64, umfuse_getdents64);
	SERVICESYSCALL(s, access, umfuse_access);
	SERVICESYSCALL(s, fcntl, umfuse_fcntl32);
#if __WORDSIZE == 32 //TODO: verify that ppc64 doesn't have these
	SERVICESYSCALL(s, fcntl64, umfuse_fcntl64);
	SERVICESYSCALL(s, _llseek, umfuse__llseek);
#endif
	SERVICESYSCALL(s, lseek, umfuse_lseek);
	SERVICESYSCALL(s, mknod, umfuse_mknod);
	SERVICESYSCALL(s, mkdir, umfuse_mkdir);
	SERVICESYSCALL(s, rmdir, umfuse_rmdir);
	SERVICESYSCALL(s, lchown, umfuse_lchown);
	SERVICESYSCALL(s, chmod, umfuse_chmod);
	SERVICESYSCALL(s, unlink, umfuse_unlink);
	SERVICESYSCALL(s, fsync, umfuse_fsync); //not the syscall meaning
	//SERVICESYSCALL(s, fdatasync, fdatasync);
	SERVICESYSCALL(s, link, umfuse_link);
	SERVICESYSCALL(s, symlink, umfuse_symlink);
	SERVICESYSCALL(s, rename, umfuse_rename);
#if __WORDSIZE == 32
	SERVICESYSCALL(s, truncate64, umfuse_truncate64);
	SERVICESYSCALL(s, ftruncate64, umfuse_ftruncate64);
#else
	SERVICESYSCALL(s, truncate, umfuse_truncate64);
	SERVICESYSCALL(s, ftruncate, umfuse_ftruncate64);
#endif
	SERVICESYSCALL(s, pread64, umfuse_pread64);
	SERVICESYSCALL(s, pwrite64, umfuse_pwrite64);
	SERVICESYSCALL(s, utimes, umfuse_utimes);
}

	static void
	__attribute__ ((destructor))
fini (void)
{
	free(s.syscall);
	free(s.socket);
	GMESSAGE("umfuse fini");
}

