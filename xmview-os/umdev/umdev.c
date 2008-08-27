/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   UMDEV: Virtual Device in Userspace
 *    Copyright (C) 2006  Renzo Davoli <renzo@cs.unibo.it>
 *    from an idea of Andrea Gasparini
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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include <utime.h>
#include <limits.h>
#include <sys/time.h>
#include <sys/mount.h>
#include <dlfcn.h>
#include <pthread.h>
#include <linux/types.h>
#include <linux/dirent.h>
#include <linux/unistd.h>
#include <stdarg.h>
#include <stdint.h>
#include <sys/types.h>
#include <config.h>
#include "module.h"
#include "libummod.h"
#include "umdev.h"

#define UMDEV_SERVICE_CODE 0x04
//static pthread_mutex_t devicetab_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Enable umdev own debug output */

//#define __UMDEV_DEBUG__ 1   /* it is better to enable it from makefile */
#ifndef __UMDEV_DEBUG_LEVEL__
#define __UMDEV_DEBUG_LEVEL__ 0
#endif

#ifdef __UMDEV_DEBUG__
#define PRINTDEBUG(level,args...) printdebug(level, __FILE__, __LINE__, __func__, args)
#else
#define PRINTDEBUG(level,args...)
#endif

static struct service s;

struct umdev {
	char *path;
	void *dlhandle;
	struct timestamp tst;
	dev_t device;
	mode_t mode;
	uid_t uid;
	gid_t gid;
	int nsubdev;
	struct umdev_operations *devops;	
	int inuse;
	unsigned long flags;
	void *private_data;
};

struct fileinfo {
	char type;
	dev_t device;
	uint64_t fh;
	int count;        /* number of processes that opened the file */
	loff_t pos;        /* file offset */
	struct umdev *umdev;
};

#define MNTTABSTEP 4 /* must be a power of two */
#define MNTTABSTEP_1 (MNTTABSTEP-1)
#define FILETABSTEP 4 /* must be a power of two */
#define FILETABSTEP_1 (FILETABSTEP-1)

static struct fileinfo **filetab=NULL;
static int filetabmax=0;

static struct umdev **devicetab=NULL;
static int devicetabmax=0;


#ifdef __UMDEV_DEBUG__
static void printdebug(int level, const char *file, const int line, const char *func, const char *fmt, ...) {
	va_list ap;
    
	if (level >= __UMDEV_DEBUG_LEVEL__) {
		va_start(ap, fmt);
#ifdef _PTHREAD_H
		fprint2( "[%d:%lu] dev %s:%d %s(): ", getpid(), pthread_self(), file, line, func);
#else
		fprint2( "[%d] dev %s:%d %s(): ", getpid(), file, line, func);
#endif
		vfprint2(fmt, ap);
		fprint2( "\n");
		va_end(ap);
	}
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

static int search_plusnum(const char *path, const char *base, int nsubdev)
{
	int len=strlen(base);
	if (strncmp(path,base,len) == 0) {
		const char *s=path+len;
		if (nsubdev == 0)
			return(*s == 0);
		else {
			for (s=path+len; *s!=0 && *s>='0' && *s <='9'; s++)
				;
			if (*s==0) {
				int sub=atoi(path+len);
				if (sub <= nsubdev)
					return 1;
				else return 0;
			} else
				return 0;
		}
	}
	else
		return 0;
}

/* search a device, returns the context i.e. the index of info for mounted file
 * -1 otherwise */
static struct umdev *searchdevice(char *path)
{
	register int i;
	struct umdev *result=NULL;
	struct stat64 buf;
	epoch_t maxepoch=0;
	int maxi=-1;

	PRINTDEBUG(0,"SearchContext:%s\n",path);
	cutdots(path);
	for (i=0;i<devicetabmax;i++)
	{
		epoch_t e;
		if ((devicetab[i] != NULL)) {
			epoch_t prevepoch=um_setepoch(devicetab[i]->tst.epoch);
			if (
				//	(strcmp(path,devicetab[i]->path) == 0) &&
				  search_plusnum(path,devicetab[i]->path,devicetab[i]->nsubdev) &&
					((e=tst_matchingepoch(&(devicetab[i]->tst))) > maxepoch)) {
				maxi=i;
				maxepoch=e;
			}
			um_setepoch(prevepoch);
		}
	}
  /* Major/Minor Number select */	
	if (maxi < 0)
		for (i=0;i<devicetabmax && result==NULL;i++)
		{
			epoch_t e;
			if ((devicetab[i] != NULL)) {
				/* set epoch */
				epoch_t prevepoch=um_setepoch(devicetab[i]->tst.epoch);
				if (((e=tst_matchingepoch(&(devicetab[i]->tst))) > maxepoch) &&  /* Epoch compatible  AND */
						/* RD 08.2008, why can't we use um_mod_getpathstat? try it */
						(stat64(path,&buf) == 0) &&  /* stat okay AND */
						((((devicetab[i]->mode & S_IFMT) == 0) ||  /* the same kind of special file (or 0, any kind)  AND */
							((buf.st_mode & S_IFMT) ==  (devicetab[i]->mode & S_IFMT))) &&
						 (major(devicetab[i]->device) == major(buf.st_rdev)) && /* the same Major num AND */
						 ((minor(devicetab[i]->device) == -1) ||  /* the same Minor (or any) */
							(((minor(devicetab[i]->device) <= minor(buf.st_rdev)) &&
								(minor(devicetab[i]->device)+devicetab[i]->nsubdev >= minor(buf.st_rdev))))))) {
					/* after all the tests: it's it! */
					maxi=i;
					maxepoch=e;
				}
				um_setepoch(prevepoch);
				/* restore epoch */
			}
		}
	if (maxi >= 0)
		result=devicetab[maxi];
	return result;
}

static inline int mode2char(mode_t mode)
{
	if (S_ISCHR(mode))
		return 'c';
	else if (S_ISBLK(mode))
		return 'b';
	else 
		return ' ';
}

static int set_dev(dev_t *dev, struct umdev *umdev,char *path)
{
	register int i;
	mode_t mode;
	
	struct stat64 buf;
	
	*dev=0;
	if (stat64(path,&buf) >= 0 && (S_ISCHR(buf.st_mode) || S_ISBLK(buf.st_mode))) {
		*dev=buf.st_rdev;
	} else {
		if (strlen(path) > strlen(umdev->path)) 
			*dev=makedev(major(umdev->device),minor(umdev->device)+atoi(path+strlen(umdev->path)));
		else
			*dev= umdev->device;
	}
	mode= umdev->mode;
	//fprint2("SET_DEV %s %x %d %d\n",path,mode,major(*dev),minor(*dev));
	return mode2char(mode);
}

/*insert a new context in the device table*/
static struct umdev *adddevicetab(struct umdev *new)
{
	register int i;
	//pthread_mutex_lock( &devicetab_mutex );
	for (i=0;i<devicetabmax && devicetab[i] != NULL;i++)
		;
	if (i>=devicetabmax) {
		register int j;
		register int devicetabnewmax=(i + MNTTABSTEP) & ~MNTTABSTEP_1;
		devicetab=(struct umdev **)realloc(devicetab,devicetabnewmax*sizeof(struct umdev *));
		assert(devicetab);
		for (j=i;j<devicetabnewmax;j++)
			devicetab[j]=NULL;
		devicetabmax=devicetabnewmax;
	}
	devicetab[i]=new;
	//pthread_mutex_unlock( &devicetab_mutex );
	return devicetab[i];
}

/* execute a specific function (arg) for each devicetab element */
static void foralldevicetabdo(void (*fun)(struct umdev *fc))
{
	register int i;
	for (i=0;i<devicetabmax;i++)
		if (devicetab[i] != NULL)
		     fun(devicetab[i]);
}

/*
 * delete the i-th element of the tab.
 * the table cannot be compacted as the index is used as id
 */
static void deldevicetab(struct umdev *fc)
{
	register int i;
	//pthread_mutex_lock( &devicetab_mutex );
	for (i=0;i<devicetabmax && fc != devicetab[i];i++)
		;
	if (i<devicetabmax)
		 devicetab[i]=NULL;
	else
		fprint2("delmnt inexistent entry\n");
	//pthread_mutex_unlock( &devicetab_mutex );
}
 
/* add an element to the filetab (open file table)
 * each file has a fileinfo record
 */
static int addfiletab()
{
	register int i;
	//pthread_mutex_lock( &devicetab_mutex );
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
	//pthread_mutex_unlock( &devicetab_mutex );
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

#define MAXARGS 256

static void debugfun(char *s,struct umdev *fc)
{
#ifdef DEBUGUMDEVARGS
	fprint2("DEBUG\n");
#endif
	fc->flags |= UMDEV_DEBUG;
}

static void charfun(char *s,struct umdev *fc)
{
	fc->mode=(fc->mode & ~S_IFMT) | S_IFCHR;
#ifdef DEBUGUMDEVARGS
	fprint2("CHAR %o\n",fc->mode);
#endif
}

static void blockfun(char *s,struct umdev *fc)
{
	fc->mode=(fc->mode & ~S_IFMT) | S_IFBLK;
#ifdef DEBUGUMDEVARGS
	fprint2("BLK %o\n",fc->mode);
#endif
}

static void majorfun(char *s,struct umdev *fc)
{
	int majx,minx;
#ifdef DEBUGUMDEVARGS
	fprint2("MAJ %s\n",s);
#endif
	majx=atoi(s);
	minx=minor(fc->device);
	fc->device=makedev(majx,minx);
}

static void minorfun(char *s,struct umdev *fc)
{
	int majx,minx;
#ifdef DEBUGUMDEVARGS
	fprint2("MIN %s\n",s);
#endif
	majx=major(fc->device);
	if (strcmp(s,"any")==0)
		minx = -1;
	else
		minx=atoi(s);
	fc->device=makedev(majx,minx);
}

static void plusnum(char *s,struct umdev *fc)
{
#ifdef DEBUGUMDEVARGS
	fprint2("PLUSNUM %s\n",s);
#endif
	fc->nsubdev=atoi(s);
}

static void modefun(char *s,struct umdev *fc)
{
	int mode;
	sscanf(s,"%o",&mode);
	fc->mode=(fc->mode & S_IFMT) | (mode & 0777);
#ifdef DEBUGUMDEVARGS
	fprint2("MODE %o %o\n",mode,fc->mode);
#endif
}

static void uidfun(char *s,struct umdev *fc)
{
#ifdef DEBUGUMDEVARGS
	fprint2("UID %s\n",s);
#endif
	fc->uid=atoi(s);
}

static void gidfun(char *s,struct umdev *fc)
{
#ifdef DEBUGUMDEVARGS
	fprint2("GID %s\n",s);
#endif
	fc->gid=atoi(s);
}


void devargs(char *opts, struct devargitem *devargtab, int devargsize, void *arg)
{
	char *sepopts[MAXARGS];
	int nsepopts=0;
	int i;
	char *optcopy=strdup(opts);
	char *s=optcopy;
	char quote=0,olds;
#ifdef DEBUGUMDEVARGS
	fprint2("devargs opts %s\n",s);
#endif
	/* PHASE 1: tokenize options */
	for (quote=0,s=opts,olds=*s;olds != 0 && nsepopts < MAXARGS;s++) {
		sepopts[nsepopts++]=s;
		while (*s != 0 && (*s != ',' || quote != 0))
		{
			if (*s=='\\' && *(s+1)!=0)
				s+=2;
			if (*s=='\'' || *s=='\"') {
				if (*s == quote)
					quote=0;
				else
					if (quote==0)
						quote=*s;
			}
			s++;
		}
		olds=*s;*s=0;
	}
#ifdef DEBUGUMDEVARGS
	for (i=0;i<nsepopts;i++)
		fprint2("separg %d = %s\n",i,sepopts[i]);
#endif
	/* PHASE 2 recognize UMUMDEV options */
	for (i=0;i<nsepopts;i++) {
		int j;
		for (j=0; j<devargsize && 
				strncmp(sepopts[i],devargtab[j].arg,strlen(devargtab[j].arg)) != 0; j++)
			;
		if (j<devargsize)
			devargtab[j].fun(sepopts[i]+strlen(devargtab[j].arg),arg);
	}
	free(optcopy);
}

static struct devargitem umdevargtab[] = {
	{"debug", debugfun},
	{"char", charfun},
	{"block", blockfun},
	{"major=", majorfun},
	{"minor=", minorfun},
	{"mode=", modefun},
	{"uid=", uidfun},
	{"gid=", gidfun},
	{"nsubdev=", plusnum}
};
#define UMDEVARGTABSIZE sizeof(umdevargtab)/sizeof(struct devargitem)

static long umdev_mount(char *source, char *target, char *filesystemtype,
		       unsigned long mountflags, void *data)
{
	void *dlhandle = openmodule(filesystemtype, RTLD_NOW);
	struct umdev_operations *umdev_ops;
	
	PRINTDEBUG(10, "MOUNT %s %s %s %x %s\n",source,target,filesystemtype,
			mountflags, (data!=NULL)?data:"<NULL>");

	if(dlhandle == NULL || (umdev_ops=dlsym(dlhandle,"umdev_ops")) == NULL) {
		fprint2("%s\n",dlerror());
		if(dlhandle != NULL)
			dlclose(dlhandle);
		errno=ENODEV;
		return -1;
	} else {
		struct umdev *new = (struct umdev *) malloc(sizeof(struct umdev));
		struct stat64 *s64;
		assert(new);
		s64=um_mod_getpathstat();
		new->path = strdup(target);
		new->mode = S_IFCHR | 0600;
		new->uid = getuid();
		new->gid = getgid();
		new->device = 0;
		if (s64) {
			new->device = s64->st_rdev;
			if (S_ISCHR(s64->st_mode) | S_ISBLK (s64->st_mode))
				new->mode = (s64->st_mode & S_IFMT) | 0600;
		}
		new->dlhandle = dlhandle;
		new->devops = umdev_ops;
		new->nsubdev = 0;
		new->inuse = 0;
		new->flags = 0;
		new->private_data = NULL;

		if(data) {
			char *datacopy=strdup(data);
			devargs(datacopy, umdevargtab, UMDEVARGTABSIZE, new);
			free(datacopy);
		}
		if (umdev_ops->init) {
			if (umdev_ops->init(mode2char(new->mode),new->device,source,
					mountflags,data?data:"", new) < 0) {
				deldevicetab(new);
				free(new->path);
				free(new);
				errno=EINVAL;
				return -1;
			}
		}
		new->tst=tst_timestamp();
		adddevicetab(new);
		return 0;
	}
}

static long umdev_umount2(char *target, int flags)
{
	struct umdev *fc;
	fc = searchdevice(target);
	if (fc == NULL) {
		errno=EINVAL;
		return -1;
	} else if (fc->inuse){
		/* TODO FORCE flag */
		errno=EBUSY;
		return -1;
	} else {
		struct umdev *fc_norace=fc;
		if (fc_norace->flags & UMDEV_DEBUG) 
			fprint2("UMOUNT => path:%s flag:%d\n",target, flags);
		if (fc_norace->devops->fini)
			fc_norace->devops->fini(mode2char(fc_norace->mode),fc_norace->device,fc);
		deldevicetab(fc);
		free(fc_norace->path);
		dlclose(fc_norace->dlhandle);
		free(fc_norace);
		return 0;
	}
}

#define TRUE 1
#define FALSE 0

static int alwaysfalse()
{
	return FALSE;
}

static long umdev_ioctlargs(struct ioctl_len_req *arg)
{
	int fd=arg->fd;
	if (filetab[fd]->umdev->devops->ioctlparms) {
		struct dev_info di;
		di.fh = filetab[fd]->fh;
		di.flags = 0;
		di.devhandle=filetab[fd]->umdev;
		return filetab[fd]->umdev->devops->ioctlparms(
				filetab[fd]->type, filetab[fd]->device, arg->req, filetab[fd]->umdev);
	} else
		return 0;
}

static epoch_t umdev_check(int type, void *arg)
{
	if (type == CHECKPATH) {
		char *path=arg;
		struct umdev *fc=searchdevice(path);
		if ( fc != NULL) {
			return fc->tst.epoch; 
		}
		else
			return FALSE;
	} else if (type == CHECKFSTYPE) {
		char *path=arg;
		return (strncmp(path,"umdev",5) == 0);
	} else if (type == CHECKIOCTLPARMS) {
		return umdev_ioctlargs(arg);
	} else {
		return FALSE;
	}
}

static long umdev_open(char *path, int flags, mode_t mode)
{
	struct umdev *fc = searchdevice(path);
	struct dev_info di;
	int fi = addfiletab();
	int rv;
	int exists_err;
	struct stat buf;
	assert(fc!=NULL);

#ifdef __UMDEV_DEBUG__
	PRINTDEBUG(10,"FLAGOPEN path:%s \nFLAGS:0x%x MODE:%d\n",path,flags,mode);

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
	filetab[fi]->count = 0;
	filetab[fi]->pos = 0;
	//filetab[fi]->size = buf.st_size; /* SIZE OF device? */
	di.flags = flags & ~(O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC);
	di.fh = 0;
	di.devhandle=fc;

	filetab[fi]->type=set_dev(&filetab[fi]->device,fc,path);
	filetab[fi]->umdev=fc;
	if (fc->devops->open)
		rv = fc->devops->open(filetab[fi]->type, filetab[fi]->device, &di);
	else
		rv=0;
	filetab[fi]->fh=di.fh;

	if (rv < 0)
	{
		if (fc->flags & UMDEV_DEBUG) 
        		fprint2("OPEN[%d: %c(%d,%d)] ERROR => path:%s flags:0x%x\n",
				fi, filetab[fi]->type, major(filetab[fi]->device), minor(filetab[fi]->device), path, flags);	
		delfiletab(fi);
		errno = -rv;
		return -1;
	} else {
		filetab[fi]->count += 1;
		if (fc->flags & UMDEV_DEBUG) 
        		fprint2("OPEN[%d: %c(%d:%d)] => path:%s flags:0x%x\n",
				fi, filetab[fi]->type, major(filetab[fi]->device), minor(filetab[fi]->device), path, flags);
		fc->inuse++;
		return fi;
	}
}

static long umdev_close(int fd)
{
	int rv;
	
	if (filetab[fd]==NULL) {
		errno=EBADF;
		return -1;
	} else {
		struct dev_info di;
		di.fh = filetab[fd]->fh;
		di.flags = filetab[fd]->umdev->flags;
		di.devhandle=filetab[fd]->umdev;
		if (filetab[fd]->umdev->flags & UMDEV_DEBUG) 
			fprint2("CLOSE[%d %c(%d:%d)] %p\n",fd,
					filetab[fd]->type, major(filetab[fd]->device), minor(filetab[fd]->device),filetab[fd]);
		filetab[fd]->count--;
		PRINTDEBUG(10,"->CLOSE %c(%d:%d) %d\n",
				filetab[fd]->type, major(filetab[fd]->device), minor(filetab[fd]->device), filetab[fd]->count);
		if (filetab[fd]->count == 0) {			 
			filetab[fd]->umdev->inuse--;
			if (filetab[fd]->umdev->devops->release)
				rv=filetab[fd]->umdev->devops->release(filetab[fd]->type, filetab[fd]->device, &di);
			else
				rv=0;
			if (filetab[fd]->umdev->flags & UMDEV_DEBUG) 
        			fprint2("RELEASE[%d %c(%d:%d)] => flags:0x%x rv=%d\n",
					fd, filetab[fd]->type, major(filetab[fd]->device), minor(filetab[fd]->device), filetab[fd]->umdev->flags,rv);
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

static long umdev_read(int fd, void *buf, size_t count)
{
	int rv;
	if (filetab[fd]==NULL) {
		errno=EBADF;
		return -1;
	} 
	else {
		struct dev_info di;
		di.fh = filetab[fd]->fh;
		di.flags = 0;
		di.devhandle=filetab[fd]->umdev;
		if (filetab[fd]->umdev->devops->read)
			rv = filetab[fd]->umdev->devops->read(
					filetab[fd]->type, filetab[fd]->device, 
					buf, count, filetab[fd]->pos, &di);
		else
			rv= -EINVAL;
		if (filetab[fd]->umdev->flags & UMDEV_DEBUG) 
        		fprint2("READ[%d %c(%d:%d)] => count:%u\n",
				fd, filetab[fd]->type, major(filetab[fd]->device), minor(filetab[fd]->device), count);
		if (rv<0) {
			errno= -rv;
			return -1;
		} else {
			filetab[fd]->pos += rv;
			return rv;
		}
	}
}

static long umdev_write(int fd, void *buf, size_t count)
{
	int rv;

	if (filetab[fd]==NULL) {
		errno = EBADF;
		return -1;
	} else {
		struct dev_info di;
		di.fh = filetab[fd]->fh;
		di.flags = 0;
		di.devhandle=filetab[fd]->umdev;
		if(filetab[fd]->umdev->devops->write) {
			rv = filetab[fd]->umdev->devops->write(
					filetab[fd]->type, filetab[fd]->device,
					buf, count, filetab[fd]->pos, &di);
		} else
			rv= -EINVAL;
		if (filetab[fd]->umdev->flags & UMDEV_DEBUG) 
			fprint2("WRITE[%d %c(%d:%d)] => count:0x%x\n",
				fd, filetab[fd]->type, major(filetab[fd]->device), minor(filetab[fd]->device), count);
	
		PRINTDEBUG(10,"WRITE rv:%d\n",rv); 
		if (rv<0) {
			errno= -rv;
			return -1;
		} else {
			filetab[fd]->pos += rv;
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

static int common_stat64(struct umdev *fc, char type, dev_t device, struct stat64 *buf64)
{
	int rv;
	assert(fc != NULL);
	struct dev_info di;
	memset(buf64, 0, sizeof(struct stat64));
	if(fc->devops->getattr)
		rv = fc->devops->getattr(type, device,buf64,fc);
	else {
		memset(buf64,0,sizeof(struct stat64));
		buf64->st_mode=fc->mode;
		buf64->st_rdev=device;
		buf64->st_uid=fc->uid;
		buf64->st_gid=fc->gid;
		rv=0;
	}
	if (fc->flags & UMDEV_DEBUG) 
		fprint2("stat->GETATTR %c(%d:%d) => status: %s\n",
				type, major(device), minor(device), rv ? "Error" : "Success");
	if (rv<0) {
		errno= -rv;
		return -1;
	} else
		return rv;
}

/*
static int common_stat64(struct umdev *fc, char type, dev_t device, struct stat64 *buf64)
{
	int rv;
	struct stat buf;
	if ((rv=common_stat(fc,type,device,&buf))>=0)
		stat2stat64(buf64,&buf);
	return rv;
}
*/

static long umdev_fstat64(int fd, struct stat64 *buf64)
{
	if (fd < 0 || filetab[fd] == NULL) {
		errno=EBADF;
		return -1;
	} else {
		struct umdev *fc=filetab[fd]->umdev;
		if(fc->devops->fgetattr) {
			struct dev_info di;
			int rv;
			di.fh = filetab[fd]->fh;
			di.flags = 0;
			di.devhandle=fc;
			rv=fc->devops->fgetattr(filetab[fd]->type,filetab[fd]->device,buf64,&di);
			if (fc->flags & UMDEV_DEBUG) 
				fprint2("stat->FGETATTR %c(%d:%d) => status: %s\n",
						filetab[fd]->type, 
						major(filetab[fd]->device), minor(filetab[fd]->device), 
						rv ? "Error" : "Success");
			if (rv<0) {
				errno= -rv;
				return -1;
			} else
				return rv;
		} else
			return common_stat64(fc,filetab[fd]->type,filetab[fd]->device,buf64);
	}
}

/*
static long umdev_fstat64(int fd, struct stat64 *buf64)
{
	if (filetab[fd]==NULL) {
		errno=EBADF;
		return -1;
	} else {
		int rv;
		struct stat buf;
		if ((rv=umdev_fstat(fd,&buf))>=0)
			stat2stat64(buf64,&buf);
		return rv;
	}
}

static long umdev_stat(char *path, struct stat *buf)
{
	dev_t device;
	int type;
	struct umdev *umdev=searchdevice(path);
	type=set_dev(&device,umdev,path);
	return common_stat(umdev,type,device,buf);
}

static long umdev_lstat(char *path, struct stat *buf)
{
	dev_t device;
	int type;
	struct umdev *umdev=searchdevice(path);
	type=set_dev(&device,umdev,path);
	return common_stat(umdev,type,device,buf);
}
*/

static long umdev_stat64(char *path, struct stat64 *buf64)
{
	dev_t device;
	int type;
	struct umdev *umdev=searchdevice(path);
	type=set_dev(&device,umdev,path);
	return common_stat64(umdev,type,device,buf64);
}

static long umdev_lstat64(char *path, struct stat64 *buf64)
{
	dev_t device;
	int type;
	struct umdev *umdev=searchdevice(path);
	type=set_dev(&device,umdev,path);
	return common_stat64(umdev,type,device,buf64);
}

static long umdev_access(char *path, int mode)
{
	struct umdev *fc=searchdevice(path);
	int rv;
	dev_t device;
	int type;
	type=set_dev(&device,fc,path);
	assert(fc!=NULL);
	if (fc->flags & UMDEV_DEBUG) 
        	fprint2("ACCESS %c(%d,%d) => path:%s mode:%s%s%s%s\n", 
							type, major(device), minor(device),
							path,
				(mode & R_OK) ? "R_OK": "",
				(mode & W_OK) ? "W_OK": "",
				(mode & X_OK) ? "X_OK": "",
				(mode & F_OK) ? "F_OK": "");
	if (fc->devops->access)
		rv= fc->devops->access(type, device, mode, fc);
	else
		rv=0;
	if (rv < 0) {
		errno = -rv;
		return -1;
	} else {
		errno = 0;
		return 0;
	}
}
/*
static long umdev_mknod(const char *path, mode_t mode, dev_t dev)
{
	struct device_context *fc = searchdevice(path);
	int rv;
	assert(fc != NULL);
	device_set_context(fc);
	if (fc->device->flags & UMDEV_DEBUG)
        	fprint2("MKNOD => path:%s\n",path);
	rv = fc->device->fops.mknod(
			path, mode, dev);
	if (rv < 0) {
		errno = -rv;
		return -1;
	}
	return rv;
}
*/


static long umdev_chmod(char *path, int mode)
{
	int rv;
	struct umdev *umdev;
	dev_t device;
	int type;

	umdev=searchdevice(path);
	assert(umdev != NULL);
	type=set_dev(&device,umdev,path);

	if (umdev->flags & UMDEV_DEBUG) 
        	fprint2("CHMOD => path:%s\n",path);
	if (umdev->devops->chmod)
		rv= umdev->devops->chmod(type,device,mode,umdev);
	else {
		umdev->mode=(umdev->mode & S_IFMT) | mode;
		rv=0;
	}
	if (rv < 0) {
		errno = -rv;
		return -1;
	}
	return rv;
}

static long umdev_chown(char *path, uid_t owner, gid_t group)
{
	int rv;
	struct umdev *umdev;
	dev_t device;
	int type;

	umdev=searchdevice(path);
	assert(umdev != NULL);
	type=set_dev(&device,umdev,path);

	if (umdev->devops->chmod)
		rv= umdev->devops->chown(type,device,owner,group,umdev);
	else {
		umdev->uid=owner;
		umdev->gid=group;
		rv=0;
	}
	if (rv < 0) {
		errno = -rv;
		return -1;
	} else
		return rv;
}

static long umdev_fsync(int fd)
{
	int rv;
	if (filetab[fd]==NULL) {
		errno=EBADF;
		return -1;
	} 
	else {
		struct dev_info di;
		di.fh = filetab[fd]->fh;
		di.flags = 0;
		di.devhandle=filetab[fd]->umdev;
		if (filetab[fd]->umdev->devops->fsync)
			rv = filetab[fd]->umdev->devops->fsync(
					filetab[fd]->type, filetab[fd]->device, &di);
		else
			rv= 0;
		if (filetab[fd]->umdev->flags & UMDEV_DEBUG) 
			fprint2("FSYNC[%d %c(%d:%d)] rv=%d\n",
					fd, filetab[fd]->type, major(filetab[fd]->device), minor(filetab[fd]->device), rv);
		if (rv<0) {
			errno= -rv;
			return -1;
		} else {
			return rv;
		}
	}
}

static loff_t umdev_x_lseek(int fd, off_t offset, int whence)
{
	if (filetab[fd]==NULL) {
		errno = EBADF; 
		return -1;
	} else if (filetab[fd]->umdev->devops->lseek) {
		loff_t rv;
		struct dev_info di;
		di.fh = filetab[fd]->fh;
		di.flags = 0;
		di.devhandle=filetab[fd]->umdev;
		rv=filetab[fd]->umdev->devops->lseek(
				filetab[fd]->type, filetab[fd]->device, offset, whence, filetab[fd]->pos, &di);
		if (filetab[fd]->umdev->flags & UMDEV_DEBUG) 
			fprint2("SEEK[%d %c(%d:%d)] OFF %lld WHENCE %d -> %lld\n",
					fd, filetab[fd]->type, major(filetab[fd]->device), minor(filetab[fd]->device),
					offset,whence, rv);
		if (rv<0) {
			errno= -rv;
			return -1;
		} else {
			filetab[fd]->pos=rv;
			return rv;
		}
	} else {
		errno = ENOSYS;
		return -1;
	}
}

static ssize_t umdev_pread64(int fd, void *buf, size_t count, long long offset)
{
	ssize_t rv;
	rv=umdev_x_lseek(fd,(off_t) offset,SEEK_SET);
	if (rv >= 0)
		rv=umdev_read(fd,buf,count);
	return rv;
}

static ssize_t umdev_pwrite64(int fd, void *buf, size_t count, long long offset)
{
	ssize_t rv;
	rv=umdev_x_lseek(fd,(off_t) offset,SEEK_SET);
	if (rv >= 0)
		rv=umdev_write(fd,buf,count);
	return rv;
}

static long umdev_lseek(int fd, int offset, int whence)
{
	return umdev_x_lseek(fd, offset, whence);
}

static long umdev__llseek(unsigned int fd, unsigned long offset_high,  unsigned  long offset_low, loff_t *result, unsigned int whence)
{
	PRINTDEBUG(10,"umdev__llseek %d %d %d %d\n",fd,offset_high,offset_low,whence);
	if (result == NULL) {
		errno = EFAULT;
		return -1;
	} else {
		loff_t rv;
		loff_t offset=((loff_t)offset_high)<<32 | offset_low;
		rv=umdev_x_lseek(fd,offset,whence);
		if (rv >= 0) {
			*result=rv;
			return 0;
		} else {
			errno = -rv;
			return -1;
		}
	}
}

static long umdev_ioctl(int fd, int req, void *arg)
{
	int rv;
	if (filetab[fd]==NULL) {
		errno=EBADF;
		return -1;
	}
	else {
		if (filetab[fd]->umdev->devops->ioctl) {
			struct dev_info di;
			di.fh = filetab[fd]->fh;
			di.flags = 0;
			di.devhandle=filetab[fd]->umdev;
			rv = filetab[fd]->umdev->devops->ioctl(
					filetab[fd]->type, filetab[fd]->device,
					req, arg, &di);
		} else
			rv= -EINVAL;
		if (filetab[fd]->umdev->flags & UMDEV_DEBUG) 
			fprint2("IOCTL[%d %c(%d:%d)] => req:%x\n",
					fd, filetab[fd]->type, major(filetab[fd]->device), minor(filetab[fd]->device), req);
		if (rv<0) {
			errno= -rv;
			return -1;
		} else 
			return rv;
	}
}

static void contextclose(struct umdev *fc)
{
	umdev_umount2(fc->path,MNT_FORCE);
}

static long umdev_event_subscribe(void (* cb)(), void *arg, int fd, int how)
{
	int rv=1;
	if (filetab[fd]==NULL) {
		errno=EBADF;
		return -1;
	}
	else {
		if (filetab[fd]->umdev->devops->event_subscribe) {
			struct dev_info di;
			di.fh = filetab[fd]->fh;
			di.flags = 0;
			di.devhandle=filetab[fd]->umdev;
			rv = filetab[fd]->umdev->devops->event_subscribe(
					          filetab[fd]->type, filetab[fd]->device,
											cb, arg, how, &di);
		}
		if (rv<0) {
			errno= -rv;
			return -1;
		} else 
			return rv;
	}
}

void umdev_setprivatedata(struct umdev *devhandle, void *privatedata)
{
	if(devhandle)
		devhandle->private_data=privatedata;
}

void *umdev_getprivatedata(struct umdev *devhandle)
{
	if(devhandle)
		return devhandle->private_data;
}

void umdev_setnsubdev(struct umdev *devhandle, int nsubdev)
{
	if(devhandle)
		devhandle->nsubdev=nsubdev;
}

int umdev_getnsubdev(struct umdev *devhandle)
{
	if(devhandle)
		return devhandle->nsubdev;
}

dev_t umdev_getbasedev(struct umdev *devhandle)
{
	if(devhandle)
		return devhandle->device;
}

void umdev_setmode(struct umdev *devhandle, mode_t mode)
{
	if(devhandle)
		devhandle->mode=mode;
}

mode_t umdev_getmode(struct umdev *devhandle)
{
	if(devhandle)
		return devhandle->mode;
}


static void
__attribute__ ((constructor))
init (void)
{
	fprint2("umdev init\n");
	s.name="umdev";
	s.code=UMDEV_SERVICE_CODE;
	s.checkfun=umdev_check;
	//pthread_key_create(&context_key,NULL);
	s.syscall=(sysfun *)calloc(scmap_scmapsize,sizeof(sysfun));
	s.socket=(sysfun *)calloc(scmap_sockmapsize,sizeof(sysfun));
	SERVICESYSCALL(s, mount, umdev_mount);
#if 0
#if ! defined(__x86_64__)
	SERVICESYSCALL(s, umount, umdev_umount2); /* umount must be mapped onto umount2 */
#endif
#endif
	SERVICESYSCALL(s, umount2, umdev_umount2);
	SERVICESYSCALL(s, open, umdev_open);
#if 0
	SERVICESYSCALL(s, creat, umdev_open); /*creat is an open with (O_CREAT|O_WRONLY|O_TRUNC)*/
#endif
	SERVICESYSCALL(s, read, umdev_read);
	SERVICESYSCALL(s, write, umdev_write);
	SERVICESYSCALL(s, close, umdev_close);
#if 0
	SERVICESYSCALL(s, stat, umdev_stat);
	SERVICESYSCALL(s, lstat, umdev_lstat);
	SERVICESYSCALL(s, fstat, umdev_fstat);
#endif
#if !defined(__x86_64__)
	SERVICESYSCALL(s, stat64, umdev_stat64);
	SERVICESYSCALL(s, lstat64, umdev_lstat64);
	SERVICESYSCALL(s, fstat64, umdev_fstat64);
#endif
	SERVICESYSCALL(s, access, umdev_access);
	SERVICESYSCALL(s, lseek, umdev_lseek);
#if ! defined(__x86_64__)
	SERVICESYSCALL(s, _llseek, umdev__llseek);
#endif
	//SERVICESYSCALL(s, mknod, umdev_mknod);
	SERVICESYSCALL(s, chown, umdev_chown);
	SERVICESYSCALL(s, fchown, fchown);
	SERVICESYSCALL(s, chmod, umdev_chmod);
	//SERVICESYSCALL(s, fchmod, fchmod);
	SERVICESYSCALL(s, fsync, umdev_fsync); 
	//SERVICESYSCALL(s, _newselect, umdev_select);
	SERVICESYSCALL(s, ioctl, umdev_ioctl); 
	SERVICESYSCALL(s, pread64, umdev_pread64); 
	SERVICESYSCALL(s, pwrite64, umdev_pwrite64); 
	s.event_subscribe=umdev_event_subscribe;
	add_service(&s);
}

static void
__attribute__ ((destructor))
fini (void)
{
	free(s.syscall);
	free(s.socket);
	foralldevicetabdo(contextclose);
	fprint2("umdev fini\n");
}

