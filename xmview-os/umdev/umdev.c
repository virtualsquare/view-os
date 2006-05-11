/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   UMDEV: Virtual Device in Userspace
 *    Copyright (C) 2006  Renzo Davoli <renzo@cs.unibo.it>
 *    from an idea of Andrea Gasparini
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
#include "module.h"
#include "libummod.h"
#include "umdev.h"

#define UMDEV_SERVICE_CODE 0x02

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
	struct umdev_operations *devops;	
	int inuse;
	unsigned long flags;
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
		fprintf(stderr, "[%d:%lu] dev %s:%d %s(): ", getpid(), pthread_self(), file, line, func);
#else
		fprintf(stderr, "[%d] dev %s:%d %s(): ", getpid(), file, line, func);
#endif
		vfprintf(stderr, fmt, ap);
		fprintf(stderr, "\n");
		fflush(stderr);
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
			if ((strcmp(path,devicetab[i]->path) == 0) &&
					((e=tst_matchingepoch(&(devicetab[i]->tst))) > maxepoch)) {
				maxi=i;
				maxepoch=e;
			}
		}
	}
  /* Major/Minor Number select */	
	if (maxi < 0 && stat64(path,&buf) >= 0)
		for (i=0;i<devicetabmax && result==NULL;i++)
		{
			epoch_t e;
			if ((devicetab[i] != NULL)) {
				if (((((devicetab[i]->mode & S_IFMT) == 0) ||
							((buf.st_mode & S_IFMT) ==  (devicetab[i]->mode & S_IFMT))) &&
						(major(devicetab[i]->device) == major(buf.st_rdev)) &&
						((minor(devicetab[i]->device) == -1) || 
						 (minor(devicetab[i]->device) == minor(buf.st_rdev)))) &&
						((e=tst_matchingepoch(&(devicetab[i]->tst))) > maxepoch)) {
					maxi=i;
					maxepoch=e;
				}
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
	if (stat64(path,&buf) >= 0) {
		*dev=buf.st_rdev;
	} else {
		*dev= umdev->device;
	}
	mode= umdev->mode;
	//printf("SET_DEV %s %x %d %d\n",path,mode,major(*dev),minor(*dev));
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
		fprintf(stderr,"delmnt inexistent entry\n");
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
	printf("DEBUG\n");
#endif
	fc->flags |= UMDEV_DEBUG;
}

static void charfun(char *s,struct umdev *fc)
{
	fc->mode=(fc->mode & ~S_IFMT) | S_IFCHR;
#ifdef DEBUGUMDEVARGS
	printf("CHAR %o\n",fc->mode);
#endif
}

static void blockfun(char *s,struct umdev *fc)
{
	fc->mode=(fc->mode & ~S_IFMT) | S_IFBLK;
#ifdef DEBUGUMDEVARGS
	printf("BLK %o\n",fc->mode);
#endif
}

static void majorfun(char *s,struct umdev *fc)
{
	int majx,minx;
#ifdef DEBUGUMDEVARGS
	printf("MAJ %s\n",s);
#endif
	majx=atoi(s);
	minx=minor(fc->device);
	fc->device=makedev(majx,minx);
}

static void minorfun(char *s,struct umdev *fc)
{
	int majx,minx;
#ifdef DEBUGUMDEVARGS
	printf("MIN %s\n",s);
#endif
	majx=major(fc->device);
	if (strcmp(s,"any")==0)
		minx = -1;
	else
		minx=atoi(s);
	fc->device=makedev(majx,minx);
}

static void modefun(char *s,struct umdev *fc)
{
	int mode;
	sscanf(s,"%o",&mode);
	fc->mode=(fc->mode & S_IFMT) | (mode & 0777);
#ifdef DEBUGUMDEVARGS
	printf("MODE %o %o\n",mode,fc->mode);
#endif
}

static void uidfun(char *s,struct umdev *fc)
{
#ifdef DEBUGUMDEVARGS
	printf("UID %s\n",s);
#endif
	fc->uid=atoi(s);
}

static void gidfun(char *s,struct umdev *fc)
{
#ifdef DEBUGUMDEVARGS
	printf("GID %s\n",s);
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
	printf("devargs opts %s\n",s);
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
		printf("separg %d = %s\n",i,sepopts[i]);
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
	{"gid=", gidfun}
};
#define UMDEVARGTABSIZE sizeof(umdevargtab)/sizeof(struct devargitem)

static int umdev_mount(char *source, char *target, char *filesystemtype,
		       unsigned long mountflags, void *data)
{
	void *dlhandle = dlopen(filesystemtype, RTLD_NOW);
	struct umdev_operations *umdev_ops;
	
	PRINTDEBUG(10, "MOUNT %s %s %s %x %s\n",source,target,filesystemtype,
			mountflags, (data!=NULL)?data:"<NULL>");

	if(dlhandle == NULL || (umdev_ops=dlsym(dlhandle,"umdev_ops")) == NULL) {
		fprintf(stderr, "%s\n",dlerror());
		fflush(stderr);
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
		new->tst=tst_timestamp();
		new->mode = S_IFCHR | 0600;
		new->uid = getuid();
		new->gid = getgid();
		if (s64) {
			new->device = s64->st_rdev;
			if (S_ISCHR(s64->st_mode) | S_ISBLK (s64->st_mode))
				new->mode = (s64->st_mode & S_IFMT) | 0600;
		}
		new->dlhandle = dlhandle;
		new->devops = umdev_ops;
		new->inuse = 0;
		new->flags = 0;

		if(data)
			devargs(data, umdevargtab, UMDEVARGTABSIZE, new);
		adddevicetab(new);
		if (umdev_ops->init)
			umdev_ops->init(mode2char(new->mode),new->device,source,mountflags,data?data:"");
		return 0;
	}
}

static int umdev_umount2(char *target, int flags)
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
		if (fc_norace->flags & UMDEV_DEBUG) {
			fprintf(stderr, "UMOUNT => path:%s flag:%d\n",target, flags);
			fflush(stderr);
		}
		if (fc_norace->devops->fini)
			fc_norace->devops->fini(mode2char(fc_norace->mode),fc_norace->device);
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

static int umdev_ioctlargs(struct ioctl_len_req *arg)
{
	int fd=arg->fd;
	if (filetab[fd]->umdev->devops->ioctlparms) {
		struct dev_info di;
		di.fh = filetab[fd]->fh;
		di.flags = 0;
		return filetab[fd]->umdev->devops->ioctlparms(
				filetab[fd]->type, filetab[fd]->device, arg->req);
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

static int umdev_open(char *path, int flags, mode_t mode)
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

	filetab[fi]->type=set_dev(&filetab[fi]->device,fc,path);
	filetab[fi]->umdev=fc;
	if (fc->devops->open)
		rv = fc->devops->open(filetab[fi]->type, filetab[fi]->device, &di);
	else
		rv=0;
	filetab[fi]->fh=di.fh;

	if (rv < 0)
	{
		if (fc->flags & UMDEV_DEBUG) {
        		fprintf(stderr, "OPEN[%d: %c(%d,%d)] ERROR => path:%s flags:0x%x\n",
				fi, filetab[fi]->type, major(filetab[fi]->device), minor(filetab[fi]->device), path, flags);	
			fflush(stderr);
		}		
		delfiletab(fi);
		errno = -rv;
		return -1;
	} else {
		filetab[fi]->count += 1;
		if (fc->flags & UMDEV_DEBUG) {
        		fprintf(stderr, "OPEN[%d: %c(%d:%d)] => path:%s flags:0x%x\n",
				fi, filetab[fi]->type, major(filetab[fi]->device), minor(filetab[fi]->device), path, flags);
			fflush(stderr);
		}

		fc->inuse++;
		return fi;
	}
}

static int umdev_close(int fd)
{
	int rv;
	
	if (filetab[fd]==NULL) {
		errno=EBADF;
		return -1;
	} else {
		struct dev_info di;
		di.fh = filetab[fd]->fh;
		di.flags = filetab[fd]->umdev->flags;
		if (filetab[fd]->umdev->flags & UMDEV_DEBUG) {
			fprintf(stderr, "CLOSE[%d %c(%d:%d)] %p\n",fd,
					filetab[fd]->type, major(filetab[fd]->device), minor(filetab[fd]->device),filetab[fd]);
			fflush(stderr);
		}
	
		filetab[fd]->count--;
		PRINTDEBUG(10,"->CLOSE %c(%d:%d) %d\n",
				filetab[fd]->type, major(filetab[fd]->device), minor(filetab[fd]->device), filetab[fd]->count);
		if (filetab[fd]->count == 0) {			 
			filetab[fd]->umdev->inuse--;
			if (filetab[fd]->umdev->devops->release)
				rv=filetab[fd]->umdev->devops->release(filetab[fd]->type, filetab[fd]->device, &di);
			else
				rv=0;
			if (filetab[fd]->umdev->flags & UMDEV_DEBUG) {
        			fprintf(stderr, "RELEASE[%d %c(%d:%d)] => flags:0x%x\n",
					fd, filetab[fd]->type, major(filetab[fd]->device), minor(filetab[fd]->device), filetab[fd]->umdev->flags);
				fflush(stderr);					
			}
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

static int umdev_read(int fd, void *buf, size_t count)
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
		if (filetab[fd]->umdev->devops->read)
			rv = filetab[fd]->umdev->devops->read(
					filetab[fd]->type, filetab[fd]->device, 
					buf, count, filetab[fd]->pos, &di);
		else
			rv= -EINVAL;
		if (filetab[fd]->umdev->flags & UMDEV_DEBUG) {
        		fprintf(stderr, "READ[%d %c(%d:%d)] => count:%u\n",
				fd, filetab[fd]->type, major(filetab[fd]->device), minor(filetab[fd]->device), count);
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

static int umdev_write(int fd, void *buf, size_t count)
{
	int rv;

	if (filetab[fd]==NULL) {
		errno = EBADF;
		return -1;
	} else {
		struct dev_info di;
		di.fh = filetab[fd]->fh;
		di.flags = 0;
		if(filetab[fd]->umdev->devops->write) {
			rv = filetab[fd]->umdev->devops->write(
					filetab[fd]->type, filetab[fd]->device,
					buf, count, filetab[fd]->pos, &di);
		} else
			rv= -EINVAL;
		if (filetab[fd]->umdev->flags & UMDEV_DEBUG) {
			fprintf(stderr, "WRITE[%d %c(%d:%d)] => count:0x%x\n",
				fd, filetab[fd]->type, major(filetab[fd]->device), minor(filetab[fd]->device), count);
			fflush(stderr);
		}
	
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

static int common_stat(struct umdev *fc, char type, dev_t device, struct stat *buf)
{
	int rv;
	assert(fc != NULL);
	struct dev_info di;
	memset(buf, 0, sizeof(struct stat));
	if(fc->devops->getattr)
		rv = fc->devops->getattr(type, device,buf);
	else {
		memset(buf,0,sizeof(struct stat));
		buf->st_mode=fc->mode;
		buf->st_rdev=device;
		buf->st_uid=fc->uid;
		buf->st_gid=fc->gid;
		rv=0;
	}
	if (fc->flags & UMDEV_DEBUG) {
		fprintf(stderr, "stat->GETATTR %c(%d:%d) => status: %s\n",
				type, major(device), minor(device), rv ? "Error" : "Success");
		fflush(stderr);
	}
	if (rv<0) {
		errno= -rv;
		return -1;
	} else
		return rv;
}

static int common_stat64(struct umdev *fc, char type, dev_t device, struct stat64 *buf64)
{
	int rv;
	struct stat buf;
	if ((rv=common_stat(fc,type,device,&buf))>=0)
		stat2stat64(buf64,&buf);
	return rv;
}

static int umdev_fstat(int fd, struct stat *buf)
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
			rv=fc->devops->fgetattr(filetab[fd]->type,filetab[fd]->device,buf,&di);
			if (fc->flags & UMDEV_DEBUG) {
				fprintf(stderr, "stat->FGETATTR %c(%d:%d) => status: %s\n",
						filetab[fd]->type, 
						major(filetab[fd]->device), minor(filetab[fd]->device), 
						rv ? "Error" : "Success");
				fflush(stderr);
			}
			if (rv<0) {
				errno= -rv;
				return -1;
			} else
				return rv;
		} else
			return common_stat(fc,filetab[fd]->type,filetab[fd]->device,buf);
	}
}

static int umdev_fstat64(int fd, struct stat64 *buf64)
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

static int umdev_stat(char *path, struct stat *buf)
{
	dev_t device;
	int type;
	struct umdev *umdev=searchdevice(path);
	type=set_dev(&device,umdev,path);
	return common_stat(umdev,type,device,buf);
}

static int umdev_lstat(char *path, struct stat *buf)
{
	dev_t device;
	int type;
	struct umdev *umdev=searchdevice(path);
	type=set_dev(&device,umdev,path);
	return common_stat(umdev,type,device,buf);
}

static int umdev_stat64(char *path, struct stat64 *buf64)
{
	dev_t device;
	int type;
	struct umdev *umdev=searchdevice(path);
	type=set_dev(&device,umdev,path);
	return common_stat64(umdev,type,device,buf64);
}

static int umdev_lstat64(char *path, struct stat64 *buf64)
{
	dev_t device;
	int type;
	struct umdev *umdev=searchdevice(path);
	type=set_dev(&device,umdev,path);
	return common_stat64(umdev,type,device,buf64);
}

static int umdev_access(char *path, int mode)
{
	struct umdev *fc=searchdevice(path);
	int rv;
	dev_t device;
	int type;
	type=set_dev(&device,fc,path);
	assert(fc!=NULL);
	if (fc->flags & UMDEV_DEBUG) {
        	fprintf(stderr, "ACCESS %c(%d,%d) => path:%s mode:%s%s%s%s\n", 
							type, major(device), minor(device),
							path,
				(mode & R_OK) ? "R_OK": "",
				(mode & W_OK) ? "W_OK": "",
				(mode & X_OK) ? "X_OK": "",
				(mode & F_OK) ? "F_OK": "");
		fflush(stderr);
	}
	if (fc->devops->access)
		rv= fc->devops->access(type, device, mode);
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
static int umdev_mknod(const char *path, mode_t mode, dev_t dev)
{
	struct device_context *fc = searchdevice(path);
	int rv;
	assert(fc != NULL);
	device_set_context(fc);
	if (fc->device->flags & UMDEV_DEBUG)
        	fprintf(stderr, "MKNOD => path:%s\n",path);
	rv = fc->device->fops.mknod(
			path, mode, dev);
	if (rv < 0) {
		errno = -rv;
		return -1;
	}
	return rv;
}
*/


static int umdev_chmod(char *path, int mode)
{
	int rv;
	struct umdev *umdev;
	dev_t device;
	int type;

	umdev=searchdevice(path);
	assert(umdev != NULL);
	type=set_dev(&device,umdev,path);

	if (umdev->flags & UMDEV_DEBUG) {
        	fprintf(stderr, "CHMOD => path:%s\n",path);
		fflush(stderr);
	}
	if (umdev->devops->chmod)
		rv= umdev->devops->chmod(type,device,mode);
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

static int umdev_chown(char *path, uid_t owner, gid_t group)
{
	int rv;
	struct umdev *umdev;
	dev_t device;
	int type;

	umdev=searchdevice(path);
	assert(umdev != NULL);
	type=set_dev(&device,umdev,path);

	if (umdev->devops->chmod)
		rv= umdev->devops->chown(type,device,owner,group);
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

//see device.h: it is has not the same meaning of syscall
static int umdev_fsync(int fd)
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
		if (filetab[fd]->umdev->devops->fsync)
			rv = filetab[fd]->umdev->devops->fsync(
					filetab[fd]->type, filetab[fd]->device, &di);
		else
			rv= -EINVAL;
		if (filetab[fd]->umdev->flags & UMDEV_DEBUG) {
			fprintf(stderr, "FSYNC[%d %c(%d:%d)]\n",
					fd, filetab[fd]->type, major(filetab[fd]->device), minor(filetab[fd]->device));
			fflush(stderr);
		}
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
		rv=filetab[fd]->umdev->devops->lseek(
				filetab[fd]->type, filetab[fd]->device, offset, whence, filetab[fd]->pos, &di);
		if (filetab[fd]->umdev->flags & UMDEV_DEBUG) {
			fprintf(stderr, "SEEK[%d %c(%d:%d)] OFF %lld WHENCE %d -> %lld\n",
					fd, filetab[fd]->type, major(filetab[fd]->device), minor(filetab[fd]->device),
					offset,whence, rv);
			fflush(stderr);
		}

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

static int umdev_lseek(int fd, int offset, int whence)
{
	return umdev_x_lseek(fd, offset, whence);
}

static int umdev__llseek(unsigned int fd, unsigned long offset_high,  unsigned  long offset_low, loff_t *result, unsigned int whence)
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

static int umdev_ioctl(int fd, int req, void *arg)
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
			rv = filetab[fd]->umdev->devops->ioctl(
					filetab[fd]->type, filetab[fd]->device,
					req, arg, &di);
		} else
			rv= -EINVAL;
		if (filetab[fd]->umdev->flags & UMDEV_DEBUG) {
			fprintf(stderr, "IOCTL[%d %c(%d:%d)] => req:%x\n",
					fd, filetab[fd]->type, major(filetab[fd]->device), minor(filetab[fd]->device), req);
			fflush(stderr);
		}
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

static int umdev_select_register(void (* cb)(), void *arg, int fd, int how)
{
	int rv=1;
	if (filetab[fd]==NULL) {
		errno=EBADF;
		return -1;
	}
	else {
		if (filetab[fd]->umdev->devops->select_register) {
			struct dev_info di;
			di.fh = filetab[fd]->fh;
			di.flags = 0;
			rv = filetab[fd]->umdev->devops->select_register(
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

static void
__attribute__ ((constructor))
init (void)
{
	printf("umdev init\n");
	s.name="umdev";
	s.code=UMDEV_SERVICE_CODE;
	s.checkfun=umdev_check;
	//pthread_key_create(&context_key,NULL);
	s.syscall=(intfun *)calloc(scmap_scmapsize,sizeof(intfun));
	s.socket=(intfun *)calloc(scmap_sockmapsize,sizeof(intfun));
	s.syscall[uscno(__NR_mount)]=umdev_mount;
#if ! defined(__x86_64__)
	s.syscall[uscno(__NR_umount)]=umdev_umount2; /* umount must be mapped onto umount2 */
#endif
	s.syscall[uscno(__NR_umount2)]=umdev_umount2;
	s.syscall[uscno(__NR_open)]=umdev_open;
	s.syscall[uscno(__NR_creat)]=umdev_open; /*creat is an open with (O_CREAT|O_WRONLY|O_TRUNC)*/
	s.syscall[uscno(__NR_read)]=umdev_read;
	s.syscall[uscno(__NR_write)]=umdev_write;
	//s.syscall[uscno(__NR_readv)]=readv;
	//s.syscall[uscno(__NR_writev)]=writev;
	s.syscall[uscno(__NR_close)]=umdev_close;
	s.syscall[uscno(__NR_stat)]=umdev_stat;
	s.syscall[uscno(__NR_lstat)]=umdev_lstat;
	s.syscall[uscno(__NR_fstat)]=umdev_fstat;
#if !defined(__x86_64__)
	s.syscall[uscno(__NR_stat64)]=umdev_stat64;
	s.syscall[uscno(__NR_lstat64)]=umdev_lstat64;
	s.syscall[uscno(__NR_fstat64)]=umdev_fstat64;
#endif
	s.syscall[uscno(__NR_access)]=umdev_access;
	s.syscall[uscno(__NR_lseek)]=umdev_lseek;
#if ! defined(__x86_64__)
	s.syscall[uscno(__NR__llseek)]=umdev__llseek;
#endif
	//s.syscall[uscno(__NR_mknod)]=umdev_mknod;
	s.syscall[uscno(__NR_chown)]=umdev_chown;
	s.syscall[uscno(__NR_fchown)]=fchown;
	s.syscall[uscno(__NR_chmod)]=umdev_chmod;
	//s.syscall[uscno(__NR_fchmod)]=fchmod;
	s.syscall[uscno(__NR_fsync)]=umdev_fsync; 
	//s.syscall[uscno(__NR__newselect)]=umdev_select;
	s.syscall[uscno(__NR_ioctl)]=umdev_ioctl; 
	s.select_register=umdev_select_register;
	add_service(&s);
}

static void
__attribute__ ((destructor))
fini (void)
{
	free(s.syscall);
	free(s.socket);
	foralldevicetabdo(contextclose);
	printf("umdev fini\n");
}

