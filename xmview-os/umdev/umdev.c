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
#include <linux/unistd.h>
#include <stdarg.h>
#include <stdint.h>
#include <sys/types.h>
#include <config.h>
#include "module.h"
#include "libummod.h"
#include "umdev.h"

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
VIEWOS_SERVICE(s)

static struct ht_elem *service_ht;

struct umdev {
	char *path;
	void *dlhandle;
	struct timestamp tst;
	dev_t dev;
	mode_t mode;
	uid_t uid;
	gid_t gid;
	int nsubdev;
	struct umdev_operations *devops;	
	int inuse;
	unsigned long flags;
	struct ht_elem *devht;
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

static int umdev_confirm(int type, void *arg, int arglen, struct ht_elem *ht)
{
	char *path=arg;
	struct umdev *fc=ht_get_private_data(ht);
	char *suffix=path+strlen(fc->path);
	//fprint2("umdev_confirm path %s suffix %s\n",path,suffix);
	int sub=atoi(suffix);
	if (sub <= fc->nsubdev)
		return 1;
	else
		return 0;
}

static int umdev_confirm_dev(int type, void *arg, int arglen, struct ht_elem *ht)
{
	dev_t *dev=arg;
	struct umdev *fc=ht_get_private_data(ht);
	if (major(fc->dev) == major(*dev) &&
			(minor(fc->dev) == -1 ||
			 (minor(fc->dev) <= minor(*dev) &&
				minor(fc->dev)+fc->nsubdev >= minor(*dev))))
		return 1;
	else
		return 0;
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
			*dev=makedev(major(umdev->dev),minor(umdev->dev)+atoi(path+strlen(umdev->path)));
		else
			*dev= umdev->dev;
	}
	mode= umdev->mode;
	//fprint2("SET_DEV %s %x %d %d\n",path,mode,major(*dev),minor(*dev));
	return mode2char(mode);
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
	minx=minor(fc->dev);
	fc->dev=makedev(majx,minx);
}

static void minorfun(char *s,struct umdev *fc)
{
	int majx,minx;
#ifdef DEBUGUMDEVARGS
	fprint2("MIN %s\n",s);
#endif
	majx=major(fc->dev);
	if (strcmp(s,"any")==0)
		minx = -1;
	else
		minx=atoi(s);
	fc->dev=makedev(majx,minx);
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
		new->dev = 0;
		if (s64) {
			new->dev = s64->st_rdev;
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
			if (umdev_ops->init(mode2char(new->mode),new->dev,source,
						mountflags,data?data:"", new) < 0) {
				deldevicetab(new);
				free(new->path);
				free(new);
				errno=EINVAL;
				return -1;
			}
		}
		ht_tab_pathadd(CHECKPATH,source,target,filesystemtype,mountflags,data,&s,1,umdev_confirm,new);
		new->devht=NULL;
		if (new->dev) {
			if (S_ISCHR(new->mode))
				new->devht=ht_tab_add(CHECKCHRDEVICE,NULL,0,&s,umdev_confirm_dev,new);
			else if (S_ISBLK(new->mode))
				new->devht=ht_tab_add(CHECKBLKDEVICE,NULL,0,&s,umdev_confirm_dev,new);
		}
		return 0;
	}
}

static void umdev_umount_internal(struct umdev *fc,int flags) {
	char *target=fc->path;
	ht_tab_invalidate(um_mod_get_hte());
	if (fc->devht)
		ht_tab_invalidate(fc->devht);
	if (fc->flags & UMDEV_DEBUG)
		fprint2("UMOUNT => path:%s flag:%d\n",target, flags);
	if (fc->devops->fini)
		fc->devops->fini(mode2char(fc->mode),fc->dev,fc);
	free(fc->path);
	dlclose(fc->dlhandle);
	free(fc);
}

static long umdev_umount2(char *target, int flags)
{
	struct umdev *fc;
	fc = um_mod_get_private_data();
	if (fc == NULL) {
		errno=EINVAL;
		return -1;
	} else if (fc->inuse){
		/* TODO FORCE flag */
		errno=EBUSY;
		return -1;
	} else {
		struct ht_elem *devht=fc->devht;
		umdev_umount_internal(fc,flags);
		ht_tab_del(um_mod_get_hte());
		if (devht)
			ht_tab_del(devht);
		return 0;
	}
}

static void umdev_destructor(int type,struct ht_elem *mp)
{
	switch (type) {
		case CHECKPATH:
			um_mod_set_hte(mp);
			umdev_umount_internal(um_mod_get_private_data(), MNT_FORCE);
	}
}

#define TRUE 1
#define FALSE 0

static int alwaysfalse()
{
	return FALSE;
}

static long umdev_ioctlparms(int fd,int req)
{
	struct fileinfo *ft=getfiletab(fd);
	if (ft->umdev->devops->ioctlparms) {
		struct dev_info di;
		di.fh = ft->fh;
		di.flags = 0;
		di.devhandle=ft->umdev;
		return ft->umdev->devops->ioctlparms(
				ft->type, ft->device, req, ft->umdev);
	} else
		return 0;
}

static long umdev_open(char *path, int flags, mode_t mode)
{
	struct umdev *fc = um_mod_get_private_data();
	struct dev_info di;
	int fd = addfiletab(sizeof(struct fileinfo));
	struct fileinfo *ft=getfiletab(fd);
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
	ft->count = 0;
	ft->pos = 0;
	//ft->size = buf.st_size; /* SIZE OF device? */
	di.flags = flags & ~(O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC);
	di.fh = 0;
	di.devhandle=fc;

	ft->type=set_dev(&ft->device,fc,path);
	ft->umdev=fc;
	if (fc->devops->open)
		rv = fc->devops->open(ft->type, ft->device, &di);
	else
		rv=0;
	ft->fh=di.fh;

	if (rv < 0)
	{
		if (fc->flags & UMDEV_DEBUG) 
			fprint2("OPEN[%d: %c(%d,%d)] ERROR => path:%s flags:0x%x\n",
					fd, ft->type, major(ft->device), minor(ft->device), path, flags);	
		delfiletab(fd);
		errno = -rv;
		return -1;
	} else {
		ft->count += 1;
		if (fc->flags & UMDEV_DEBUG) 
			fprint2("OPEN[%d: %c(%d:%d)] => path:%s flags:0x%x\n",
					fd, ft->type, major(ft->device), minor(ft->device), path, flags);
		fc->inuse++;
		return fd;
	}
}

static long umdev_close(int fd)
{
	int rv;
	struct fileinfo *ft=getfiletab(fd);

	struct dev_info di;
	di.fh = ft->fh;
	di.flags = ft->umdev->flags;
	di.devhandle=ft->umdev;
	if (ft->umdev->flags & UMDEV_DEBUG) 
		fprint2("CLOSE[%d %c(%d:%d)] %p\n",fd,
				ft->type, major(ft->device), minor(ft->device),ft);
	ft->count--;
	PRINTDEBUG(10,"->CLOSE %c(%d:%d) %d\n",
			ft->type, major(ft->device), minor(ft->device), ft->count);
	if (ft->count == 0) {			 
		ft->umdev->inuse--;
		if (ft->umdev->devops->release)
			rv=ft->umdev->devops->release(ft->type, ft->device, &di);
		else
			rv=0;
		if (ft->umdev->flags & UMDEV_DEBUG) 
			fprint2("RELEASE[%d %c(%d:%d)] => flags:0x%x rv=%d\n",
					fd, ft->type, major(ft->device), minor(ft->device), ft->umdev->flags,rv);
		delfiletab(fd);
	}
	if (rv<0) {
		errno= -rv;
		return -1;
	} else {
		return rv;
	}
}

static long umdev_read(int fd, void *buf, size_t count)
{
	int rv;
	struct fileinfo *ft=getfiletab(fd);
	struct dev_info di;
	di.fh = ft->fh;
	di.flags = 0;
	di.devhandle=ft->umdev;
	if (ft->umdev->devops->read)
		rv = ft->umdev->devops->read(
				ft->type, ft->device, 
				buf, count, ft->pos, &di);
	else
		rv= -EINVAL;
	if (ft->umdev->flags & UMDEV_DEBUG) 
		fprint2("READ[%d %c(%d:%d)] => count:%u\n",
				fd, ft->type, major(ft->device), minor(ft->device), count);
	if (rv<0) {
		errno= -rv;
		return -1;
	} else {
		ft->pos += rv;
		return rv;
	}
}

static long umdev_write(int fd, void *buf, size_t count)
{
	int rv;
	struct fileinfo *ft=getfiletab(fd);

	struct dev_info di;
	di.fh = ft->fh;
	di.flags = 0;
	di.devhandle=ft->umdev;
	if(ft->umdev->devops->write) {
		rv = ft->umdev->devops->write(
				ft->type, ft->device,
				buf, count, ft->pos, &di);
	} else
		rv= -EINVAL;
	if (ft->umdev->flags & UMDEV_DEBUG) 
		fprint2("WRITE[%d %c(%d:%d)] => count:0x%x\n",
				fd, ft->type, major(ft->device), minor(ft->device), count);

	PRINTDEBUG(10,"WRITE rv:%d\n",rv); 
	if (rv<0) {
		errno= -rv;
		return -1;
	} else {
		ft->pos += rv;
		return rv;
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

static long umdev_stat64(char *path, struct stat64 *buf64)
{
	dev_t device;
	int type;
	struct umdev *umdev=um_mod_get_private_data();
	type=set_dev(&device,umdev,path);
	return common_stat64(umdev,type,device,buf64);
}

static long umdev_lstat64(char *path, struct stat64 *buf64)
{
	dev_t device;
	int type;
	struct umdev *umdev=um_mod_get_private_data();
	type=set_dev(&device,umdev,path);
	return common_stat64(umdev,type,device,buf64);
}

static long umdev_access(char *path, int mode)
{
	struct umdev *fc=um_mod_get_private_data();
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
	 struct device_context *fc = um_mod_get_private_data();
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

	umdev=um_mod_get_private_data();
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

	umdev=um_mod_get_private_data();
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
	struct fileinfo *ft=getfiletab(fd);
	struct dev_info di;
	di.fh = ft->fh;
	di.flags = 0;
	di.devhandle=ft->umdev;
	if (ft->umdev->devops->fsync)
		rv = ft->umdev->devops->fsync(
				ft->type, ft->device, &di);
	else
		rv= 0;
	if (ft->umdev->flags & UMDEV_DEBUG) 
		fprint2("FSYNC[%d %c(%d:%d)] rv=%d\n",
				fd, ft->type, major(ft->device), minor(ft->device), rv);
	if (rv<0) {
		errno= -rv;
		return -1;
	} else {
		return rv;
	}
}

static loff_t umdev_x_lseek(int fd, off_t offset, int whence)
{
	struct fileinfo *ft=getfiletab(fd);
	if (ft->umdev->devops->lseek) {
		loff_t rv;
		struct dev_info di;
		di.fh = ft->fh;
		di.flags = 0;
		di.devhandle=ft->umdev;
		rv=ft->umdev->devops->lseek(
				ft->type, ft->device, offset, whence, ft->pos, &di);
		if (ft->umdev->flags & UMDEV_DEBUG) 
			fprint2("SEEK[%d %c(%d:%d)] OFF %lld WHENCE %d -> %lld\n",
					fd, ft->type, major(ft->device), minor(ft->device),
					offset,whence, rv);
		if (rv<0) {
			errno= -rv;
			return -1;
		} else {
			ft->pos=rv;
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
	struct fileinfo *ft=getfiletab(fd);
	if (ft->umdev->devops->ioctl) {
		struct dev_info di;
		di.fh = ft->fh;
		di.flags = 0;
		di.devhandle=ft->umdev;
		rv = ft->umdev->devops->ioctl(
				ft->type, ft->device,
				req, arg, &di);
	} else
		rv= -EINVAL;
	if (ft->umdev->flags & UMDEV_DEBUG) 
		fprint2("IOCTL[%d %c(%d:%d)] => req:%x\n",
				fd, ft->type, major(ft->device), minor(ft->device), req);
	if (rv<0) {
		errno= -rv;
		return -1;
	} else 
		return rv;
}

static void contextclose(struct umdev *fc)
{
	umdev_umount2(fc->path,MNT_FORCE);
}

static long umdev_event_subscribe(void (* cb)(), void *arg, int fd, int how)
{
	int rv=1;
	struct fileinfo *ft=getfiletab(fd);
	if (ft->umdev->devops->event_subscribe) {
		struct dev_info di;
		di.fh = ft->fh;
		di.flags = 0;
		di.devhandle=ft->umdev;
		rv = ft->umdev->devops->event_subscribe(
				ft->type, ft->device,
				cb, arg, how, &di);
	}
	if (rv<0) {
		errno= -rv;
		return -1;
	} else 
		return rv;
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
		return devhandle->dev;
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
	s.name="UMDEV";
	s.description="virtual devices";
	s.destructor=umdev_destructor;
	s.ioctlparms=umdev_ioctlparms;
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
	//SERVICESYSCALL(s, fstat64, umdev_fstat64);
#endif
	SERVICESYSCALL(s, access, umdev_access);
	SERVICESYSCALL(s, lseek, umdev_lseek);
#if ! defined(__x86_64__)
	SERVICESYSCALL(s, _llseek, umdev__llseek);
#endif
	//SERVICESYSCALL(s, mknod, umdev_mknod);
	SERVICESYSCALL(s, chown, umdev_chown);
	//SERVICESYSCALL(s, fchown, fchown);
	SERVICESYSCALL(s, chmod, umdev_chmod);
	//SERVICESYSCALL(s, fchmod, fchmod);
	SERVICESYSCALL(s, fsync, umdev_fsync); 
	//SERVICESYSCALL(s, _newselect, umdev_select);
	SERVICESYSCALL(s, ioctl, umdev_ioctl); 
	SERVICESYSCALL(s, pread64, umdev_pread64); 
	SERVICESYSCALL(s, pwrite64, umdev_pwrite64); 
	s.event_subscribe=umdev_event_subscribe;
	service_ht=ht_tab_add(CHECKFSTYPE,"umdev",0,&s,NULL,NULL);
}

	static void
	__attribute__ ((destructor))
fini (void)
{
	ht_tab_del(service_ht);
	free(s.syscall);
	free(s.socket);
	fprint2("umdev fini\n");
}

