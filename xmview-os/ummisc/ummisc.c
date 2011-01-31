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

#ifndef __UMMISC_DEBUG_LEVEL__
#define __UMMISC_DEBUG_LEVEL__ 0
#endif

#ifdef __UMMISC_DEBUG__
#define PRINTDEBUG(level,args...) printdebug(level, __FILE__, __LINE__, __func__, args)
#else
#define PRINTDEBUG(level,args...)
#endif

static struct service s;
VIEWOS_SERVICE(s)

struct ummisc {
	char *path;
	int pathlen;
	void *dlhandle;
	fd_set scset;
	struct ht_elem *scht;
	struct ummisc_operations *ummisc_ops;
	void *private_data;
};

struct fileinfo {
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

void *misc_getdl(struct ummisc *mh)
{
	return mh->dlhandle;
}

int misc_check_sc(int type, void *arg, int arglen,
		struct ht_elem *ht)
{
	struct ummisc *mh=ht_get_private_data(ht);
	int *pscno=arg;
	int scno=*pscno;
	return FD_ISSET(scno,&(mh->scset));
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
	for (c=0;(c=*s2-*s1)==0 && *s1 && *s2;s1++,s2++)
		;
	if (*s1 == *s2 || *s1 == '/' || *s2 == '/')
		return 0;
	else
		return c;
}

static struct fsentry *recsearch(struct fsentry *fsdir,struct fsentry *fse,char *path)
{
	//printk("%p %p %s\n",fsdir,fse,path);
	if (*path == 0)
		return(fsdir);
	else{
		if (*path == '/')
			path++;
		if (fse==NULL || fse->name==NULL)
			return NULL;
		else {
			//printk("|%s|%s| %d\n",fse->name,path,strpathcmp(fse->name,path));
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
	//struct ummisc *mh = searchmisc(path,SUBSTR);
	struct ummisc *mh = um_mod_get_private_data();
	assert(mh);
	char *upath=unwrap(mh,path);
	//printk("open |%s| %d\n",upath,*upath);
	struct fsentry *fse=searchentry(mh,upath);
	//printk("ummisc_open %s %p\n",upath,fse);
	if (fse != NULL) {
		int fd = addfiletab(sizeof(struct fileinfo));
		struct fileinfo *ft=getfiletab(fd);
		ft->pos = 0;
		ft->flags = flags & ~(O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC);
		ft->path=strdup(upath);
		//printk("%d %lld %s\n",fd,ft->pos,ft->path);
		ft->fse=fse;
		ft->ummisc=mh;
		/* is a dir, root is always a dir! */
		if (fse->subdir != NULL || *upath==0) {
			if (fse->subdir==NULL)
				fse->subdir=nullroot;
			ft->buf = NULL;
			ft->size = 0;
		} else {
			ft->buf = calloc(MISCFILESIZE,1);
			assert(ft->buf != NULL);
			ft->size=fse->getputfun(UMMISC_GET,ft->buf,MISCFILESIZE,mh,
					ft->fse->tag,ft->path);
			if (flags & O_TRUNC) ft->size=0;
			if (flags & O_APPEND) ft->pos=ft->size;
		}
		return fd;
	} else {
		errno=ENOENT;
		return -1;
	}
}

static long ummisc_close(int fd)
{
	struct fileinfo *ft=getfiletab(fd);

	struct ummisc *mh = ft->ummisc;
	//printk("close %s\n",ft->path);
	if (ft->fse->getputfun != NULL &&
			(ft->flags & O_ACCMODE) != 0) { /*O_WRONLY or O_RDWR */
		ft->fse->getputfun(UMMISC_PUT,ft->buf,ft->size,mh,
				ft->fse->tag,ft->path);
	}
	if (ft->buf != NULL)
		free(ft->buf);
	free(ft->path);
	delfiletab(fd);
	return 0;
}

static long ummisc_read(int fd, char *buf, size_t count)
{
	int rv;
	struct fileinfo *ft=getfiletab(fd);
	//printk("READIN %d c%d p%lld s%lld \n",rv,
	//count, ft->pos, ft->size);
	for (rv=0; rv< count; rv++) {
		if (ft->pos > ft->size)
			break;
		if (ft->buf[ft->pos] == 0)
			break;
		buf[rv]=ft->buf[ft->pos];
		ft->pos++;
	}
	//printk("READ %d c%d p%lld s%lld %s\n",rv,
	//	count, ft->pos, ft->size, buf);
	return rv;
}

static long ummisc_write(int fd, char *buf, size_t count)
{
	int rv;
	struct fileinfo *ft=getfiletab(fd);
	for (rv=0; rv< count; rv++) {
		if (ft->pos >= MISCFILESIZE) /* it keeps one char for \0 */
			break;
		ft->buf[ft->pos]=buf[rv];
		ft->pos++;
	}
	if (ft->pos > ft->size)
		ft->size=ft->pos;
	return rv;
}

static void setstat64(struct stat64 *buf64, int isdir)
{
	memset(buf64,0,sizeof(struct stat64));
	if (isdir)
		buf64->st_mode=S_IFDIR | 0555;
	else
		buf64->st_mode=S_IFREG | 0666;
	buf64->st_size=MISCFILESIZE;
}

static long ummisc_lstat64(char *path, struct stat64 *buf64)
{
	//struct ummisc *mh = searchmisc(path,SUBSTR);
	struct ummisc *mh = um_mod_get_private_data();
	assert(mh);
	char *upath=unwrap(mh,path);
	struct fsentry *fse=searchentry(mh,upath);
	//printk("stat64 %s %p\n",path,fse);
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
	//struct ummisc *mh = searchmisc(path,SUBSTR);
	struct ummisc *mh = um_mod_get_private_data();
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
	struct fileinfo *ft=getfiletab(fd);
	switch (whence) {
		case SEEK_SET: ft->pos=offset; break;
		case SEEK_CUR: ft->pos+=offset; break;
		case SEEK_END: ft->pos=strlen(ft->buf)+offset; break;
	}
	if (ft->pos < 0) ft->pos=0;
	return ft->pos;
}

static long dirsize(struct fsentry *fsdir)
{
	int size=0;
	if (fsdir != NULL) {
		while (fsdir->name != NULL) {
			//printk("dirsize add %s %d\n",fsdir->name,WORDALIGN(SIZEDIRENT64NONAME+strlen(fsdir->name)+1));
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
			//printk("dirpop add %s %d\n",fsdir->name,WORDALIGN(SIZEDIRENT64NONAME+strlen(fsdir->name)+1));
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
	struct fileinfo *ft=getfiletab(fd);
	if (ft->fse->subdir == NULL) {
		errno=ENOTDIR;
		return -1;
	} else {
		int rv=0;
		struct dirent64 *this;
		if (ft->buf==NULL) {
			ft->size=dirsize(ft->fse->subdir);
			//printk("ummisc_getdents64 size=%d\n",ft->size);
			ft->buf=malloc(ft->size);
			assert(ft->buf != NULL);
			dirpopulate(ft->fse->subdir,ft->buf);
			//printk("ummisc_dirpopulate size=%d\n",ft->size);
		}
		while (rv+ft->pos < ft->size) {
			this=(struct dirent64 *)(ft->buf+ft->pos+rv);
			if (rv+ft->pos > ft->size)
				break;
			if (rv+this->d_reclen > count)
				break;
			rv+=this->d_reclen;
		}
		memcpy((char*) dirp, ft->buf + ft->pos, rv);
		ft->pos += rv;
		//printk("getdents64 returns %d\n",rv);
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
		printk("%s\n",dlerror());
		if(dlhandle != NULL)
			dlclose(dlhandle);
		errno=ENODEV;
		return -1;
	} else {
		struct ummisc *new = (struct ummisc *) malloc(sizeof(struct ummisc));
		struct stat64 *s64;
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
		new->scht=ht_tab_add(CHECKSC,NULL,0,&s,misc_check_sc,new);
		ht_tab_pathadd(CHECKPATH,source,target,filesystemtype,mountflags,data,&s,0,NULL,new);
		return 0;
	}
}

static void ummisc_umount_internal(struct ummisc *mh, int flags)
{
	ht_tab_invalidate(mh->scht);
	ht_tab_invalidate(um_mod_get_hte());
	if (mh->ummisc_ops->fini) 
		mh->ummisc_ops->fini(mh);
	free(mh->path);
	free(mh);
}

static long ummisc_umount2(char *target, int flags)
{
	struct ummisc *mh = um_mod_get_private_data();
	if (mh == NULL) {
		errno=EINVAL;
		return -1;
	} else {
		struct ht_elem *scht=mh->scht;
		ummisc_umount_internal(mh, flags);
		ht_tab_del(scht);
		ht_tab_del(um_mod_get_hte());
		return 0;
	}
}

static void ummisc_destructor(int type,struct ht_elem *mp)
{
	switch (type) {
		case CHECKPATH:
			um_mod_set_hte(mp);
			ummisc_umount_internal(um_mod_get_private_data(), MNT_FORCE);
	}
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
	else
		return NULL;
}

	static void
	__attribute__ ((constructor))
init (void)
{
	printk(KERN_NOTICE "ummisc init\n");
	s.name="ummisc";
	s.description="virtual miscellaneous (time, uname, uid/gid, ...)";
	s.destructor=ummisc_destructor;
	s.syscall=(sysfun *)calloc(scmap_scmapsize,sizeof(sysfun));
	s.socket=(sysfun *)calloc(scmap_sockmapsize,sizeof(sysfun));
	SERVICESYSCALL(s, mount, ummisc_mount);
	SERVICESYSCALL(s, umount2, ummisc_umount2);
	SERVICESYSCALL(s, open, ummisc_open);
	SERVICESYSCALL(s, read, ummisc_read);
	SERVICESYSCALL(s, write, ummisc_write);
	SERVICESYSCALL(s, close, ummisc_close);
	SERVICESYSCALL(s, lstat64, ummisc_lstat64);
	SERVICESYSCALL(s, fcntl, ummisc_fcntl64);
	SERVICESYSCALL(s, fsync, ummisc_fsync);
	SERVICESYSCALL(s, access, ummisc_access);
	SERVICESYSCALL(s, lseek, ummisc_lseek);
	SERVICESYSCALL(s, getdents64, ummisc_getdents64);

	initmuscno(&s);
}

	static void
	__attribute__ ((destructor))
fini (void)
{
	free(s.syscall);
	free(s.socket);
	finimuscno();
	printk(KERN_NOTICE "ummisc fini\n");
}
