/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   UMPROC: /proc management
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
#include <errno.h>
#include <pthread.h>
#include <sys/mount.h>

#include <config.h>
#include "module.h"

#ifndef __UMPROC_DEBUG_LEVEL__
#define __UMPROC_DEBUG_LEVEL__ 0
#endif

#ifdef __UMPROC_DEBUG__
#define PRINTDEBUG(level,args...) printdebug(level, __FILE__, __LINE__, __func__, args)
#else
#define PRINTDEBUG(level,args...)
#endif

#define PROC_MOUNTS 1
static struct service s;
VIEWOS_SERVICE(s)

static struct ht_elem *service_ht;

struct fileinfo {
	loff_t pos;        /* file offset */
	loff_t size;        /* file size */
	int flags;
	char *path;
	char *buf;
	struct umproc *umproc;
};

struct umproc {
	int tag;
};

struct umproc proc_mounts={PROC_MOUNTS};

static void fill_proc_mounts(struct fileinfo *ft)
{
	int size;
	FILE *f=open_memstream(&(ft->buf),&size);
	int fd=open("/proc/mounts",O_RDONLY);
	if (fd>=0) {
		char *buf[128];
		int n;
		while ((n=read(fd,buf,128)) > 0)
			fwrite(buf,n,1,f);
		close(fd);
	}
	ht_tab_getmtab(f);
	fclose(f);
	ft->size=size;
}

static long umproc_open(char *path, int flags, mode_t mode)
{
	struct umproc *mh = um_mod_get_private_data();
	assert(mh);
	int fd = addfiletab(sizeof(struct fileinfo));
	struct fileinfo *ft=getfiletab(fd);
	int rv;
	ft->pos = 0;
	ft->flags = flags & ~(O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC);
	ft->path=strdup(path);
	//printk("%d %lld %s\n",fd,ft->pos,ft->path);
	ft->umproc=mh;
	ft->buf=NULL;
	switch (mh->tag) {
		case PROC_MOUNTS:
			fill_proc_mounts(ft);
			break;
	}
	return fd;
}

static long umproc_close(int fd)
{
	int rv;
	struct fileinfo *ft=getfiletab(fd);
	if (ft->buf != NULL)
		free(ft->buf);
	free(ft->path);
	delfiletab(fd);
	return 0;
}

static long umproc_read(int fd, char *buf, size_t count)
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

static void setstat64(struct stat64 *buf64, int isdir)
{
	memset(buf64,0,sizeof(struct stat64));
	buf64->st_mode=S_IFREG | 0444;
}

static long umproc_stat64(char *path, struct stat64 *buf64)
{
	struct umproc *mh = um_mod_get_private_data();
	assert(mh);
	//printk("stat64 %s %p\n",path,fse);
	setstat64(buf64,0);
	return 0;
}

/* TODO management of fcntl */
static long umproc_fcntl64(int fd, int cmd, void *arg)
{
	//print2("umproc_fcntl64\n");
	errno=0;
	return 0;
}

static long umproc_fsync(int fd, int cmd, void *arg)
{
	//print2("umproc_fcntl64\n");
	errno=0;
	return 0;
}

static long umproc_access(char *path, int mode)
{
	//struct umproc *mh = searchproc(path,SUBSTR);
	struct umproc *mh = um_mod_get_private_data();
	assert(mh);
	return 0;
}

static loff_t umproc_lseek(int fd, off_t offset, int whence)
{
	int rv;
	struct fileinfo *ft=getfiletab(fd);
	switch (whence) {
		case SEEK_SET: ft->pos=offset; break;
		case SEEK_CUR: ft->pos+=offset; break;
		case SEEK_END: ft->pos=strlen(ft->buf)+offset; break;
	}
	if (ft->pos < 0) ft->pos=0;
}

void *viewos_init(char *args)
{
	return ht_tab_pathadd(CHECKPATH,"none","/proc/mounts","proc",0,"ro",&s,0,NULL,&proc_mounts);
}

void *viewos_fini(void *data)
{
	struct ht_elem *proc_ht=data;
	ht_tab_del(proc_ht);
}

	static void
	__attribute__ ((constructor))
init (void)
{
	printk("umproc init\n");
	s.name="umproc";
	s.description="/proc virtualization";
	s.syscall=(sysfun *)calloc(scmap_scmapsize,sizeof(sysfun));
	s.socket=(sysfun *)calloc(scmap_sockmapsize,sizeof(sysfun));
	SERVICESYSCALL(s, open, umproc_open);
	SERVICESYSCALL(s, read, umproc_read);
	SERVICESYSCALL(s, close, umproc_close);
	SERVICESYSCALL(s, stat64, umproc_stat64);
	SERVICESYSCALL(s, lstat64, umproc_stat64);
	SERVICESYSCALL(s, fcntl64, umproc_fcntl64);
	SERVICESYSCALL(s, fsync, umproc_fsync);
	SERVICESYSCALL(s, access, umproc_access);
	SERVICESYSCALL(s, lseek, umproc_lseek);

	//service_ht=ht_tab_pathadd(CHECKPATH,"none","/proc/mounts","proc",0,"ro",&s,0,NULL,&proc_mounts);
}

	static void
	__attribute__ ((destructor))
fini (void)
{
	ht_tab_del(service_ht);
	free(s.syscall);
	free(s.socket);
	printk("umproc fini\n");
}
