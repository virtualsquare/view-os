/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   UMDEVLOOP: Virtual loop device.
 *
 *    Copyright (C) 2012  Renzo Davoli <renzo@cs.unibo.it>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; version 2 of the License
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
#include <string.h>
#include <fcntl.h>
#include "umdev.h"
#include "stdlib.h"
#include <errno.h>
#include <linux/fs.h>
#include <linux/loop.h>
#include <config.h>

#define STD_NUNITS 7
#define LOX_FLAGS_PLUS 0x1

struct loop_unit {
	int fd;
	int count;
	struct loop_info64 info;
};

struct loop {
	char flags;
	int nunits;
	int mindevice;
	struct loop_unit **unit;
};

static int lo_open(char type, dev_t device, struct dev_info *di)
{
	struct loop *loop = umdev_getprivatedata(di->devhandle);
	if (loop) {
		int loopno=minor(device)-minor(umdev_getbasedev(di->devhandle))-loop->mindevice;
		if (loopno<0 || loopno >= loop->nunits)
			return -ENODEV;
		else if (loop->unit[loopno] == NULL)
			return 0;
		else {
			loop->unit[loopno]->count++;
			return 0;
		}
	}
	else
		return -ENODEV;
	return 0;
}

static int lo_read(char type, dev_t device, char *buf, size_t len, loff_t pos, struct dev_info *di)
{
	struct loop *loop = umdev_getprivatedata(di->devhandle);
	if (loop) {
		int loopno=minor(device)-minor(umdev_getbasedev(di->devhandle))-loop->mindevice;
		if (loopno<0 || loopno >= loop->nunits)
			return -ENODEV;
		else 
			if (loop->unit[loopno] == NULL)
			return 0;
		else {
			ssize_t rv=pread(loop->unit[loopno]->fd,
					buf, len, pos + loop->unit[loopno]->info.lo_offset);
			if (rv < 0)
				return -errno;
			else
				return rv;
		}
	}
	else
		return -ENODEV;
}

static int lo_write(char type, dev_t device, const char *buf, size_t len, loff_t pos, struct dev_info *di)
{
	struct loop *loop = umdev_getprivatedata(di->devhandle);
	if (loop) {
		int loopno=minor(device)-minor(umdev_getbasedev(di->devhandle))-loop->mindevice;
		if (loopno<0 || loopno >= loop->nunits)
			return -ENODEV;
		else
			if (loop->unit[loopno] == NULL)
				return -ENOSPC;
			else if (loop->unit[loopno]->info.lo_flags & LO_FLAGS_READ_ONLY)
				return -EROFS;
			else {
				ssize_t rv;
				if (loop->unit[loopno]->info.lo_sizelimit > 0 &&
						pos + len > loop->unit[loopno]->info.lo_sizelimit)
					len = loop->unit[loopno]->info.lo_sizelimit - pos;
				rv=pwrite(loop->unit[loopno]->fd,
						buf, len, pos + loop->unit[loopno]->info.lo_offset);
				if (rv < 0)
					return -errno;
				else
					return rv;
			}
	}
	else
		return -ENODEV;
}

static int lo_clr_fd(struct loop_unit **pthisunit);
static int lo_release(char type, dev_t device, struct dev_info *di)
{
	struct loop *loop = umdev_getprivatedata(di->devhandle);
	if (loop) { 
		int loopno=minor(device)-minor(umdev_getbasedev(di->devhandle))-loop->mindevice;
		if (loopno<0 || loopno >= loop->nunits)
			return -ENODEV;
		else 
			if (loop->unit[loopno] == NULL)
				return 0;
			else {
				loop->unit[loopno]->count--;
				//printk("AUTOCLEAR TEST %d\n",loop->unit[loopno]->count);
				if ((loop->unit[loopno]->info.lo_flags & LO_FLAGS_AUTOCLEAR)
						&&loop->unit[loopno]->count == 0) {
					//printk("AUTOCLEAR\n");
					lo_clr_fd(&loop->unit[loopno]);
				}
				return 0;
			}
	}             
	else
		return -ENODEV;
}

static loff_t lo_lseek(char type, dev_t device, loff_t offset, int whence, loff_t pos, struct dev_info *di)
{
	loff_t rv;
	loff_t sizelimit, cursize;
	struct loop *loop = umdev_getprivatedata(di->devhandle);
	int loopno=minor(device)-minor(umdev_getbasedev(di->devhandle))-loop->mindevice;
	if (loopno<0 || loopno >= loop->nunits)
		return -ENODEV;
	else 
		if (loop->unit[loopno] == NULL)
			sizelimit=cursize=0;
		else {
			sizelimit=loop->unit[loopno]->info.lo_sizelimit;
			if (sizelimit == 0) {
				struct stat buf;
				if (fstat(loop->unit[loopno]->fd, &buf) < 0)
					cursize=0;
				else
					cursize=buf.st_size;
			}
		}
	switch (whence) {
		case SEEK_SET:
			rv=offset;
			break;
		case SEEK_CUR:
			rv=pos+offset;
			break;
		case SEEK_END: 
			rv=cursize + offset;
			break;
	}
	if (rv<0) rv=0;
	if (sizelimit > 0 && rv > sizelimit)
		rv=sizelimit;
	return rv;
}

static void lo_plus(char *s,struct loop *lo)
{
	lo->flags |= LOX_FLAGS_PLUS;
}

static void lo_ndevs(char *s,struct loop *lo)
{
	if (s) {
		long ndevs=atoi(s);
		lo->nunits=ndevs;
	}
}

static struct devargitem umdevargtab[] = {
	  {"ndevs=", lo_ndevs},
	  {"plus", lo_plus},
};
#define UMDEVARGTABSIZE sizeof(umdevargtab)/sizeof(struct devargitem)
		
static int lo_init(char type, dev_t device, char *path, unsigned long flags, char *args,struct umdev *devhandle)
{
	struct loop *loop=calloc(1,sizeof (struct loop));
	if (loop) {
		if(args)
			devargs(args, umdevargtab, UMDEVARGTABSIZE, loop);
		if (loop->nunits == 0) loop->nunits=STD_NUNITS;
		mode_t mode=umdev_getmode(devhandle);
		mode = (mode & ~S_IFMT) | S_IFBLK;
		umdev_setmode(devhandle, mode);
		dev_t dev=umdev_getbasedev(devhandle);
		if (major(dev) == 0)
			umdev_setbasedev(devhandle,makedev(7,0));
		umdev_setprivatedata(devhandle,loop);
		loop->unit=calloc(loop->nunits,sizeof(struct loop_unit *));
		if (loop->unit == NULL) {
			free(loop);
			return -ENODEV;
		}
		if (loop->flags & LOX_FLAGS_PLUS) {
			char *looptest;
			int i;
			for (i = 0; i < 1024; i++) {
				int rv;
				asprintf(&looptest,"/dev/loop%d",i);
				rv=access(looptest, F_OK);
				free(looptest);
				if (rv < 0 && errno==ENOENT) {
					loop->mindevice=i;
					break;
				}
			}
		}
		//printk("MINDEVICE = %d\n", loop->mindevice);
		umdev_setsubdev(devhandle, loop->mindevice, loop->mindevice+loop->nunits);
		return 0;
	} else
		return -ENODEV;
}

static int lo_fini(char type, dev_t device, struct umdev *devhandle)
{
	struct loop *loop = umdev_getprivatedata(devhandle);
	if (loop) {
		free(loop);
	}
	return 0;
}

static int lo_set_fd(struct loop_unit **pthisunit, int fd, int loopno)
{
	struct loop_unit *thisunit=calloc(1,sizeof (struct loop_unit));
	char *procfile,path[PATH_MAX];
	struct stat statbuf;
	int symlinklen;
	if (thisunit==NULL)
		return -ENODEV;

	asprintf(&procfile, "/proc/%d/fd/%d",um_mod_getpid(),fd);
	/* it requires virtualization of /proc/pid/fd to support nested virtualization */
	symlinklen=readlink(procfile, path, PATH_MAX);
	if (symlinklen < 0) {
		free(procfile);
		free(thisunit);
		return -errno;
	} else
		path[symlinklen]=0;
	free(procfile);
	thisunit->fd=open(path, O_RDWR|O_LARGEFILE);
	if (thisunit->fd < 0) {
		free(thisunit);
		return -errno;
	}
	thisunit->count=1;
	fstat(thisunit->fd, &statbuf);
	thisunit->info.lo_device=statbuf.st_dev;
	thisunit->info.lo_inode=statbuf.st_ino;
	thisunit->info.lo_rdevice=statbuf.st_rdev;
	thisunit->info.lo_number=loopno;
	strncpy(thisunit->info.lo_file_name,path,LO_NAME_SIZE);
	*pthisunit=thisunit;
	return 0;
}

static int lo_clr_fd(struct loop_unit **pthisunit)
{
	struct loop_unit *thisunit=*pthisunit;
	if (thisunit->count > 1)
		return -EBUSY;
	close(thisunit->fd);
	free(thisunit);
	*pthisunit=NULL;
	return 0;
}

static int lo_get_status(struct loop_unit *thisunit, struct loop_info *info)
{
	info->lo_number=thisunit->info.lo_number;
	info->lo_device=thisunit->info.lo_device;
	info->lo_inode=thisunit->info.lo_inode;
	info->lo_rdevice=thisunit->info.lo_rdevice;
	info->lo_offset=thisunit->info.lo_offset;
	info->lo_encrypt_type=thisunit->info.lo_encrypt_type;
	info->lo_flags=thisunit->info.lo_flags;
	memcpy(info->lo_name,thisunit->info.lo_file_name,sizeof(info->lo_name));
	info->lo_init[0]=thisunit->info.lo_init[0];
	info->lo_init[1]=thisunit->info.lo_init[1];
	return 0;
}

static int lo_set_status(struct loop_unit *thisunit, struct loop_info *info)
{
	thisunit->info.lo_offset=info->lo_offset;
	thisunit->info.lo_encrypt_type=info->lo_encrypt_type;
	thisunit->info.lo_encrypt_key_size=info->lo_encrypt_key_size;
	thisunit->info.lo_flags=info->lo_flags;
	memcpy(thisunit->info.lo_encrypt_key,info->lo_encrypt_key,sizeof(thisunit->info.lo_encrypt_key));
	thisunit->info.lo_init[0]=info->lo_init[0];
	thisunit->info.lo_init[1]=info->lo_init[1];
	return 0;
}

static int lo_get_status64(struct loop_unit *thisunit, struct loop_info64 *info)
{
	info->lo_device=thisunit->info.lo_device;
	info->lo_inode=thisunit->info.lo_inode;
	info->lo_rdevice=thisunit->info.lo_rdevice;
	info->lo_offset=thisunit->info.lo_offset;
	info->lo_sizelimit=thisunit->info.lo_sizelimit;
	info->lo_number=thisunit->info.lo_number;
	info->lo_encrypt_type=thisunit->info.lo_encrypt_type;
	info->lo_flags=thisunit->info.lo_flags;
	memcpy(info->lo_file_name,thisunit->info.lo_file_name,sizeof(info->lo_file_name));
	memcpy(info->lo_crypt_name,thisunit->info.lo_crypt_name,sizeof(info->lo_crypt_name));
	memcpy(info->lo_init,thisunit->info.lo_init,sizeof(info->lo_init));
	return 0;
}

static int lo_set_status64(struct loop_unit *thisunit, struct loop_info64 *info)
{
	thisunit->info.lo_offset=info->lo_offset;
	thisunit->info.lo_sizelimit=info->lo_sizelimit;
	thisunit->info.lo_encrypt_type=info->lo_encrypt_type;
	thisunit->info.lo_encrypt_key_size=info->lo_encrypt_key_size;
	thisunit->info.lo_flags=info->lo_flags;
	memcpy(thisunit->info.lo_crypt_name,info->lo_crypt_name,sizeof(thisunit->info.lo_crypt_name));
	memcpy(thisunit->info.lo_encrypt_key,info->lo_encrypt_key,sizeof(thisunit->info.lo_encrypt_key));
	memcpy(thisunit->info.lo_init,info->lo_init,sizeof(thisunit->info.lo_init));
	return 0;
}

static int lo_ioctl(char type, dev_t device, int req, void * arg, struct dev_info *di)
{
	struct loop *loop = umdev_getprivatedata(di->devhandle);
	if (loop) {
		int loopno=minor(device)-minor(umdev_getbasedev(di->devhandle))-loop->mindevice;
		struct loop_unit *thisunit;
		//printk("lo_ioctl %x\n",req);
		if (loopno<0 || loopno >= loop->nunits)
			return -ENODEV;
		thisunit=loop->unit[loopno];
		switch (req) {
			case LOOP_SET_FD:
				if (thisunit != NULL)
					return -EBUSY;
				break;
			case LOOP_CLR_FD:
			case LOOP_SET_STATUS:
			case LOOP_GET_STATUS:
			case LOOP_SET_STATUS64:
			case LOOP_GET_STATUS64:
			//case LOOP_CHANGE_FD:
			//case LOOP_SET_CAPACITY:
				if (thisunit == NULL)
					return -ENXIO;
		}
		switch (req) {
			case LOOP_SET_FD: return lo_set_fd(&loop->unit[loopno], (int) arg, loopno);
			case LOOP_CLR_FD: return lo_clr_fd(&loop->unit[loopno]);
			case LOOP_SET_STATUS: return lo_set_status(thisunit, arg);
			case LOOP_GET_STATUS: return lo_get_status(thisunit, arg);
			case LOOP_SET_STATUS64: return lo_set_status64(thisunit, arg);
			case LOOP_GET_STATUS64: return lo_get_status64(thisunit, arg);
			//case LOOP_CHANGE_FD: return lo_change_fd(thisunit, (int) arg);
			//case LOOP_SET_CAPACITY: return lo_set_capacity(thisunit, arg);
			default: return -EINVAL;
							 return 0;
		}
	} else
		return -ENODEV;
}

static int lo_ioctl_params(char type, dev_t device, int req, struct dev_info *di)
{
	//printk("lo_ioctl_params %d\n",req);
	switch (req) {
		case LOOP_SET_FD: return 0;
		case LOOP_CLR_FD: return 0;
		case LOOP_SET_STATUS: return _IOW(0,0,struct loop_info);
		case LOOP_GET_STATUS: return _IOR(0,0,struct loop_info);
		case LOOP_SET_STATUS64: return _IOW(0,0,struct loop_info64);
		case LOOP_GET_STATUS64: return _IOR(0,0,struct loop_info64);
		//case LOOP_CHANGE_FD: return 0;
		//case LOOP_SET_CAPACITY: return 0;
		default: return 0;
	}
}

struct umdev_operations umdev_ops={
	.open=lo_open,
	.read=lo_read,
	.write=lo_write,
	.release=lo_release,
	.lseek=lo_lseek,
	.init=lo_init,
	.ioctl=lo_ioctl,
	.ioctlparms=lo_ioctl_params,
	.fini=lo_fini,
};


