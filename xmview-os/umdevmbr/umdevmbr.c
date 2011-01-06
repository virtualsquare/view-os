/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   UMDEVMBR: Virtual Device to access Disk Images
 *   (using the standard IBM-PC partition scheme based on MBR/Extended MBR)
 *
 *    Copyright (C) 2006  Renzo Davoli <renzo@cs.unibo.it>
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
#include "umdev.h"
#include <stdlib.h>
#include <errno.h>
#include <linux/fs.h>
#include <linux/hdreg.h>
#include <config.h>
#include <sys/ioctl.h>
#include "mbr.h"

//char readonly=0;

static int hdmbr_open(char type, dev_t device, struct dev_info *di)
{
	struct mbr *mbr=umdev_getprivatedata(di->devhandle);
	int partno=minor(device)-minor(umdev_getbasedev(di->devhandle));
	if (partno==0 || mbr->part[partno-1] != NULL)
		return 0;
	else
		return -ENODEV;
}

static int hdmbr_read(char type, dev_t device, char *buf, size_t len, loff_t pos, struct dev_info *di)
{
	struct mbr *mbr=umdev_getprivatedata(di->devhandle);
	int partno=minor(device)-minor(umdev_getbasedev(di->devhandle));
	int rv;
	if (partno==0) /* partno==0, the disk as a whole */ {
		rv=pread64(mbr->fd,buf,len,pos);
		return (rv<0)?-errno:rv;
	} else { /* access a partition */
		struct partition *partition=mbr->part[partno-1];
		if (partition) {
			if ((pos >> IDE_BLOCKSIZE_LOG) <= partition->LBAnoblocks) {
				pos += ((off_t) partition->LBAbegin) << IDE_BLOCKSIZE_LOG;
				rv=pread64(mbr->fd,buf,len,pos);
				return (rv<0)?-errno:rv;
			} else
				return 0;
		} else
			return -ENODEV;
	}
}

static int hdmbr_write(char type, dev_t device, const char *buf, size_t len, loff_t pos, struct dev_info *di)
{
	struct mbr *mbr=umdev_getprivatedata(di->devhandle);
	int partno=minor(device)-minor(umdev_getbasedev(di->devhandle));
	int rv;
	if (partno==0) /* partno==0, the disk as a whole */ {
		rv=pwrite64(mbr->fd,buf,len,pos);
		return (rv<0)?-errno:rv;
	} else { /* access a partition */
		struct partition *partition=mbr->part[partno-1];
		if (partition) {
			if ((pos >> IDE_BLOCKSIZE_LOG) <= partition->LBAnoblocks) {
				pos += ((off_t) partition->LBAbegin) << IDE_BLOCKSIZE_LOG;
				rv=pwrite64(mbr->fd,buf,len,pos);
				return (rv<0)?-errno:rv;
			} else
				return -EINVAL;
		} else
			return -ENODEV;
	}
}

static int hdmbr_release(char type, dev_t device, struct dev_info *di)
{
	return 0;
}

static loff_t hdmbr_lseek(char type, dev_t device, loff_t offset, int whence, loff_t pos, struct dev_info *di)
{
	loff_t rv;
	switch (whence) {
		case SEEK_SET:
			rv=offset;
			break;
		case SEEK_CUR:
			rv=pos+offset;
			break;
		case SEEK_END: {
										 struct mbr *mbr=umdev_getprivatedata(di->devhandle);
										 int partno=minor(device)-minor(umdev_getbasedev(di->devhandle));
										 if (partno==0)
											 rv=mbr->size + offset;
										 else { /* access a partition */
											 struct partition *partition=mbr->part[partno-1];
											 if (partition) 
												 rv=((partition->LBAnoblocks)<< IDE_BLOCKSIZE_LOG) +offset;
											 else
												 return -ENODEV;

										 }
									 }
			break;
	}
	if (rv<0) rv=0;
	return rv;
}

static int hdmbr_init(char type, dev_t device, char *path, unsigned long flags, char *args, struct umdev *devhandle)
{
	int fd=open(path,O_RDWR);
	if (fd < 0) 
		return -1;
	else {
		struct mbr *mbr=mbr_open(fd);
		if (mbr != NULL) {
			mode_t mode=umdev_getmode(devhandle);
			mode = (mode & ~S_IFMT) | S_IFBLK;
			umdev_setmode(devhandle, mode);
			umdev_setprivatedata(devhandle,mbr);
			umdev_setnsubdev(devhandle, IDE_MAXPART);
			return 0;
		} else
			return -1;
	}
}

static int hdmbr_fini(char type, dev_t device, struct umdev *devhandle)
{
	struct mbr *mbr=umdev_getprivatedata(devhandle);
	mbr_close(mbr);
	return 0;
}

static int hdmbr_ioctl(char type, dev_t device, int req, void * arg, struct dev_info *di)
{
	struct mbr *mbr=umdev_getprivatedata(di->devhandle);
	switch (req) {
		/*case BLKROSET: if (*(int *)arg != 0)
										 readonly=1;
									 break;
		case BLKROGET: *(int *)arg = readonly;
									 break;*/
		case BLKSSZGET: *(int *)arg = IDE_BLOCKSIZE;
										break;
		case BLKRRPART: mbr_reread(mbr);
										break;
		case BLKGETSIZE: {
											 int partno=minor(device)-minor(umdev_getbasedev(di->devhandle));
											 if (partno==0)
												 *(int *)arg = (mbr->size >> IDE_BLOCKSIZE_LOG);
											 else { /* access a partition */
												 struct partition *partition=mbr->part[partno-1];
												 if (partition) 
													 *(int *)arg = (partition->LBAnoblocks) << IDE_BLOCKSIZE_LOG;
												 else
													 return -ENODEV;
											 }
										 }
										 break;
		case BLKGETSIZE64: {
												 int partno=minor(device)-minor(umdev_getbasedev(di->devhandle));
												 if (partno==0)
													 *(long long *)arg = mbr->size;
												 else { /* access a partition */
													 struct partition *partition=mbr->part[partno-1];
													 if (partition) 
														 *(long long *)arg = (partition->LBAnoblocks) << IDE_BLOCKSIZE_LOG;
													 else
														 return -ENODEV;
												 }
											 }
											 break;
		case HDIO_GETGEO: {
												struct hd_geometry *hdg = arg;
												*hdg=mbr->geometry;
											}
										 break;
		default: return -EINVAL;
	}
	return 0;
}

static int hdmbr_ioctl_params(char type, dev_t device, int req, struct umdev *devhandle)
{
	switch (req) {
		/*case BLKROSET: return (sizeof(int) | IOCTL_R);
		case BLKROGET: return (sizeof(int) | IOCTL_W);*/
		case BLKSSZGET: return (sizeof(int) | IOCTL_W);
		case BLKRRPART: return 0;
		case BLKGETSIZE: return (sizeof(int) | IOCTL_W);
		case BLKGETSIZE64: return (sizeof(long long) | IOCTL_W);
		case HDIO_GETGEO: return (sizeof(struct hd_geometry) | IOCTL_W);
		default: return 0;
	}
}

struct umdev_operations umdev_ops={
	.open=hdmbr_open,
	.read=hdmbr_read,
	.write=hdmbr_write,
	.release=hdmbr_release,
	.lseek=hdmbr_lseek,
	.init=hdmbr_init,
	.fini=hdmbr_fini,
	.ioctl=hdmbr_ioctl,
	.ioctlparms=hdmbr_ioctl_params,
};


