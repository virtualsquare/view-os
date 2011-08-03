/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   UMDEVVD: Virtual device for VDI, VMDK, VHD disks.
 *   (It requires the VBoxDD library at run time).
 *
 *    Copyright (C) 2010  Renzo Davoli <renzo@cs.unibo.it>
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

#include <limits.h>
#include <errno.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <dlfcn.h>
#include "umdev.h"
#include <linux/fs.h>
#include <linux/hdreg.h>
#include "module.h"

#define STD_SECTORSIZE 512
#define STD_SECTORSIZE_OFFSET_MASK 0x1ff

#ifdef __GNUC__
#define UNUSED __attribute__ ((unused))
#else
#define UNUSED
#endif

#define RT_BIT(bit)                             (1UL << (bit))
#define VD_OPEN_FLAGS_NORMAL        0
#define VD_OPEN_FLAGS_READONLY      RT_BIT(0)

typedef struct PDMMEDIAGEOMETRY
{
	uint32_t    cCylinders;
	uint32_t    cHeads;
	uint32_t    cSectors;
} PDMMEDIAGEOMETRY;

typedef int (* intfun)();
typedef uint64_t (* uint64_tfun)();

static int VBoxDD_count;
static void *VBoxDD_handle;
static intfun pVDFlush;
static intfun pVDRead;
static intfun pVDWrite;
static uint64_tfun pVDGetSize;
static intfun pVDCreate;
static intfun pVDOpen;
static intfun pVDClose;
static intfun pVDGetLCHSGeometry;

struct vddisk {
	void         *hdDisk;
	unsigned long flags;
	loff_t size;
};

static int load_VBoxDD()
{
	if (VBoxDD_count == 0) {
		VBoxDD_handle=dlopen("VBoxDD.so",RTLD_LAZY);
		if (VBoxDD_handle == NULL) {
			VBoxDD_handle=dlopen("/usr/lib/virtualbox/VBoxDD.so",RTLD_LAZY);
			if (VBoxDD_handle == NULL) {
				printk("VBoxDD library: not found\n");
				return -ENOENT;
			}
		}
		pVDFlush=dlsym(VBoxDD_handle,"VDFlush");
		pVDRead=dlsym(VBoxDD_handle,"VDRead");
		pVDWrite=dlsym(VBoxDD_handle,"VDWrite");
		pVDGetSize=dlsym(VBoxDD_handle,"VDGetSize");
		pVDCreate=dlsym(VBoxDD_handle,"VDCreate");
		pVDOpen=dlsym(VBoxDD_handle,"VDOpen");
		pVDClose=dlsym(VBoxDD_handle,"VDClose");
		pVDGetLCHSGeometry=dlsym(VBoxDD_handle,"VDGetLCHSGeometry");
		/*printk("%p %p %p %p %p %p %p %p \n",
				pVDFlush,
				pVDRead,
				pVDWrite,
				pVDGetSize,
				pVDCreate,
				pVDOpen,
				pVDClose,
				pVDGetLCHSGeometry);*/
	}
	VBoxDD_count++;
	return 0;
}

static void unload_VBoxDD()
{
	VBoxDD_count--;
	if (VBoxDD_count == 0) {
		dlclose(VBoxDD_handle);
		VBoxDD_handle=NULL;
	}
}

static int vd_open(char type, dev_t device, struct dev_info *di)
{
	return 0;
}

static int vd_release(char type, dev_t device, struct dev_info *di)
{
	struct vddisk *vddisk = umdev_getprivatedata(di->devhandle);
	if (vddisk) 
		pVDFlush(vddisk->hdDisk);
	return 0;
}

static inline int aligned_read(void *disk,loff_t pos, char *buf, size_t len)
{
	if ((pos & STD_SECTORSIZE_OFFSET_MASK)==0 && 
			(len & STD_SECTORSIZE_OFFSET_MASK)==0) {
		int ret = pVDRead(disk,pos,buf,len);
		return (ret >= 0) ? (signed) len : -EIO;
	} else {
		int rv;
		char tbuf[STD_SECTORSIZE];
		size_t toff,tlen,llen=len;
		toff=pos & STD_SECTORSIZE_OFFSET_MASK;
		if (toff) {
			rv=pVDRead(disk,pos - toff,tbuf,STD_SECTORSIZE);
			if (rv<0) return -EIO;
			tlen=STD_SECTORSIZE-toff;
			if (len<tlen) tlen=len;
			memcpy(buf,tbuf+toff,tlen);
			pos+=tlen;
			buf+=tlen;
			llen-=tlen;
		}
		tlen=llen & ~STD_SECTORSIZE_OFFSET_MASK;
		if (tlen) {
			rv=pVDRead(disk,pos,buf,tlen);
			if (rv<0) return -EIO;
			pos+=tlen;
			buf+=tlen;
			llen-=tlen;
		}
		if (llen > 0) {
			rv=pVDRead(disk,pos,tbuf,STD_SECTORSIZE);
			if (rv<0) return -EIO;
			memcpy(buf,tbuf,llen);
		}
		return len;
	}
}

static int vd_read(char type, dev_t device, char *buf, size_t len, loff_t pos, struct dev_info *di)
{
	struct vddisk *vddisk = umdev_getprivatedata(di->devhandle);
	if (vddisk) {
		loff_t size=vddisk->size;
		if (pos > size) pos=size;
		if (pos+len > size) len=size-pos;
		if (len > 0) 
			return aligned_read(vddisk->hdDisk,pos,buf,len);
		else
			return 0;
	}
	else
		return -ENODEV;
}

static inline int aligned_write(void *disk,loff_t pos, const char *buf, size_t len)
{
	if ((pos & STD_SECTORSIZE_OFFSET_MASK)==0 && 
			(len & STD_SECTORSIZE_OFFSET_MASK)==0) {
		int ret = pVDWrite(disk,pos,buf,len);
		return (ret >= 0) ? (signed) len : -EIO; 
	} else {
		int rv;
		char tbuf[STD_SECTORSIZE];
		size_t toff,tlen,llen=len;
		toff=pos & STD_SECTORSIZE_OFFSET_MASK;
		if (toff) {
			rv=pVDRead(disk,pos - toff,tbuf,STD_SECTORSIZE);
			if (rv<0) return -EIO;
			tlen=STD_SECTORSIZE-toff;
			if (len<tlen) tlen=len;
			memcpy(tbuf+toff,buf,tlen);
			rv=pVDWrite(disk,pos - toff,tbuf,STD_SECTORSIZE);
			if (rv<0) return -EIO;
			pos+=tlen;
			buf+=tlen;
			llen-=tlen;
		}
		tlen=llen & ~STD_SECTORSIZE_OFFSET_MASK;
		if (tlen) {
			rv=pVDWrite(disk,pos,buf,tlen);
			if (rv<0) return -EIO;
			pos+=tlen;
			buf+=tlen;
			llen-=tlen;
		}
		if (llen > 0) {
			rv=pVDRead(disk,pos,tbuf,STD_SECTORSIZE);
			if (rv<0) return -EIO;
			memcpy(tbuf,buf,llen);
			rv=pVDWrite(disk,pos,tbuf,STD_SECTORSIZE);
			if (rv<0) return -EIO;
		}
		return len;
	}
}

static int vd_write(char type, dev_t device, const char *buf, size_t len, loff_t pos, struct dev_info *di)
{
	struct vddisk *vddisk = umdev_getprivatedata(di->devhandle);
	if (vddisk) {
		loff_t size=vddisk->size;
		if (vddisk->flags & MS_RDONLY)
			return -EACCES;
		else {
			if (pos > size) pos=size;
			if (pos+len > size) len=size-pos;
			if (len > 0)
				return aligned_write(vddisk->hdDisk,pos,buf,len);
			else
				return 0;
		}
	} else
		return -ENODEV;
}

static loff_t vd_lseek(char type, dev_t device, loff_t offset, int whence, loff_t pos, struct dev_info *di)
{
	struct vddisk *vddisk = umdev_getprivatedata(di->devhandle);
	if (vddisk) {
		loff_t size=vddisk->size;
		loff_t rv;
		switch (whence) {
			case SEEK_SET:
				rv=offset;
				break;
			case SEEK_CUR:
				rv=pos+offset;
				break;
			case SEEK_END:
				rv=size+offset;
				break;
		}
		if (rv<0) rv=0;
		if (rv>size) rv=size;
		return rv;
	}
	else
		return -ENODEV;
}

// detects type of virtual image
int detectDiskType (char **disktype, char *filename) {
	char buf[8];
	int fd = open (filename, O_RDONLY);
	read (fd, buf, sizeof (buf));

	if (strncmp (buf, "conectix", 8) == 0)  *disktype = "VHD";
	else if (strncmp (buf, "VMDK", 4) == 0)  *disktype = "VMDK";
	else if (strncmp (buf, "KDMV", 4) == 0)  *disktype = "VMDK";
	else if (strncmp (buf, "<<<",  3) == 0)  *disktype = "VDI";
	else {
		printk("cannot autodetect disk type\n");
		close(fd);
		return -ENODEV;
	}
	printk ("disktype is %s\n", *disktype);
	close(fd);
	return 0;
}

static int vd_init(char type, dev_t device, char *path, unsigned long flags, char *args,struct umdev *devhandle)
{
	struct vddisk *vddisk;
	char *diskType = "auto";
	if (load_VBoxDD() != 0)
		return -ENODEV;
	vddisk=calloc(1,sizeof (struct vddisk));
	if (vddisk==NULL)
		return -ENOMEM;
	vddisk->flags=flags;
	if (pVDCreate(NULL, &vddisk->hdDisk) < 0) {
		printk("invalid initialisation of VD interface\n");
		goto enodev;
	}
	if (detectDiskType (&diskType, path) < 0)
		goto enodev;
	if (pVDOpen(vddisk->hdDisk,diskType, path, 
					(flags & MS_RDONLY)?VD_OPEN_FLAGS_READONLY:VD_OPEN_FLAGS_NORMAL, NULL) < 0) {
		printk("opening vbox image failed\n");
		goto enodev;
	}
	vddisk->size=pVDGetSize(vddisk->hdDisk, 0);
	mode_t mode=umdev_getmode(devhandle);
	mode = (mode & ~S_IFMT) | S_IFBLK;
	umdev_setmode(devhandle, mode);
	umdev_setprivatedata(devhandle,vddisk);
	return 0;
enodev:
	free(vddisk);
	return -ENODEV;
}

static int vd_fini(char type, dev_t device, struct umdev *devhandle)
{
	struct vddisk *vddisk = umdev_getprivatedata(devhandle);
	if (vddisk) {
		pVDClose(vddisk->hdDisk,0);
		free(vddisk);
		unload_VBoxDD();
	}
	return 0;
}

static int vd_ioctl(char type, dev_t device, int req, void * arg, struct dev_info *di)
{
	struct vddisk *vddisk = umdev_getprivatedata(di->devhandle);
	if (vddisk) {
		switch (req) {
			case BLKROGET: *(int *)arg = ((vddisk->flags & MS_RDONLY) != 0);
										 break;
			case BLKSSZGET: *(int *)arg = STD_SECTORSIZE;
											break;
			case BLKRRPART: break;
			case BLKGETSIZE: *(int *)arg = vddisk->size / STD_SECTORSIZE;
											 break;
			case BLKGETSIZE64: *(long long *)arg = vddisk->size;
												 break;
			case HDIO_GETGEO: {
													struct hd_geometry *hdg = arg;
													PDMMEDIAGEOMETRY vdgeom;
													pVDGetLCHSGeometry(vddisk->hdDisk,0,&vdgeom);
													/*char*/hdg->heads=vdgeom.cHeads;
													/*char*/hdg->sectors=vdgeom.cSectors;
													/*short*/hdg->cylinders=vdgeom.cCylinders;
													hdg->start=0;
												}
												break;
			default: return -EINVAL;
		}
		return 0;
	} else
		return -ENODEV;
}
static int vd_ioctl_params(char type, dev_t device, int req, struct dev_info *di)
{
	switch (req) {
		case BLKROSET: return (sizeof(int) | IOCTL_R);
		case BLKROGET: return (sizeof(int) | IOCTL_W);
		case BLKSSZGET: return (sizeof(int) | IOCTL_W);
		case BLKRRPART: return 0;
		case BLKGETSIZE: return (sizeof(int) | IOCTL_W);
		case BLKGETSIZE64: return (sizeof(long long) | IOCTL_W);
		case HDIO_GETGEO: return (sizeof(struct hd_geometry) | IOCTL_W);
		default: return 0;
	}
}

struct umdev_operations umdev_ops={
	.open=vd_open,
	.read=vd_read,
	.write=vd_write,
	.release=vd_release,
	.lseek=vd_lseek,
	.init=vd_init,
	.ioctl=vd_ioctl,
	.ioctlparms=vd_ioctl_params,
	.fini=vd_fini,
};

