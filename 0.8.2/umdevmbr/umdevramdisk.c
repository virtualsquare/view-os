#include <stdio.h>
#include <string.h>
#include "umdev.h"
#include "stdlib.h"
#include <errno.h>
#include <linux/fs.h>
#include <linux/hdreg.h>
#include <config.h>

#define STD_SIZE 64*1024
#define STD_SECTORSIZE 512

#define READONLY 1
#define MBR 2

struct ramdisk {
	char *diskdata;
	char flags;
	unsigned long long rd_size;
	struct hd_geometry rd_geom;
};

static int rd_open(char type, dev_t device, struct dev_info *di)
{
		return 0;
}

static int rd_read(char type, dev_t device, char *buf, size_t len, loff_t pos, struct dev_info *di)
{
	struct ramdisk *ramdisk = umdev_getprivatedata(di->devhandle);
	if (ramdisk) {
		loff_t size=ramdisk->rd_size*STD_SECTORSIZE;
		size_t rlen;
		if (pos > size) pos=size;
		if (pos+len <= size) 
			rlen=len;
		else
			rlen=size-pos;
		memcpy(buf,ramdisk->diskdata+pos,rlen);
		return rlen;
	}
	else
		return -ENODEV;
}

static int rd_write(char type, dev_t device, const char *buf, size_t len, loff_t pos, struct dev_info *di)
{
	struct ramdisk *ramdisk = umdev_getprivatedata(di->devhandle);
	if (ramdisk) {
		if (ramdisk->flags & READONLY)
			return -EACCES;
		else {
			loff_t size=ramdisk->rd_size*STD_SECTORSIZE;
			size_t rlen;
			if (pos > size) pos=size;
			if (pos+len <= size) 
				rlen=len;
			else
				rlen=size-pos;
			memcpy(ramdisk->diskdata+pos,buf,rlen);
			return rlen;
		}
	}
	else
		return -ENODEV;
}

static int rd_release(char type, dev_t device, struct dev_info *di)
{
	return 0;
}

static loff_t rd_lseek(char type, dev_t device, loff_t offset, int whence, loff_t pos, struct dev_info *di)
{
	struct ramdisk *ramdisk = umdev_getprivatedata(di->devhandle);
	if (ramdisk) {
		loff_t size=ramdisk->rd_size*STD_SECTORSIZE;
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

static void rd_setmbr(char *s,struct ramdisk *rd)
{
	rd->flags |= MBR;
}

static void rd_setsize(char *s,struct ramdisk *rd)
{
	if (s) {
		int len=strlen(s);
		long long size=atoi(s);
		switch (s[len-1]) {
			case 'k':
			case 'K': size *= 1024 / STD_SECTORSIZE; break;
			case 'm':
			case 'M': size *= 1024 * 1024 / STD_SECTORSIZE; break;
			case 'g':
			case 'G': size *= 1024 * 1024 * 1024 / STD_SECTORSIZE; break;
		}
		rd->rd_size=size;
	}
}

static struct devargitem umdevargtab[] = {
	  {"size=", rd_setsize},
	  {"mbr", rd_setmbr},
};
#define UMDEVARGTABSIZE sizeof(umdevargtab)/sizeof(struct devargitem)
		
static int rd_init(char type, dev_t device, char *path, unsigned long flags, char *args,struct umdev *devhandle)
{
	struct ramdisk *ramdisk=calloc(1,sizeof (struct ramdisk));
	if(args)
		    devargs(args, umdevargtab, UMDEVARGTABSIZE, ramdisk);
	if (ramdisk) {
		if (ramdisk->rd_size == 0)
			ramdisk->rd_size=STD_SIZE;
		ramdisk->rd_geom.start=0;
		if (ramdisk->rd_size == (unsigned int) ramdisk->rd_size) {
			ramdisk->rd_geom.heads=16;
			ramdisk->rd_geom.sectors=16;
			ramdisk->rd_geom.cylinders=(ramdisk->rd_size+(ramdisk->rd_geom.heads*ramdisk->rd_geom.sectors)-1)/(ramdisk->rd_geom.heads*ramdisk->rd_geom.sectors);
		} else {
			ramdisk->rd_geom.heads=128;
			ramdisk->rd_geom.sectors=128;
			ramdisk->rd_geom.cylinders=(ramdisk->rd_size+(ramdisk->rd_geom.heads*ramdisk->rd_geom.sectors)-1)/(ramdisk->rd_geom.heads*ramdisk->rd_geom.sectors);
		}
		ramdisk->rd_size=ramdisk->rd_geom.heads*ramdisk->rd_geom.sectors*ramdisk->rd_geom.cylinders;
		if (!ramdisk->diskdata) {
			ramdisk->diskdata=malloc(ramdisk->rd_size * STD_SECTORSIZE);
			if (!ramdisk->diskdata) {
				free(ramdisk);
				return -ENOMEM;
			}
		}
		mode_t mode=umdev_getmode(devhandle);
		mode = (mode & ~S_IFMT) | S_IFBLK;
		umdev_setmode(devhandle, mode);
		umdev_setprivatedata(devhandle,ramdisk);
	return 0;
	} else
		return -ENODEV;
}

static int rd_fini(char type, dev_t device, struct umdev *devhandle)
{
    struct ramdisk *ramdisk = umdev_getprivatedata(devhandle);
		if (ramdisk) {
			free(ramdisk->diskdata);
			free(ramdisk);
		}
		return 0;
}

static int rd_ioctl(char type, dev_t device, int req, void * arg, struct dev_info *di)
{
	struct ramdisk *ramdisk = umdev_getprivatedata(di->devhandle);
	if (ramdisk) {
		switch (req) {
			case BLKROSET: if (*(int *)arg != 0)
											 ramdisk->flags |= READONLY;
										 break;
			case BLKROGET: *(int *)arg = ((ramdisk->flags & READONLY) != 0);
										 break;
			case BLKSSZGET: *(int *)arg = STD_SECTORSIZE;
											break;
			case BLKRRPART: break;
			case BLKGETSIZE: *(int *)arg = ramdisk->rd_size * 
											    ((ramdisk->flags & MBR)?1:STD_SECTORSIZE);
											 break;
			case BLKGETSIZE64: *(long long *)arg = ramdisk->rd_size * STD_SECTORSIZE;
												 //printk("BLKGETSIZE64 %lld\n",*(long long *)arg);
												 break;
			case HDIO_GETGEO: {
													struct hd_geometry *hdg = arg;
													*hdg=ramdisk->rd_geom;
												}
												break;
			default: return -EINVAL;
		}
		return 0;
	} else
		return -ENODEV;
}

static int rd_ioctl_params(char type, dev_t device, int req, struct dev_info *di)
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
	.open=rd_open,
	.read=rd_read,
	.write=rd_write,
	.release=rd_release,
	.lseek=rd_lseek,
	.init=rd_init,
	.ioctl=rd_ioctl,
	.ioctlparms=rd_ioctl_params,
	.fini=rd_fini,
};


