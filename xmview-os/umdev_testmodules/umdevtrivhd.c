#include <stdio.h>
#include <string.h>
#include "umdev.h"
#include "stdlib.h"
#include <errno.h>
#include <linux/fs.h>
#include <linux/hdreg.h>

#define STD_SIZE 64*1024
#define STD_SECTORSIZE 512
char *testdisk;
char readonly=0;
unsigned long long hd_size;
struct hd_geometry hd_geom;

static int hd_open(char type, dev_t device, struct dev_info *di)
{
}

static int hd_read(char type, dev_t device, char *buf, size_t len, loff_t pos, struct dev_info *di)
{
	loff_t rlen;
	if (pos > hd_size) pos=hd_size;
	if (pos+len <= hd_size) 
		rlen=len;
	else
		rlen=hd_size-pos;
	memcpy(buf,testdisk+pos,rlen);
	return rlen;
}

static int hd_write(char type, dev_t device, const char *buf, size_t len, loff_t pos, struct dev_info *di)
{
	loff_t rlen;
	if (pos > hd_size) pos=hd_size;
	if (pos+len <= hd_size)
		rlen=len;
	else
		rlen=hd_size-pos;
	memcpy(testdisk+pos,buf,rlen);
	return rlen;
}

static int hd_release(char type, dev_t device, struct dev_info *di)
{
}

static loff_t hd_lseek(char type, dev_t device, loff_t offset, int whence, loff_t pos, struct dev_info *di)
{
	loff_t rv;
	switch (whence) {
		case SEEK_SET:
			rv=offset;
			break;
		case SEEK_CUR:
			rv=pos+offset;
			break;
		case SEEK_END:
			rv=hd_size+offset;
			break;
	}
	if (rv<0) rv=0;
	if (rv>hd_size) rv=hd_size;
	return rv;
}

static int hd_init(char type, dev_t device, char *path, unsigned long flags, char *args,struct umdev *devhandle)
{
	hd_size=STD_SIZE;
	hd_geom.start=0;
	if (hd_size == (unsigned int) hd_size) {
		hd_geom.heads=16;
		hd_geom.sectors=16;
		hd_geom.cylinders=(hd_size+(hd_geom.heads*hd_geom.sectors)-1)/(hd_geom.heads*hd_geom.sectors);
	} else {
		hd_geom.heads=128;
		hd_geom.sectors=128;
		hd_geom.cylinders=(hd_size+(hd_geom.heads*hd_geom.sectors)-1)/(hd_geom.heads*hd_geom.sectors);
	}
	hd_size=hd_geom.heads*hd_geom.sectors*hd_geom.cylinders;
	if (!testdisk) {
		testdisk=malloc(hd_size * STD_SECTORSIZE);
	}
	return 0;
}

static int hd_ioctl(char type, dev_t device, int req, void * arg, struct dev_info *di)
{
	switch (req) {
		case BLKROSET: if (*(int *)arg != 0)
										 readonly=1;
									 break;
		case BLKROGET: *(int *)arg = readonly;
									 break;
		case BLKSSZGET: *(int *)arg = STD_SECTORSIZE;
										break;
		case BLKRRPART: break;
		case BLKGETSIZE: *(int *)arg = hd_size;
										 break;
		case BLKGETSIZE64: *(long long *)arg = hd_size;
											 break;
		case HDIO_GETGEO: {
												struct hd_geometry *hdg = arg;
												*hdg=hd_geom;
											}
										 break;
		default: return -EINVAL;
	}
	return 0;
}

static int hd_ioctl_params(char type, dev_t device, int req, struct umdev *devhandle)
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
	.open=hd_open,
	.read=hd_read,
	.write=hd_write,
	.release=hd_release,
	.lseek=hd_lseek,
	.init=hd_init,
	.ioctl=hd_ioctl,
	.ioctlparms=hd_ioctl_params,
};


