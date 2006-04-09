#include <stdio.h>
#include <string.h>
#include "umdev.h"
#include "stdlib.h"

#define SIZE 100000000
char *testdisk;

static int hd_open(char type, dev_t device, struct dev_info *di)
{
}

static int hd_read(char type, dev_t device, char *buf, size_t len, loff_t pos, struct dev_info *di)
{
	loff_t rlen;
	if (pos > SIZE) pos=SIZE;
	if (pos+len <= SIZE) 
		rlen=len;
	else
		rlen=SIZE-pos;
	memcpy(buf,testdisk+pos,rlen);
	return rlen;
}

static int hd_write(char type, dev_t device, const char *buf, size_t len, loff_t pos, struct dev_info *di)
{
	loff_t rlen;
	if (pos > SIZE) pos=SIZE;
	if (pos+len <= SIZE)
		rlen=len;
	else
		rlen=SIZE-pos;
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
			rv=SIZE+offset;
			break;
	}
	if (rv<0) rv=0;
	if (rv>SIZE) rv=SIZE;
	return rv;
}

static int hd_init(char type, dev_t device, char *path, unsigned long flags, char *args)
{
	if (!testdisk) {
		testdisk=malloc(SIZE);
	}
	printf("INIT %p\n",testdisk);
	return 0;
}

struct umdev_operations umdev_ops={
	.open=hd_open,
	.read=hd_read,
	.write=hd_write,
	.release=hd_release,
	.lseek=hd_lseek,
	.init=hd_init,
};


