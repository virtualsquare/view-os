#include <stdio.h>
#include "umdev.h"

static int null_open(char type, dev_t device, struct dev_info *di)
{
	printf("null_open %c %d %d flag %x\n",type,major(device),minor(device),di->flags);
	return 0;
}

static int null_read(char type, dev_t device, char *buf, size_t len, loff_t pos,struct dev_info *di)
{
	printf("null_read %c %d %d len %d\n",type,major(device),minor(device),len);
	return 0;
}

static int null_write(char type, dev_t device, const char *buf, size_t len, loff_t pos, struct dev_info *di)
{
	printf("null_write %c %d %d len %d\n",type,major(device),minor(device),len);
	return len;
}

static int null_release(char type, dev_t device, struct dev_info *di)
{
	printf("null_release %c %d %d flag %x\n",type,major(device),minor(device),di->flags);
	return 0;
}

struct umdev_operations umdev_ops={
	.open=null_open,
	.read=null_read,
	.write=null_write,
	.release=null_release,
};


