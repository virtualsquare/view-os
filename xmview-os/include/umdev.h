/*
 *     UMDEV: Virtual Device in Userspace
 *     Copyright (C) 2006  Renzo Davoli <renzo@cs.unibo.it>
 *
 *     This program can be distributed under the terms of the GNU GPLv2.
 *     See the file COPYING.LIB.
 */

#ifndef _UMDEV_H_
#define _UMDEV_H_
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>

#define IOCTLLENMASK      0x07ffffff
#define IOCTL_R           0x10000000
#define IOCTL_W           0x20000000

#define UMDEV_DEBUG       (1 << 29)

typedef void (* voidfun)(void *arg);

struct dev_info {
	/* user mode process handle
	 * um_x_getxxxx calls use this handle to get info from the calling
	 * process */
	void *umph;

	/* Open flags, available in open and release */
	int flags;

	/* File handle. It usually set up in open and then
	 * available for all other operations */
	uint64_t fh;
};

struct umdev_operations {
	int (*getattr) (char, dev_t, struct stat *);
	int (*fgetattr) (char, dev_t, struct stat *, struct dev_info *);
	int (*chmod) (char, dev_t, mode_t);
	int (*chown) (char, dev_t, uid_t, gid_t);
  int (*open) (char, dev_t, struct dev_info *);
	int (*read) (char, dev_t, char *, size_t, loff_t, struct dev_info *);
	int (*write) (char, dev_t, const char *, size_t, loff_t, struct dev_info *);
	loff_t (*lseek) (char, dev_t, loff_t, int, loff_t, struct dev_info *);
	int (*fsync) (char, dev_t, struct dev_info *);
	int (*ioctl) (char, dev_t, int, void *, struct dev_info *);
	int (*release) (char, dev_t, struct dev_info *);
	int (*access) (char, dev_t, int);

	int (*select_register) (char, dev_t, voidfun cb, void *arg, int how, struct dev_info *);

	int (*ioctlparms) (char, dev_t, int arg, void *umph);

	int (*init) (char, dev_t, char *path, unsigned long flags, char *args);
	int (*fini) (char, dev_t);
};	

/* MOUNT ARG MGMT */
struct devargitem {
	char *arg;
	void (*fun)();
};
void devargs(char *opts, struct devargitem *devargtab, int devargsize, void *arg);

	
#endif /* _UMDEV_H_ */

