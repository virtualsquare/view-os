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

struct umdev;

struct dev_info {

	/* Open flags, available in open and release */
	int flags;

	/* File handle. It usually set up in open and then
	 * available for all other operations */
	uint64_t fh; 
	
	/* devhandle for management */
	struct umdev *devhandle;
};

struct umdev_operations {
	int (*getattr) (char, dev_t, struct stat64 *, struct umdev *devhandle);
	int (*fgetattr) (char, dev_t, struct stat64 *, struct dev_info *);
	int (*chmod) (char, dev_t, mode_t, struct umdev *devhandle);
	int (*chown) (char, dev_t, uid_t, gid_t, struct umdev *devhandle);
  int (*open) (char, dev_t, struct dev_info *);
	int (*read) (char, dev_t, char *, size_t, loff_t, struct dev_info *);
	int (*write) (char, dev_t, const char *, size_t, loff_t, struct dev_info *);
	loff_t (*lseek) (char, dev_t, loff_t, int, loff_t, struct dev_info *);
	int (*fsync) (char, dev_t, struct dev_info *);
	int (*ioctl) (char, dev_t, int, void *, struct dev_info *);
	int (*release) (char, dev_t, struct dev_info *);
	int (*access) (char, dev_t, int, struct umdev *devhandle);

	int (*event_subscribe) (char, dev_t, voidfun cb, void *arg, int how, struct dev_info *);

	int (*ioctlparms) (char, dev_t, int arg, struct dev_info *);
	int (*init) (char, dev_t, char *path, unsigned long flags, char *args, struct umdev *devhandle);
	int (*fini) (char, dev_t, struct umdev *devhandle);
};	

/* MOUNT ARG MGMT */
struct devargitem {
	char *arg;
	void (*fun)();
};
void devargs(char *opts, struct devargitem *devargtab, int devargsize, void *arg);

void umdev_setprivatedata(struct umdev *devhandle, void *privatedata);
void *umdev_getprivatedata(struct umdev *devhandle);

void umdev_setnsubdev(struct umdev *devhandle, int nsubdev);
int umdev_getnsubdev(struct umdev *devhandle);
	
void umdev_setmode(struct umdev *devhandle, mode_t mode);
mode_t umdev_getmode(struct umdev *devhandle);

dev_t umdev_getbasedev(struct umdev *devhandle);
#endif /* _UMDEV_H_ */

