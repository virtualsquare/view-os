/*
 *     UMMISC: Virtual Miscellanea in Userspace
 *     (virtualization of pid/uid/gid/time/uname....)
 *     Copyright (C) 2006  Renzo Davoli <renzo@cs.unibo.it>
 *
 *     This program can be distributed under the terms of the GNU GPLv2.
 *     See the file COPYING.LIB.
 */

#ifndef _UMMISC_H_
#define _UMMISC_H_
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>

#define IOCTLLENMASK      0x07ffffff
#define IOCTL_R           0x10000000
#define IOCTL_W           0x20000000

#define MISCFILESIZE	4096
#define UMMISC_DEBUG       (1 << 29)

typedef void (* voidfun)(void *arg);

struct ummisc;

#define UMMISC_GET 1
#define UMMISC_PUT 0
struct fsentry {
	char *name;
	struct fsentry *subdir;
	loff_t (*getputfun)(int op,char *value,int size,struct ummisc *mh,int tag,char *path);
	int tag;
};

struct ummisc_operations {
	struct fsentry root;
	void (*init) (char *path, unsigned long flags, char *args,struct ummisc *mh);
	void (*fini) (struct ummisc *mh);
};	

/* MOUNT ARG MGMT */
struct miscargitem {
	char *arg;
	void (*fun)();
};

void miscargs(char *opts, struct miscargitem *miscargtab, int miscargsize, void *arg);

struct ummisc *searchmisc_sc(int scno);
void *misc_getdl(struct ummisc *mh);

void ummisc_setprivatedata(struct ummisc *mischandle,void *privatedata);
void *ummisc_getprivatedata(struct ummisc *mischandle);

//void ummisc_setmode(struct ummisc *mischandle, mode_t mode);
//mode_t ummisc_getmode(struct ummisc *mischandle);
#endif /* _UMMISC_H_ */

