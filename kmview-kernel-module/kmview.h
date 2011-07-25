#ifndef _KMVIEW_H
#define _KMVIEW_H
/*
 * kmview data structures
 *
 * Copyright (C) 2007 Andrea Gasparini (gaspa@yattaweb.it), 
 *                    Renzo Davoli (renzo@cs.unibo.it)
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  Due to this file being licensed under the GPL there is controversy over
 *  whether this permits you to write a module that #includes this file
 *  without placing your module under the GPL.  Please consult a lawyer for
 *  advice before doing this.
 *
 */

#include <linux/ptrace.h>
#include <sys/ioctl.h>

#define KMVIEW_EVENT_NONE             0x00
#define KMVIEW_EVENT_NEWTHREAD        0x01
#define KMVIEW_EVENT_TERMTHREAD       0x02
#define KMVIEW_EVENT_SYSCALL_ENTRY    0x10
#define KMVIEW_EVENT_SOCKETCALL_ENTRY 0x11
#define KMVIEW_EVENT_SYSCALL_EXIT     0x20

struct kmview_event {
	unsigned long tag;
	union {
		struct kmview_event_newthread{
			pid_t kmpid;
			pid_t pid;
			pid_t umppid;
			unsigned long flags;
		} newthread;
		struct kmview_event_termthread{
			pid_t umpid;
			unsigned long remaining;
		} termthread;
		struct kmview_event_ioctl_syscall{
			union {
				pid_t umpid;
				pid_t kmpid;
				unsigned long just_for_64bit_alignment;
			} x;
			unsigned long scno;
			unsigned long args[6];
			unsigned long pc;
			unsigned long sp;
		} syscall;
#ifdef __NR_socketcall
		struct kmview_event_socketcall{
			union {
				pid_t umpid;
				unsigned long just_for_64bit_alignment;
			} x;
			unsigned long scno;
			unsigned long args[6];
			unsigned long pc;
			unsigned long sp;
			unsigned long addr;
		} socketcall;
#endif
		struct kmview_event_ioctl_sysreturn{
			union {
				pid_t umpid;
				pid_t kmpid;
				unsigned long just_for_64bit_alignment;
			} x;
			long retval;
			long erno;
		} sysreturn;
	} x;
};

struct kmview_ioctl_umpid {
	pid_t kmpid;
	pid_t umpid;
};

struct kmview_ioctl_data {
	pid_t kmpid;
	long addr; 
	int len; 
	void *localaddr;
};

struct kmview_magicpoll {
	long magicpoll_addr;
	long magicpoll_cnt;
};

struct kmview_fd {
	pid_t kmpid;
	int fd;
};

#define GH_SIZE 64
#define GH_TERMINATE 255
#define GH_DUMMY 254

struct ghosthash64 {
	unsigned char deltalen[GH_SIZE];
	unsigned int hash[GH_SIZE];
};

#define KMVIEW_FLAG_SOCKETCALL 0x1
#define KMVIEW_FLAG_FDSET      0x2
#define KMVIEW_FLAG_EXCEPT_CLOSE      0x4
#define KMVIEW_FLAG_EXCEPT_FCHDIR     0x8
#define KMVIEW_FLAG_PATH_SYSCALL_SKIP    0x10

#define KMVIEW_GET_VERSION     _IO('v', 1)
#define KMVIEW_SET_FLAGS       _IO('v', 2)
#define KMVIEW_MAGICPOLL       _IOR('v', 3, struct kmview_magicpoll)
#define KMVIEW_ATTACH          _IO('v', 4)
#define KMVIEW_UMPID           _IOR('v', 5, struct kmview_ioctl_umpid)
#define KMVIEW_GET_FLAGS       _IO('v', 6)
#define KMVIEW_SYSRESUME       _IO('v', 10)
#define KMVIEW_SYSVIRTUALIZED  _IOR('v', 11, struct kmview_event_ioctl_sysreturn)
#define KMVIEW_SYSMODIFIED     _IOR('v', 12, struct kmview_event_ioctl_syscall)
#define KMVIEW_SYSRETURN       _IOR('v', 13, struct kmview_event_ioctl_sysreturn)
#define KMVIEW_SYSARGMOD       _IOR('v', 14, struct kmview_event_ioctl_syscall)
#define KMVIEW_READDATA        _IOR('v', 20, struct kmview_ioctl_data)
#define KMVIEW_READSTRINGDATA  _IOR('v', 21, struct kmview_ioctl_data)
#define KMVIEW_WRITEDATA       _IOR('v', 22, struct kmview_ioctl_data)
#define KMVIEW_ADDFD           _IOR('v', 30, struct kmview_fd)
#define KMVIEW_DELFD           _IOR('v', 31, struct kmview_fd)

#define KMVIEW_SYSCALLBITMAP   _IOR('v', 40, unsigned int)
#define KMVIEW_SET_CHROOT      _IO('v', 41)
#define KMVIEW_CLR_CHROOT      _IO('v', 42)
#define KMVIEW_GHOSTMOUNTS     _IOR('v', 43, struct ghosthash64)

#define MAXSYSCALL 384
#define INT_PER_MAXSYSCALL	(MAXSYSCALL / (sizeof(unsigned int) * 8))
#define SYSCALLBITMAPEL(x)	((x) >> 5)
#define SYSCALLBITMAPOFF(x)	((x)&0x1f)

static inline unsigned int scbitmap_isset(unsigned int *bitmap,unsigned long scno) {
	if (likely(scno < MAXSYSCALL))
		return bitmap[SYSCALLBITMAPEL(scno)] & 1<<SYSCALLBITMAPOFF(scno);
	else
		return 0;
}

static inline void scbitmap_set(unsigned int *bitmap,unsigned long scno) {
	if (scno < MAXSYSCALL)
		bitmap[SYSCALLBITMAPEL(scno)] |= 1<<SYSCALLBITMAPOFF(scno);
}

static inline void scbitmap_clr(unsigned int *bitmap,unsigned long scno) {
	if (scno < MAXSYSCALL)
		bitmap[SYSCALLBITMAPEL(scno)] &= ~(1<<SYSCALLBITMAPOFF(scno));
}

static inline void scbitmap_fill(unsigned int *bitmap) {
	register int i;
	for (i=0; i<INT_PER_MAXSYSCALL; i++)
		bitmap[i]= -1;
}

static inline void scbitmap_zero(unsigned int *bitmap) {
	register int i;
	for (i=0; i<INT_PER_MAXSYSCALL; i++)
		bitmap[i]= 0;
}

static inline void ghosthash_new(struct ghosthash64 *gh)
{
	  gh->deltalen[0] = GH_TERMINATE;
}

#endif
