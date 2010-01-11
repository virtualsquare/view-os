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

#ifndef _KMVIEW_DATA_H
#define _KMVIEW_DATA_H
#include <linux/ioctl.h>
#include <linux/utrace.h>
#include <linux/list.h>
#include <linux/wait.h>
#include <linux/semaphore.h>
#include <linux/spinlock.h>
/* PUBLIC INTERFACE IS IN kmview.h */
#include "kmview.h"
#include "kmview_arch.h"

#define USE_KMEM_CACHE
#define KMVIEW_NEWSTOP

struct kmview_tracer {
	struct semaphore sem;
	struct task_struct *task;
	pid_t ntraced;
	atomic_t flags;
	long magicpoll_addr;
	long magicpoll_cnt;
	spinlock_t lock;
	unsigned int syscall_bitmap[INT_PER_MAXSYSCALL];
	wait_queue_head_t event_waitqueue;
	struct list_head event_queue;
};

#define KMVIEW_THREAD_FLAG_SKIP_EXIT 1
#define KMVIEW_THREAD_FLAG_SKIP_CALL 2
#define KMVIEW_THREAD_FLAG_SKIP_BOTH 3
#define KMVIEW_THREAD_CHROOT 0x10
#define KMVIEW_THREAD_INHERITED_FLAGS KMVIEW_THREAD_CHROOT

struct kmview_thread {
	struct task_struct *task;
	struct kmview_tracer *tracer;
#ifdef KMVIEW_NEWSTOP
	struct semaphore kmstop;
#endif
	pid_t kmpid;
	pid_t umpid;
	u32 flags;
	unsigned long scno;
	struct utrace_engine *engine;
	struct pt_regs *regs;
#ifdef __NR_socketcall
	unsigned long socketcallargs[6];
#endif
	//struct utrace_examiner exam;
	struct kmview_fdsysset *fdset;
};


struct kmview_module_event {
	struct list_head eventlist;
	u32 tag;
	struct kmview_thread *thread;
	pid_t arg; /* umppid or ntraced */
	unsigned long arg2; /*clone_flags*/
};

static inline unsigned int scbitmap_isset_locked(struct kmview_tracer *kmt,int scno) {
	unsigned long flags;
	unsigned int rv;
	spin_lock_irqsave(&kmt->lock, flags);
	rv=scbitmap_isset(kmt->syscall_bitmap,scno);
	spin_unlock_irqrestore(&kmt->lock, flags);
	return rv;
}

#endif
