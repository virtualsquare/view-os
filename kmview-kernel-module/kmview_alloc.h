/*
 * kmview O(1) thread allocator
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

#ifndef _KMVIEW_ALLOC_H
#define _KMVIEW_ALLOC_H
#include <linux/init.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/slab.h>

extern int kmpid_deny_new_threads;

struct kmpid_struct {
	struct kmview_thread *km_thread;
	pid_t next_kmpid;
};

void kmpid_init(void);
void kmpid_fini(void);

pid_t kmpid_alloc(struct kmview_thread *kmt);
void kmpid_free(pid_t km_oldpid);
struct kmpid_struct *kmpid_search(pid_t kmpid);
void kmpid_forall(void (*f)(struct kmpid_struct *kms,void *arg),void * arg);
#endif
