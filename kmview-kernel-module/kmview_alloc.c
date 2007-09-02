/*
 * kmview O(1) thread allocator
 *
 * Copyright (C) 2007 Renzo Davoli (renzo@cs.unibo.it)
 *                    Andrea Gasparini (gaspa@yattaweb.it), 
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

#include <linux/init.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include "kmview_alloc.h"

#define STEPHEAD 16
#define ALLOCUNIT 1024
#define ALLOCLOG 10
#define ALLOCMASK 1023  /* 0x03ff */

int kmpid_deny_new_threads=0;
static struct kmpid_struct **km_head;
static pid_t km_maxhead, km_nhead, km_nthread;
static pid_t km_freehead;
DECLARE_MUTEX(kmpid_mutex);

static void km_realloc_head (void){
	pid_t oldsize=km_maxhead;
	struct kmpid_struct **old_head=km_head;
	km_maxhead+=ALLOCUNIT;
	km_head=kmalloc(km_maxhead * sizeof(struct kmpid_struct *),GFP_KERNEL);
	memcpy(km_head,old_head,oldsize *sizeof(struct kmpid_struct *));
	kfree(old_head);
}

void kmpid_init(void) {
	km_head=NULL;
	km_freehead=-1;
	km_maxhead=km_nhead=km_nthread=0;
}

void kmpid_fini(void) {
	int i;
	for (i=0;i<km_nhead;i++)
		kfree(km_head[i]);
	if (km_head != NULL)
		kfree(km_head);
}

static struct kmpid_struct *kmpid2struct(pid_t kmpid)
{
	struct kmpid_struct *kmpage;
	//printf("%d %p %p\n",kmpid,km_head,km_head[kmpid>>ALLOCLOG]);
	if (kmpid < km_nthread &&
			km_head != NULL && 
			(kmpage=km_head[kmpid>>ALLOCLOG]) != NULL) 
			return km_head[kmpid>>ALLOCLOG]+(kmpid & ALLOCMASK);
	else 
		return NULL;
}

pid_t kmpid_alloc(struct kmview_thread *kmt)
{
	pid_t retval;
	down(&kmpid_mutex);
	if (kmpid_deny_new_threads)
		retval= -1;
	else {
		if (km_freehead >= 0) {
			retval=km_freehead;
			km_freehead=kmpid2struct(km_freehead)->next_kmpid;
		} else {
			retval=km_nthread++;
			if ((km_nhead << ALLOCLOG) < km_nthread) {
				if (km_nhead >= km_maxhead)
					km_realloc_head();
				km_head[km_nhead]=kmalloc(ALLOCUNIT * sizeof(struct kmpid_struct),GFP_KERNEL);
				km_nhead++;
			}
		}
		kmpid2struct(retval)->km_thread=kmt; 
	}
	up(&kmpid_mutex);
	return retval;
}

void kmpid_free(pid_t km_oldpid)
{
	struct kmpid_struct *oldstruct;
	down(&kmpid_mutex);
	oldstruct=kmpid2struct(km_oldpid);
	if (oldstruct != NULL) {
		oldstruct->km_thread=NULL;
		oldstruct->next_kmpid=km_freehead;
		km_freehead=km_oldpid;
	}
	up(&kmpid_mutex);
}

struct kmpid_struct *kmpid_search(pid_t kmpid)
{
	struct kmpid_struct *retval;
	down(&kmpid_mutex);
	retval=kmpid2struct(kmpid);
	if (retval != NULL && retval->km_thread == NULL)
		retval=NULL;
	up(&kmpid_mutex);
	return retval;
}

void kmpid_forall(void (*f)(struct kmpid_struct *kms,void *arg),void * arg)
{
	int i;
	for (i=0;i<km_nthread;i++) {
		struct kmpid_struct *kms=kmpid2struct(i);
		if (kms->km_thread != NULL)
			f(kms,arg);
	}
}

#if 0
main()
{
	int i;
	kmpid_init();
	for (i=0;i<5000; i++) 
		printf("%d ",kmpid_alloc());
	printf("\n");
	for (i=0;i<500; i++) 
		printf("%p ",kmpid2struct(i));
	printf("\n");
	kmpid_free(130);
	kmpid_free(140);
	kmpid_free(150);
	for (i=0;i<500; i++)
		printf("%d ",kmpid_alloc());
	printf("\n");
	for (i=1000;i<2000; i++)
		kmpid_free(i);
	for (i=0;i<500; i++)
		printf("%d ",kmpid_alloc());
	printf("\n");
	kmpid_fini();
}
#endif
