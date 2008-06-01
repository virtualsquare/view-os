/*
 * Utrace based device for tracing processes.
 *        ( callback from utrace engines )
 *
 * Copyright (C) 2007 Andrea Gasparini (gaspa@yattaweb.it)
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
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/utrace.h>
#include <linux/ptrace.h>
#include <linux/unistd.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/cdev.h>
#include <linux/cache.h>
#include <linux/fs.h>

#include "kmview_data.h"
#include "kmview_alloc.h"
#include "kmview_arch_i386.h"
#include "kmview_fdsysset.h"

#ifdef USE_KMEM_CACHE
static struct kmem_cache *kmview_thread_cache;
static struct kmem_cache *kmview_module_event_cache;
#endif

static u32 kmview_clone(struct utrace_attached_engine *engine, struct task_struct *parent, unsigned long clone_flags, struct task_struct *child);
static void kmview_reap(struct utrace_attached_engine *engine, struct task_struct *tsk);
static u32 kmview_syscall_entry(struct utrace_attached_engine *engine, struct task_struct *tsk, struct pt_regs *regs);
static u32 kmview_syscall_exit(struct utrace_attached_engine *engine, struct task_struct *tsk, struct pt_regs *regs);
int kmview_allow_access_process_vm(struct utrace_attached_engine *engine,
		struct task_struct *target, struct task_struct *caller);
static u32 kmview_report_signal(struct utrace_attached_engine *engine,
		struct task_struct *tsk, struct pt_regs *regs,
		u32 action, siginfo_t *info,
		const struct k_sigaction *orig_ka,
		struct k_sigaction *return_ka);

#define KMVIEW_EVENTS (UTRACE_EVENT(REAP) | UTRACE_EVENT(CLONE)\
		| UTRACE_EVENT(SYSCALL_ENTRY) | UTRACE_EVENT(SYSCALL_EXIT) \
		| UTRACE_EVENT(SIGNAL_TERM) \
		) 

#ifdef __NR_socketcall
int socketcallnargs[] = {
	0,
  3, /* sys_socket(2)    */
  3, /* sys_bind(2)      */
  3, /* sys_connect(2)   */
  2, /* sys_listen(2)    */
  3, /* sys_accept(2)    */
  3, /* sys_getsockname(2)   */
  3, /* sys_getpeername(2)   */
  4, /* sys_socketpair(2)    */
  4, /* sys_send(2)      */
  4, /* sys_recv(2)      */
  6, /* sys_sendto(2)    */
  6, /* sys_recvfrom(2)    */
  2, /* sys_shutdown(2)    */
  5, /* sys_setsockopt(2)    */
  5, /* sys_getsockopt(2)    */
  3, /* sys_sendmsg(2)   */
  3, /* sys_recvmsg(2)   */
	4  /* sys_msocket new call for multiple stack access */
};
#endif

const struct utrace_engine_ops kmview_ops =
{
	.report_clone = kmview_clone,
	.report_reap = kmview_reap,
	.report_syscall_entry = kmview_syscall_entry,
	.report_syscall_exit = kmview_syscall_exit,
	.report_signal = kmview_report_signal,
	.allow_access_process_vm = kmview_allow_access_process_vm
};

static inline void kmview_event_enqueue(
		u32 tag,
		struct kmview_thread *kmt,
		pid_t arg,
		unsigned long arg2)
{
#ifdef USE_KMEM_CACHE
	struct kmview_module_event *kme=kmem_cache_alloc(kmview_module_event_cache, GFP_KERNEL);
#else
  struct kmview_module_event *kme=kmalloc(sizeof(struct kmview_module_event),GFP_KERNEL);
#endif
	if (kme) {
		kme->tag=tag;
		kme->thread=kmt;
		kme->arg=arg;
		kme->arg2=arg2;
		down(&kmt->tracer->sem);
		list_add_tail(&kme->eventlist,&kmt->tracer->event_queue);
		//printk("added e=%d TAG %d\n",kmt->tracer->waiting,tag);
		up(&kmt->tracer->sem);
		wake_up(&kmt->tracer->event_waitqueue);
	}
}

static inline struct utrace_attached_engine *kmview_attach_engine(struct task_struct *task)
{
	struct utrace_attached_engine *task_engine;
	int rv=-100;
	task_engine = utrace_attach(task, UTRACE_ATTACH_CREATE, &kmview_ops, 0);
	/*printk("utrace_attach %d %x\n",task->pid,KMVIEW_EVENTS);*/
	if (IS_ERR(task_engine)) {
		printk("ERROR in attaching process %d => %ld\n",
				task->pid, PTR_ERR(task_engine));
		task_engine=NULL;
	} else 
		rv=utrace_set_flags(task, task_engine, KMVIEW_EVENTS);
	return task_engine;
}

static inline pid_t kmview_new_thread(
		struct task_struct *task,
		struct kmview_tracer *tracer,
		struct utrace_attached_engine *engine,
		struct kmview_fdsysset *fdset)
{
	struct kmview_thread *kmt;
#ifdef USE_KMEM_CACHE
	kmt=kmem_cache_alloc(kmview_thread_cache, GFP_KERNEL);
#else
	kmt=kmalloc(sizeof(struct kmview_thread),GFP_KERNEL);
#endif
	if (!kmt)
		return -ENOMEM;
	//printk("NEW_THREAD %d tracer %p\n",task->pid,tracer);
	kmt->task=task;
	kmt->tracer=tracer;
	kmt->kmpid=kmpid_alloc(kmt);
	kmt->umpid=-1;
	kmt->flags=0;
	down(&kmt->tracer->sem);
	kmt->tracer->ntraced++;
	up(&kmt->tracer->sem);
	kmt->engine=engine;
	kmt->fdset=fdsysset_copy(fdset);
	if (engine) 
		engine->data=kmt;
	return kmt->kmpid;
}

pid_t kmview_root_thread(struct task_struct *task, struct kmview_tracer *tracer)
{
	struct utrace_attached_engine *engine=kmview_attach_engine(task);
	pid_t kmpid;
	if (!engine)
		return -EIO;
	kmpid=kmview_new_thread(task,tracer,engine,NULL);
	if (kmpid < 0)
		return -EIO;
	kmview_event_enqueue(KMVIEW_EVENT_NEWTHREAD,kmpid_search(kmpid)->km_thread,-1,0);
	return kmpid;
}

void kmview_kmpid_resume(pid_t kmpid)
{
	struct kmpid_struct *kmps=kmpid_search(kmpid);
	if (kmps) {
		struct kmview_thread *kmt=kmps->km_thread;
		//printk("utrace_set_flags %d\n",KMVIEW_EVENTS);
		utrace_set_flags(kmt->task, kmt->engine, KMVIEW_EVENTS);
	}
}

/*
 * On clone, attach to the child.
 */
static u32 kmview_clone(struct utrace_attached_engine *engine, struct task_struct *parent, unsigned long clone_flags, struct task_struct *child)
{
	pid_t kmpid;
	struct utrace_attached_engine *childengine=kmview_attach_engine(child);
	struct kmview_thread *kmt;
	kmt=engine->data;
	if (kmt->tracer) {
		kmpid=kmview_new_thread(child,kmt->tracer,childengine,kmt->fdset);
		if (kmpid < 0) {
			kill_proc(child->pid,9,0);
			return UTRACE_ACTION_NEWSTATE | UTRACE_ACTION_QUIESCE;
		}
		kmview_event_enqueue(KMVIEW_EVENT_NEWTHREAD,kmpid_search(kmpid)->km_thread,kmt->umpid,clone_flags);
	} else
		return UTRACE_ACTION_NEWSTATE | UTRACE_ACTION_QUIESCE;
	return UTRACE_ACTION_RESUME;
}

/*
 * Reap. Detach & destroy data structures.
 */
static void kmview_reap(struct utrace_attached_engine *engine, struct task_struct *tsk)
{
	struct kmview_thread *kmt=engine->data;
	/*printk("process %d terminated\n",tsk->pid);*/
	/*destroy data structures*/
	if (kmt) {
		if (kmt->tracer) {
			pid_t remaining;
			down(&kmt->tracer->sem);
			kmt->tracer->ntraced--;
			remaining=kmt->tracer->ntraced;
			up(&kmt->tracer->sem);
			kmview_event_enqueue(KMVIEW_EVENT_TERMTHREAD,kmt,remaining,0);
		} 
	}
}

void kmview_thread_free(struct kmview_thread *kmt)
{
	fdsysset_free(kmt->fdset);
	kmpid_free(kmt->kmpid);
#ifdef USE_KMEM_CACHE
	kmem_cache_free(kmview_thread_cache,kmt);
#else
	kfree(kmt);
#endif
}

void kmview_module_event_free(struct kmview_module_event *kme)
{
#ifdef USE_KMEM_CACHE
	kmem_cache_free(kmview_module_event_cache,kme);
#else
	kfree(kme);
#endif
}

static inline int iskmviewfd (unsigned long sysno, int fd, struct kmview_fdsysset *fdset,
		    int except_close, int except_fchdir) {
	if (!isfdsys(sysno))
		return 1;
	if (except_close && (sysno == __NR_close
#ifdef __NR_shutdown
				|| sysno == __NR_shutdown
#endif
				))
		return 1;
	if (except_fchdir && sysno == __NR_fchdir)
		return 1;
	if (fdset == NULL)
		return 0;
	return FD_ISSET(fd,&fdset->fdset);
}

static inline int iskmviewsockfd(unsigned long socketcallno, int fd, struct kmview_fdsysset *fdset,
		        int except_close)
{
	if (!isfdsocket(socketcallno))
		return 1;
	if (except_close && socketcallno == 13) /*shutdown is a kind of close*/
		return 1;
	if (fdset == NULL)
		    return 0;
	return FD_ISSET(fd,&fdset->fdset);
}

static u32 kmview_syscall_entry(struct utrace_attached_engine *engine,
		struct task_struct *tsk, struct pt_regs *regs)
{
	struct kmview_thread* kmt = (struct kmview_thread*)engine->data;
	//printk("syscall entry(%d) : %ld %ld regs...\n",tsk->pid,arch_scno(regs),arch_n(regs,0));

	if (kmt->tracer) {
		kmt->scno=arch_scno(regs);
#ifdef __NR_socketcall
		if (kmt->tracer->flags & KMVIEW_FLAG_SOCKETCALL &&
				kmt->scno == __NR_socketcall) {
			unsigned long socketcallno=arch_n(regs,0);
			if (copy_from_user(&kmt->socketcallargs,(void *)arch_n(regs,1),
						socketcallnargs[socketcallno] * sizeof(unsigned long))) {
				kill_proc(tsk->pid,9,0);
				return UTRACE_ACTION_NEWSTATE | UTRACE_ACTION_QUIESCE;
			}
			if (!(kmt->tracer->flags & KMVIEW_FLAG_FDSET)  ||
					iskmviewsockfd(socketcallno, socketcallnargs[0], kmt->fdset,
						kmt->tracer->flags & KMVIEW_FLAG_EXCEPT_CLOSE)) {
				kmt->regs=regs;
				kmview_event_enqueue(KMVIEW_EVENT_SOCKETCALL_ENTRY,kmt,socketcallnargs[socketcallno],0);
				return UTRACE_ACTION_NEWSTATE | UTRACE_ACTION_QUIESCE;
			} else {
				kmt->flags |= KMVIEW_THREAD_FLAG_SKIP_EXIT;
				kmt->flags &= ~KMVIEW_THREAD_FLAG_SKIP_CALL;
				return UTRACE_ACTION_RESUME;
			}
		} else
#endif
		if (!(kmt->tracer->flags & KMVIEW_FLAG_FDSET) ||
				iskmviewfd(arch_scno(regs), arch_n(regs,0), kmt->fdset,
					kmt->tracer->flags & KMVIEW_FLAG_EXCEPT_CLOSE,
					kmt->tracer->flags & KMVIEW_FLAG_EXCEPT_FCHDIR)) {
			kmt->regs=regs;
			kmview_event_enqueue(KMVIEW_EVENT_SYSCALL_ENTRY,kmt,0,0);
			return UTRACE_ACTION_NEWSTATE | UTRACE_ACTION_QUIESCE;
		} else {
			kmt->flags |= KMVIEW_THREAD_FLAG_SKIP_EXIT;
			kmt->flags &= ~KMVIEW_THREAD_FLAG_SKIP_CALL;
			return UTRACE_ACTION_RESUME;
		}
	} else {
		kill_proc(tsk->pid,9,0);
		return UTRACE_ACTION_NEWSTATE | UTRACE_ACTION_QUIESCE;
	}
}

static u32 kmview_syscall_exit(struct utrace_attached_engine *engine,
		struct task_struct *tsk, struct pt_regs *regs)
{
	struct kmview_thread* kmt = (struct kmview_thread*)engine->data;
	//printk("syscall exit(%d) : %ld regs ...\n",tsk->pid,arch_scno(regs));
	if (kmt->tracer) {
		kmt->regs=regs;
		if(kmt->flags & KMVIEW_THREAD_FLAG_SKIP_CALL) /*restore call*/
			arch_scno(regs)=kmt->scno;
		if(kmt->flags & KMVIEW_THREAD_FLAG_SKIP_EXIT)
			return UTRACE_ACTION_RESUME;
		else {
			kmview_event_enqueue(KMVIEW_EVENT_SYSCALL_EXIT,kmt,0,0);
			return UTRACE_ACTION_NEWSTATE | UTRACE_ACTION_QUIESCE;
		}
	} else {
		kill_proc(tsk->pid,9,0);
		return UTRACE_ACTION_NEWSTATE | UTRACE_ACTION_QUIESCE;
	}
}

static u32 kmview_report_signal(struct utrace_attached_engine *engine,
		struct task_struct *tsk, struct pt_regs *regs,
		u32 action, siginfo_t *info,
		const struct k_sigaction *orig_ka,
		struct k_sigaction *return_ka) {
}

int kmview_allow_access_process_vm(struct utrace_attached_engine *engine,
		    struct task_struct *target, struct task_struct *caller) {
	struct kmview_thread* kmt = (struct kmview_thread*)engine->data;
	if (kmt->tracer != NULL && kmt->tracer->task == caller)
		return 1;
	else
		return 0;
}

int kmview_trace_init(void)
{
#ifdef USE_KMEM_CACHE
	if ((kmview_thread_cache = KMEM_CACHE(kmview_thread, 0)) && 
			(kmview_module_event_cache = KMEM_CACHE(kmview_module_event, 0)))
		return 0;
	else
		return -ENOMEM;
#else
	return 0;
#endif
}

void kmview_trace_fini(void)
{
#ifdef USE_KMEM_CACHE
	if (kmview_thread_cache)
		        kmem_cache_destroy(kmview_thread_cache);
	if (kmview_module_event_cache)
		        kmem_cache_destroy(kmview_module_event_cache);
#endif
}
