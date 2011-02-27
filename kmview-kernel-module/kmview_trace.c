/*
 * Utrace based device for tracing processes.
 *        ( callback from utrace engines )
 *
 * Copyright (C) 2007 Andrea Gasparini (gaspa@yattaweb.it)
 *          2007-2010 Renzo Davoli (renzo@cs.unibo.it)
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
#include <linux/security.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/cdev.h>
#include <linux/cache.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include "kmview_data.h"
#include "kmview_alloc.h"
#include "kmview_arch.h"
#include "kmview_fdsysset.h"

//#define KMVIEW_DEBUG
unsigned int pathsyscall[]=PATHSYSCALL;
unsigned int path0syscall[]=PATH0SYSCALL;
unsigned int path1syscall[]=PATH1SYSCALL;
unsigned int path2syscall[]=PATH2SYSCALL;
unsigned int path3syscall[]=PATH3SYSCALL;
/*unsigned int atsyscall[]=ATSYSCALL;*/
unsigned int selectpollsyscall[]=SELECTPOLLSYSCALL;
unsigned int fdsyscall[]=FDSYSCALL;

#ifdef USE_KMEM_CACHE
static struct kmem_cache *kmview_thread_cache;
static struct kmem_cache *kmview_module_event_cache;
static struct kmem_cache *kmview_fdset_cache;
#endif

static u32 kmview_clone(enum utrace_resume_action action,
		struct utrace_engine *engine, 
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
		struct task_struct *parent,
#endif
		unsigned long clone_flags, struct task_struct *child);

static void kmview_reap(struct utrace_engine *engine, struct task_struct *tsk);

static u32 kmview_syscall_entry(u32 action,struct utrace_engine *engine, 
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
		struct task_struct *tsk,
#endif
		struct pt_regs *regs);

static u32 kmview_syscall_exit(u32 action,struct utrace_engine *engine, 
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
		struct task_struct *tsk,
#endif
		struct pt_regs *regs);

static u32 kmview_report_exec(u32 action, struct utrace_engine *engine,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
		struct task_struct *tsk,
#endif
		const struct linux_binfmt *fmt, const struct linux_binprm *bprm, 
		struct pt_regs *regs);

#define KMVIEW_EVENTS (UTRACE_EVENT(REAP) | UTRACE_EVENT(CLONE)\
		| UTRACE_EVENT(SYSCALL_ENTRY) | UTRACE_EVENT(SYSCALL_EXIT)) | UTRACE_EVENT(EXEC)

static inline u32 kmview_abort_task(struct task_struct *task)
{
	send_sig(SIGKILL,task,1);
	return UTRACE_STOP;
}

static inline u32 kmview_stop_task(struct kmview_thread *kmt)
{
#ifdef KMVIEW_NEWSTOP
	/* it should not creat unkillable 'D' processes */
	down(&kmt->kmstop);
	return UTRACE_RESUME;
#else
	return UTRACE_STOP;
#endif
}

static inline u32 kmview_resume_task(struct kmview_thread *kmt)
{
#ifdef KMVIEW_NEWSTOP
	up(&kmt->kmstop);
	return 0;
#else
	return utrace_control(kmt->task, kmt->engine, UTRACE_RESUME);
#endif
}

#ifdef __NR_socketcall
char socketcallnargs[] = {
	4, /* 0 sys_msocket new call for multiple stack access */
  3, /* 1 sys_socket(2)    */
  3, /* 2 sys_bind(2)      */
  3, /* 3 sys_connect(2)   */
  2, /* 4 sys_listen(2)    */
  3, /* 5 sys_accept(2)    */
  3, /* 6 sys_getsockname(2)   */
  3, /* 7 sys_getpeername(2)   */
  4, /* 8 sys_socketpair(2)    */
  4, /* 9 sys_send(2)      */
  4, /*10 sys_recv(2)      */
  6, /*11 sys_sendto(2)    */
  6, /*12 sys_recvfrom(2)    */
  2, /*13 sys_shutdown(2)    */
  5, /*14 sys_setsockopt(2)    */
  5, /*15 sys_getsockopt(2)    */
  3, /*16 sys_sendmsg(2)   */
  3, /*17 sys_recvmsg(2)   */
	4  /*18 sys_accept4(2) */
};

static inline int isfdsocket(unsigned long x) {
	if (x<2 || x>18 || x==8)
		return 0;
	else
		return 1;
}
#endif

const struct utrace_engine_ops kmview_ops =
{
	.report_clone = kmview_clone,
	.report_reap = kmview_reap,
	.report_syscall_entry = kmview_syscall_entry,
	.report_syscall_exit = kmview_syscall_exit,
	.report_exec = kmview_report_exec,
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
#ifdef KMVIEW_DEBUG
		printk("added TAG %d\n",tag);
#endif
		up(&kmt->tracer->sem);
		wake_up(&kmt->tracer->event_waitqueue);
	}
}

static inline struct utrace_engine *kmview_attach_engine(struct task_struct *task)
{
	struct utrace_engine *task_engine;
	int rv=-100;
	task_engine = utrace_attach_task(task, UTRACE_ATTACH_CREATE, &kmview_ops, 0);
#ifdef KMVIEW_DEBUG
	printk("utrace_attach %d %lx\n",task->pid,KMVIEW_EVENTS);
#endif
	if (IS_ERR(task_engine)) {
		printk("ERROR in attaching process %d => %ld\n",
				task->pid, PTR_ERR(task_engine));
		task_engine=NULL;
	} if (task_engine==NULL) 
		printk("ERROR in attaching process %d => NULL\n", task->pid);
	else {
		utrace_engine_put(task_engine);
		rv=utrace_set_events(task, task_engine, KMVIEW_EVENTS);
#ifdef KMVIEW_DEBUG
	printk("utrace_set events %d %d\n",task->pid,rv);
#endif
	}
	return task_engine;
}

static inline pid_t kmview_new_thread(
		struct task_struct *task,
		struct kmview_tracer *tracer,
		struct utrace_engine *engine,
		struct kmview_fdset *fdset,
		u32 inherited_flags,
		unsigned long clone_flags)
{
	struct kmview_thread *kmt;
#ifdef USE_KMEM_CACHE
	kmt=kmem_cache_alloc(kmview_thread_cache, GFP_KERNEL);
#else
	kmt=kmalloc(sizeof(struct kmview_thread),GFP_KERNEL);
#endif
	if (!kmt)
		return -ENOMEM;
#ifdef KMVIEW_DEBUG
	printk("NEW_THREAD %d tracer %p\n",task->pid,tracer);
#endif
	kmt->task=task;
	kmt->tracer=tracer;
	kmt->kmpid=kmpid_alloc(kmt);
	kmt->umpid=-1;
	/*skip the ioctl exit call! */
	kmt->flags=KMVIEW_THREAD_FLAG_SKIP_EXIT | inherited_flags;
#ifdef KMVIEW_NEWSTOP
	sema_init(&kmt->kmstop, 0);
#endif
	down(&kmt->tracer->sem);
	kmt->tracer->ntraced++;
	up(&kmt->tracer->sem);
	kmt->engine=engine;
	if (clone_flags & CLONE_FILES) {
		atomic_inc(&fdset->nusers);
		kmt->fdset=fdset;
	} else {
#ifdef USE_KMEM_CACHE
		kmt->fdset=kmem_cache_alloc(kmview_fdset_cache, GFP_KERNEL);
#else
		kmt->fdset=kmalloc(sizeof(struct kmview_fdset),GFP_KERNEL);
#endif
		atomic_set(&kmt->fdset->nusers,1);
		if (fdset == NULL) 
			kmt->fdset->fdsysset=NULL;
		else
			kmt->fdset->fdsysset=fdsysset_copy(fdset->fdsysset);
	}
	if (engine) 
		engine->data=kmt;
	return kmt->kmpid;
}

pid_t kmview_root_thread(struct task_struct *task, struct kmview_tracer *tracer)
{
	struct utrace_engine *engine=kmview_attach_engine(task);
	pid_t kmpid;
	struct kmview_thread* kmt;
	if (!engine)
		return -EIO;
	kmpid=kmview_new_thread(task,tracer,engine,NULL,0,0);
	if (kmpid < 0)
		return -EIO;
	kmt = (struct kmview_thread*)engine->data;
	/*skip the ioctl exit call! */
	/*kmt->flags |= KMVIEW_THREAD_FLAG_SKIP_EXIT;*/
	kmview_event_enqueue(KMVIEW_EVENT_NEWTHREAD,kmpid_search(kmpid)->km_thread,-1,0);
	return kmpid;
}

void kmview_kmpid_resume(pid_t kmpid)
{
	struct kmpid_struct *kmps=kmpid_search(kmpid);
	if (kmps) {
		int rv;
		struct kmview_thread *kmt=kmps->km_thread;
#ifdef KMVIEW_DEBUG
		printk("utrace_control RESUME %d\n",kmt->task->pid);
#endif
		rv=kmview_resume_task(kmt);
		if (rv!=0 && rv != -ESRCH) /* terminated process */
			printk("ERR! utrace_control resume %d\n",rv);
#ifdef KMVIEW_DEBUG
	printk("utrace_resume %d %d\n",kmt->task->pid,rv);
#endif
	}
}

/*
 * On clone, attach to the child.
 */
static u32 kmview_clone(u32 action, 
		struct utrace_engine *engine, 
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
		struct task_struct *parent, 
#endif
		unsigned long clone_flags, 
		struct task_struct *child)
{
	pid_t kmpid;
	struct utrace_engine *childengine=kmview_attach_engine(child);
	struct kmview_thread *kmt;
	kmt=engine->data;
	if (kmt->tracer) {
		kmpid=kmview_new_thread(child,kmt->tracer,childengine,kmt->fdset,
				kmt->flags & KMVIEW_THREAD_INHERITED_FLAGS,clone_flags);
		if (kmpid < 0) 
			return kmview_abort_task(child);
		kmview_event_enqueue(KMVIEW_EVENT_NEWTHREAD,kmpid_search(kmpid)->km_thread,kmt->kmpid,clone_flags);
	} else
		return kmview_abort_task(child);
	return UTRACE_RESUME;
}

/*
 * Reap. Detach & destroy data structures.
 */
static void kmview_reap(struct utrace_engine *engine, struct task_struct *tsk)
{
	struct kmview_thread *kmt=engine->data;
#ifdef KMVIEW_DEBUG
	printk("========= process %d terminated\n",tsk->pid);
#endif
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

static u32 kmview_report_exec(enum utrace_resume_action action,
		struct utrace_engine *engine,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
		struct task_struct *task,
#endif
		const struct linux_binfmt *fmt,
		const struct linux_binprm *bprm,
		struct pt_regs *regs)
{
	/* revert the effect of setuid */
	if (current_uid() != current_euid() ||
			current_gid() != current_egid()) {
		struct cred *new;
		new = prepare_creds();
		if (!new) {
			abort_creds(new);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
			send_sig(SIGKILL,task,1);
#else
			/* XXX terminate process */
#endif
		} else {
			new->fsuid = new->euid = new->suid = current_uid();
			new->fsgid = new->egid = new->sgid = current_gid();
			new->cap_inheritable = CAP_EMPTY_SET;
			new->cap_permitted = CAP_EMPTY_SET;
			new->cap_effective = CAP_EMPTY_SET;
			commit_creds(new);
			/* printk("EXEC %d -> u%d g%d eu%d eg%d\n", task->pid,
					current_uid(),
					current_gid(),
					current_euid(),
					current_egid()); */
		}
	}
	return UTRACE_RESUME;
}

void kmview_thread_free(struct kmview_thread *kmt, int kill)
{
	if (kill && kmt->task) {
		int rv;
		rv=utrace_control(kmt->task,kmt->engine,UTRACE_DETACH);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
		send_sig(SIGKILL,kmt->task,1);
#else
		/* XXX terminate process */
#endif
#ifdef KMVIEW_NEWSTOP
		up(&kmt->kmstop);
#endif
	}
	if (atomic_dec_and_test(&kmt->fdset->nusers)) {
		fdsysset_free(kmt->fdset->fdsysset);
#ifdef USE_KMEM_CACHE
		kmem_cache_free(kmview_fdset_cache,kmt->fdset);
#else
		kfree(kmt->fdset);
#endif
	}
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

static inline int isinfdset(int fd, struct kmview_fdset *fdset)
{
	struct kmview_fdsysset *fdsysset=fdset->fdsysset;
	if (unlikely(fd < 0 || fd >= __FD_SETSIZE || fdsysset == NULL))
		return 0;
	return FD_ISSET(fd,&fdsysset->fdset);
}

static inline int iskmviewfd (unsigned long sysno, int fd, struct kmview_fdset *fdset,
		    int except_close, int except_fchdir) {
	if (!scbitmap_isset(fdsyscall,sysno))
		return 1;
	if (except_close && (sysno == __NR_close
#ifdef __NR_shutdown
				|| sysno == __NR_shutdown
#endif
				))
		return 1;
	if (except_fchdir && sysno == __NR_fchdir)
		return 1;
	return isinfdset(fd,fdset);
}

#ifdef __NR_socketcall
static inline int iskmviewsockfd(unsigned long socketcallno, int fd, struct kmview_fdset *fdset)
{
	if (!isfdsocket(socketcallno))
		return 1;
	return isinfdset(fd,fdset);
}
#endif

static inline unsigned int hashadd (long prevhash, char c) {
	  return prevhash ^ ((prevhash << 5) + (prevhash >> 2) + c);
}

static inline unsigned int hashsum (int sum,const char *path,int len) {
	int i;
	for (i=0;i<len;i++,path++)
		sum=hashadd(sum,*path);
	return sum;
}

static inline int ghosthash_match(struct ghosthash64 *gh,char *path)
{
	unsigned short len=strlen(path);
	unsigned short scanlen,pos;
	unsigned int scanhash;
	int i;
	for (i=0,scanhash=0,scanlen=pos=0;
			i<GH_SIZE && gh->deltalen[i] < GH_TERMINATE && len>=0;
			i++) {
		if (gh->deltalen[i] > 0) {
			scanhash=hashsum(scanhash,path,gh->deltalen[i]);
			path+=gh->deltalen[i];
			len -=gh->deltalen[i];
		}
		if (len >= 0 && scanhash == gh->hash[i])
			return len;
	}
	return -ENOENT;
}

static inline int ghosthash_match_lock(struct kmview_tracer *kmt,char *path) {
	unsigned long flags;
	int rv;
	spin_lock_irqsave(&kmt->lock, flags);
	rv=ghosthash_match(&kmt->ghostmounts,path);
	spin_unlock_irqrestore(&kmt->lock, flags);
	return rv;
}

static inline int kmview_path_exceptions(struct kmview_thread* kmt,
		struct pt_regs *regs)
{
	int path_argno;
	char *path;
	if (scbitmap_isset(path0syscall,kmt->scno))
		path_argno=0;
	else if (scbitmap_isset(path1syscall,kmt->scno))
		path_argno=1;
	else if (scbitmap_isset(path2syscall,kmt->scno))
		path_argno=2;
	else if (scbitmap_isset(path3syscall,kmt->scno))
		path_argno=3;
	else 
		return 0;
	/*if (scbitmap_isset(atsyscall,kmt->scno) && 
			arch_n(regs,path_argno-1) != AT_FDCWD)
		return 0;*/
	path = getname((char __user *) arch_n(regs,path_argno));
	if (IS_ERR(path))
		return 0;
	if (path[0] == '/' && ghosthash_match_lock(kmt->tracer,path) >= 0) {
		putname(path);
		return 1;
	} else {
		putname(path);
		return 0;
	}
}

static u32 kmview_syscall_entry(u32 action, struct utrace_engine *engine,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
		struct task_struct *tsk,
#endif
		struct pt_regs *regs)
{
	struct kmview_thread* kmt = (struct kmview_thread*)engine->data;
#ifdef KMVIEW_DEBUG
	printk("syscall entry(%d) A:%x : %ld %ld regs...\n",kmt->task->pid,action,arch_scno(regs),arch_n(regs,0));
#endif

	if (kmt->tracer) {
		int tracer_flags=atomic_read(&kmt->tracer->flags);
		kmt->scno=arch_scno(regs);

		if (scbitmap_isset_locked(kmt->tracer,kmt->scno)) 
			goto kmview_syscall_resume;
		if (tracer_flags & KMVIEW_FLAG_PATH_SYSCALL_SKIP &&
				scbitmap_isset(pathsyscall,kmt->scno)) {
			if ((kmt->flags & KMVIEW_THREAD_CHROOT) == 0) {
				if (!kmview_path_exceptions(kmt, regs))
					goto kmview_syscall_resume;
			}
		}
		/* skip select/poll if all the fds are real! */
		if (tracer_flags & KMVIEW_FLAG_FDSET) {
		 if (scbitmap_isset(selectpollsyscall,kmt->scno) && kmt->fdset->fdsysset == NULL)
			goto kmview_syscall_resume;
		 if ((kmt->scno == __NR_mmap 
#ifdef __NR_mmap2
					 || kmt->scno == __NR_mmap2
#endif
				 ) && !isinfdset(arch_n(regs,4),kmt->fdset))
			 goto kmview_syscall_resume;
		}
#ifdef __NR_socketcall
		if (tracer_flags & KMVIEW_FLAG_SOCKETCALL &&
				kmt->scno == __NR_socketcall) {
			unsigned long socketcallno=arch_n(regs,0);
			if (copy_from_user(&kmt->socketcallargs,(void *)arch_n(regs,1),
						socketcallnargs[socketcallno] * sizeof(unsigned long)))
				return kmview_abort_task(kmt->task);
			if (!(tracer_flags & KMVIEW_FLAG_FDSET)  ||
					iskmviewsockfd(socketcallno, kmt->socketcallargs[0], kmt->fdset)) {
				kmt->regs=regs;
				kmview_event_enqueue(KMVIEW_EVENT_SOCKETCALL_ENTRY,kmt,socketcallnargs[socketcallno],0);
				//printk("STOPs\n");
				return kmview_stop_task(kmt);
			} else 
				goto kmview_syscall_resume;
		} else
#endif
		if (!(tracer_flags & KMVIEW_FLAG_FDSET) ||
				 iskmviewfd(arch_scno(regs), arch_n(regs,0), kmt->fdset,
					 tracer_flags & KMVIEW_FLAG_EXCEPT_CLOSE,
					 tracer_flags & KMVIEW_FLAG_EXCEPT_FCHDIR)) {
			kmt->regs=regs;
			kmview_event_enqueue(KMVIEW_EVENT_SYSCALL_ENTRY,kmt,0,0);
			//printk("STOP\n");
			return kmview_stop_task(kmt);
		} else {
			goto kmview_syscall_resume;
		}
	} else 
		return kmview_abort_task(kmt->task);
kmview_syscall_resume:
	kmt->flags |= KMVIEW_THREAD_FLAG_SKIP_EXIT;
	kmt->flags &= ~KMVIEW_THREAD_FLAG_SKIP_CALL;
	return UTRACE_RESUME;
}

static u32 kmview_syscall_exit(enum utrace_resume_action action,
		struct utrace_engine *engine, 
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
		struct task_struct *tsk,
#endif
		struct pt_regs *regs)
{
	struct kmview_thread* kmt = (struct kmview_thread*)engine->data;
#ifdef KMVIEW_DEBUG
	printk("syscall exit(%d) A:%x : %ld %ld regs ...\n",kmt->task->pid,action,arch_scno(regs),arch_n(regs,0));
#endif
	if (kmt->tracer) {
		kmt->regs=regs;
		if(kmt->flags & KMVIEW_THREAD_FLAG_SKIP_CALL) /*restore call*/
			arch_scno(regs)=kmt->scno;
		if(kmt->flags & KMVIEW_THREAD_FLAG_SKIP_EXIT)
			return UTRACE_RESUME;
		else {
			kmview_event_enqueue(KMVIEW_EVENT_SYSCALL_EXIT,kmt,0,0);
			//printk("STOPx\n");
			return kmview_stop_task(kmt);
		}
	} else 
		return kmview_abort_task(kmt->task);
}

int kmview_trace_init(void)
{
#ifdef USE_KMEM_CACHE
	if ((kmview_thread_cache = KMEM_CACHE(kmview_thread, 0)) && 
			(kmview_module_event_cache = KMEM_CACHE(kmview_module_event, 0)) &&
			(kmview_fdset_cache = KMEM_CACHE(kmview_fdset, 0)))
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
	if (kmview_fdset_cache)
		        kmem_cache_destroy(kmview_fdset_cache);
#endif
}
