/*
 * Main kmview module file.
 * 	(part of the View-OS project: wiki.virtualsquare.org) 
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

#include <linux/init.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/cdev.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/ioctl.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/poll.h>
#include <linux/cache.h>
#include <asm/unistd.h>
#include "kmview_data.h"
#include "kmview_alloc.h"
#include "kmview_trace.h"
#include "kmview_fdsysset.h"
#include "kmview_arch.h"
#include "kmview_accessvm.h"
//#define KMDEBUG
#define KMVIEW_VERSION 1

MODULE_LICENSE("GPL");
MODULE_AUTHOR("VIEW-OS TEAM");
MODULE_DESCRIPTION("VIEW-OS Kernel Module");

#define VIEWOS_MINOR 233

#if BITS_PER_LONG==32
unsigned long fdsyslist[]=FDSYSCALL32;
#ifdef __NR_socketcall
unsigned long fdsocketlist=FDSOCKETCALL32;
#endif
#endif
#if BITS_PER_LONG==64
unsigned long fdsyslist[]=FDSYSCALL64;
#ifdef __NR_socketcall
unsigned long fdsocketlist=FDSOCKETCALL64;
#endif
#endif

int kmview_major =   0;
int kmview_minor =   VIEWOS_MINOR;

module_param(kmview_major, int, S_IRUGO);
module_param(kmview_minor, int, S_IRUGO);

#ifdef USE_KMEM_CACHE
static struct kmem_cache *kmview_tracer_cache;
#endif

static int kmview_open(struct inode *inode, struct file *filp)
{   
	struct kmview_tracer *kmt;
#ifdef USE_KMEM_CACHE
	kmt=kmem_cache_alloc(kmview_tracer_cache, GFP_KERNEL);
#else
	kmt=kmalloc(sizeof(struct kmview_tracer), GFP_KERNEL);
#endif
	if (!kmt)
		        return -ENOMEM;
#ifdef KMDEBUG
	printk("NEW_TRACER %d %p\n",current->pid,kmt);
#endif
	init_MUTEX(&kmt->sem);
	init_waitqueue_head(&kmt->event_waitqueue);
	kmt->task=current;
	kmt->ntraced=0;
	kmt->flags=0;
	kmt->magicpoll_addr=0;
	kmt->magicpoll_cnt=0;
	INIT_LIST_HEAD(&kmt->event_queue);
    // each open at our device has at one and only one tracer.
    // so i fill private_data with the pointer of the tracer in order
    // to retrieve it simply.
	filp->private_data = kmt;
	return 0;
}

static void terminated_tracer_kill_threads(struct kmpid_struct *kms,void *arg)
{
	struct kmview_tracer *kmt=arg;
	if (kms->km_thread->tracer == kmt || kmt==NULL) 
		kmview_thread_free(kms->km_thread, 1);
}

static void terminated_tracer_cleanup_msgqueue(struct kmview_tracer *kmt)
{
	struct kmview_module_event *module_event;
	while (!list_empty(&kmt->event_queue)) {
		module_event=list_entry(kmt->event_queue.next,struct kmview_module_event,eventlist );
		list_del(&module_event->eventlist);
		kmview_module_event_free(module_event);
	}
}

static int kmview_release(struct inode *inode, struct file *filp)
{
	struct kmview_tracer *kmt=filp->private_data;
#ifdef KMDEBUG
	printk("TRACER_TERMINATED %d %p\n",current->pid,kmt);
#endif
	if(down_interruptible(&kmt->sem))
		return -EIO;
	/* cleanup 1: kill all the processes of this treacer */
	kmpid_forall(terminated_tracer_kill_threads,kmt);
	/* cleanup 2: empty the pending event queue */
	terminated_tracer_cleanup_msgqueue(kmt);
	up(&kmt->sem);
#ifdef USE_KMEM_CACHE
	kmem_cache_free(kmview_tracer_cache,kmt);
#else
	kfree(kmt);
#endif
	return 0;
}

/* be careful: must be called inside kmt->sem mutex*/
static int kmview_fill_event(struct kmview_tracer *kmt, struct kmview_event *event)
{
	struct kmview_module_event *module_event;
	int len=0;
	register int i;
	module_event=list_entry(kmt->event_queue.next,struct kmview_module_event,eventlist );
	event->tag=module_event->tag;
	switch(event->tag) {
		case KMVIEW_EVENT_NEWTHREAD:
			event->x.newthread.kmpid=module_event->thread->kmpid;
			event->x.newthread.pid=module_event->thread->task->pid;
			event->x.newthread.umppid=module_event->arg;
			event->x.newthread.flags=module_event->arg2;
			len=sizeof(unsigned long)+sizeof(struct kmview_event_newthread);
			break;
		case KMVIEW_EVENT_TERMTHREAD:
			event->x.termthread.umpid=module_event->thread->umpid;
			event->x.termthread.remaining=module_event->arg;
			kmview_thread_free(module_event->thread,0);
			len=sizeof(unsigned long)+sizeof(struct kmview_event_termthread);
			break;
		case KMVIEW_EVENT_SYSCALL_ENTRY:
			event->x.syscall.x.umpid=module_event->thread->umpid;
			event->x.syscall.scno=arch_scno(module_event->thread->regs);
			for (i=0;i<6;i++)
				event->x.syscall.args[i]=arch_n(module_event->thread->regs,i);
			event->x.syscall.pc=arch_pc(module_event->thread->regs);
			event->x.syscall.sp=arch_sp(module_event->thread->regs);
			//printk("SYS sp %lx pc %lx\n", event->x.socketcall.sp, event->x.socketcall.pc);
			len=sizeof(unsigned long)+sizeof(struct kmview_event_ioctl_syscall);
			break;
		case KMVIEW_EVENT_SYSCALL_EXIT:
			event->x.sysreturn.x.umpid=module_event->thread->umpid;
			event->x.sysreturn.retval=arch_get_rv(module_event->thread->regs);
			event->x.sysreturn.erno=arch_get_errno(module_event->thread->regs);
			len=sizeof(unsigned long)+sizeof(struct kmview_event_ioctl_sysreturn);
			break;
#ifdef __NR_socketcall
		case KMVIEW_EVENT_SOCKETCALL_ENTRY:
			event->x.socketcall.x.umpid=module_event->thread->umpid;
			event->x.socketcall.scno=arch_n(module_event->thread->regs,0);
			for (i=0;i<module_event->arg;i++)
				event->x.socketcall.args[i]=module_event->thread->socketcallargs[i];
			for (i=0;i<6;i++) 
				module_event->thread->socketcallargs[i]=arch_n(module_event->thread->regs,i);
			event->x.socketcall.pc=arch_pc(module_event->thread->regs);
			event->x.socketcall.sp=arch_sp(module_event->thread->regs);
			event->x.socketcall.addr=arch_n(module_event->thread->regs,1);
			//printk("SOCK sp %lx pc %lx\n", event->x.socketcall.sp, event->x.socketcall.pc);
			len=sizeof(unsigned long)+sizeof(struct kmview_event_socketcall);
			break;
#endif
	}
	list_del(&module_event->eventlist);
	kmview_module_event_free(module_event);
	return len;
}

static ssize_t kmview_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos)
{
	struct kmview_tracer *kmt=filp->private_data;
	struct kmview_event *event=(struct kmview_event *)buf;
	int len;

#ifdef KMDEBUG
	printk("READ pending %d %p %d %d\n",current->pid,kmt,count,sizeof(*event));
#endif
	if(count < sizeof(*event))
		return -EINVAL;
	if(wait_event_interruptible(kmt->event_waitqueue, !list_empty(&kmt->event_queue)))
		return -EAGAIN;
	if(down_interruptible(&kmt->sem))
		return -EIO;

	len=kmview_fill_event(kmt,event);
#ifdef KMDEBUG
	printk("READ %d %p\n",current->pid,kmt);
#endif
	up(&kmt->sem);
	return len;
}

static int kmview_ioctl(struct inode *inode, struct file *filp,
		                       unsigned int cmd, unsigned long arg)
{
	struct kmview_tracer *kmt=filp->private_data;
	long ret=0;
	register int i;
	int locked;

	if(down_interruptible(&kmt->sem))
		return -EIO;
	locked=1;
#ifdef KMDEBUG
	printk("IOCTL %d %x %p\n",current->pid,cmd,kmt);
#endif
	switch(cmd) {
		case KMVIEW_GET_VERSION:
			ret=KMVIEW_VERSION;
			break;
		case KMVIEW_SET_FLAGS:
			if (kmt->ntraced > 0)
				ret=-EACCES;
			else
				kmt->flags = arg;
			break;
		case KMVIEW_MAGICPOLL:
			{
				struct kmview_magicpoll kmmagicpoll;
				if (kmt->ntraced > 0)
					ret=-EACCES;
				else if (copy_from_user(&kmmagicpoll, (void *)arg, sizeof(kmmagicpoll))) {
					ret = -EFAULT;
				} else {
					kmt->magicpoll_addr=kmmagicpoll.magicpoll_addr;
					kmt->magicpoll_cnt=kmmagicpoll.magicpoll_cnt;
				}
				break;
			}
		case KMVIEW_ATTACH:
			if (kmt->task->pid != current->real_parent->pid)
				ret=-EPERM;
			else {
				up(&kmt->sem);
				locked=0;
				kmview_root_thread(current,kmt);
			}
			break;
		case KMVIEW_UMPID:
			{
				struct kmview_ioctl_umpid umpidarg;
				struct kmpid_struct *kmpids;
				if (copy_from_user(&umpidarg, (void *)arg, sizeof(umpidarg))) {
					ret = -EFAULT;
				} else {
					if ((kmpids=kmpid_search(umpidarg.kmpid))==NULL ||
							kmpids->km_thread->tracer != kmt)
						ret=-EPERM;
					else 
						kmpids->km_thread->umpid=umpidarg.umpid;
				}
				break;
			}
		case KMVIEW_SYSRESUME:
			{
				pid_t kmpid=arg;
				struct kmpid_struct *kmpids;
				if ((kmpids=kmpid_search(kmpid))==NULL ||
						kmpids->km_thread->tracer != kmt)
					ret=-EPERM;
				else {
					//printk("KMVIEW_SYSRESUME\n");
					kmpids->km_thread->flags |= KMVIEW_THREAD_FLAG_SKIP_EXIT;
					kmpids->km_thread->flags &= ~KMVIEW_THREAD_FLAG_SKIP_CALL;
					kmview_kmpid_resume(kmpid);
				}
				break;
			}
		case KMVIEW_SYSVIRTUALIZED:
		case KMVIEW_SYSRETURN:
			{
				struct kmpid_struct *kmpids;
				struct kmview_event_ioctl_sysreturn umsysreturn;
				if (copy_from_user(&umsysreturn, (void *)arg, sizeof(umsysreturn)))
					ret = -EFAULT;
				else if ((kmpids=kmpid_search(umsysreturn.x.kmpid))==NULL ||
						kmpids->km_thread->tracer != kmt)
					ret=-EPERM;
				else {
					arch_put_rv_errno(kmpids->km_thread->regs,umsysreturn.retval,umsysreturn.erno);
					/* if everything succeeded, restart the process */
					if (cmd == KMVIEW_SYSVIRTUALIZED) {
						arch_scno(kmpids->km_thread->regs)=-1;
						kmpids->km_thread->flags |= KMVIEW_THREAD_FLAG_SKIP_BOTH;
					} else { /* cmd == KMVIEW_SYSRETURN */
#ifdef __NR_socketcall
						if (kmpids->km_thread->scno == __NR_socketcall) {
							for(i=0;i<6;i++)
								arch_n(kmpids->km_thread->regs,i)=kmpids->km_thread->socketcallargs[i];
						}
#endif
						kmpids->km_thread->flags &= ~KMVIEW_THREAD_FLAG_SKIP_BOTH;
					}
					//printk("KMVIEW_SYSRETURN\n");
					kmview_kmpid_resume(umsysreturn.x.kmpid);
				}
				break;
			}
		case KMVIEW_SYSMODIFIED:
		case KMVIEW_SYSARGMOD:
			{
				struct kmpid_struct *kmpids;
				struct kmview_event_ioctl_syscall umsyscall;
				if (copy_from_user(&umsyscall, (void *)arg, sizeof(umsyscall)))
					ret = -EFAULT;
				else if ((kmpids=kmpid_search(umsyscall.x.kmpid))==NULL ||
						kmpids->km_thread->tracer != kmt)
					ret=-EPERM;
				else {
					/*printk("MODI PRE %ld %lx %lx sp %lx pc %lx--",arch_scno(kmpids->km_thread->regs),
							arch_n(kmpids->km_thread->regs,0),
							arch_n(kmpids->km_thread->regs,1),
							arch_sp(kmpids->km_thread->regs),
							arch_pc(kmpids->km_thread->regs));*/
					arch_scno(kmpids->km_thread->regs)=umsyscall.scno;
					for(i=0;i<6;i++)
						arch_n(kmpids->km_thread->regs,i)=umsyscall.args[i];
					arch_pc(kmpids->km_thread->regs)=umsyscall.pc;
					arch_sp(kmpids->km_thread->regs)=umsyscall.sp;
					/*printk("MODI POST %ld %lx %lx sp %lx pc %lx\n",arch_scno(kmpids->km_thread->regs),
							arch_n(kmpids->km_thread->regs,0),
							arch_n(kmpids->km_thread->regs,1),
							arch_sp(kmpids->km_thread->regs),
							arch_pc(kmpids->km_thread->regs));*/
					kmpids->km_thread->flags &= ~KMVIEW_THREAD_FLAG_SKIP_BOTH;
					if (cmd==KMVIEW_SYSARGMOD)
						kmpids->km_thread->flags |= KMVIEW_THREAD_FLAG_SKIP_EXIT;
					//printk("KMVIEW_SYSMODIFIED\n");
					kmview_kmpid_resume(umsyscall.x.kmpid);
				}
				break;
			}
		case KMVIEW_READDATA:
		case KMVIEW_READSTRINGDATA:
		case KMVIEW_WRITEDATA:
			{
				struct kmview_ioctl_data umpiddata;
				struct kmpid_struct *kmpids;
				if (copy_from_user(&umpiddata, (void *)arg, sizeof(umpiddata))) 
					ret = -EFAULT;
				else if ((kmpids=kmpid_search(umpiddata.kmpid))==NULL ||
						kmpids->km_thread->tracer != kmt)
					ret=-EPERM;
				else  {
					switch (cmd) {
						case KMVIEW_READDATA:
							ret=kmview_access_process_vm(kmpids->km_thread->task,
									umpiddata.addr,
									umpiddata.localaddr,
									umpiddata.len,0,0);
							break;
						case KMVIEW_READSTRINGDATA:
							ret=kmview_access_process_vm(kmpids->km_thread->task,
									umpiddata.addr,
									umpiddata.localaddr,
									umpiddata.len,0,1);
							break;
						case KMVIEW_WRITEDATA:
						default:
							ret=kmview_access_process_vm(kmpids->km_thread->task,
									umpiddata.addr,
									umpiddata.localaddr,
									umpiddata.len,1,0);
							break;
					}
				}
				break;
			}
		case KMVIEW_ADDFD:
		case KMVIEW_DELFD:
			{
				struct kmview_fd kmview_fdarg;
				struct kmpid_struct *kmpids;
				if (copy_from_user(&kmview_fdarg, (void *)arg, sizeof(kmview_fdarg))) 
					ret = -EFAULT;
				else if ((kmpids=kmpid_search(kmview_fdarg.kmpid))==NULL ||
						kmpids->km_thread->tracer != kmt)
					ret=-EPERM;
				else if ((kmview_fdarg.fd < 0) || (kmview_fdarg.fd >= __FD_SETSIZE))
					ret=-EINVAL;
				else {
					if (cmd == KMVIEW_ADDFD) 
						kmpids->km_thread->fdset=fdsysset_set(kmview_fdarg.fd,kmpids->km_thread->fdset);
					else /*KMVIEW_DELFD*/
						kmpids->km_thread->fdset=fdsysset_clr(kmview_fdarg.fd,kmpids->km_thread->fdset);
				}
			break;
			}
		default:
			ret = -ENOIOCTLCMD;
	}
	if (locked)
		up(&kmt->sem);
	return ret;
}

static unsigned int kmview_poll(struct file *filp,
		struct poll_table_struct *wait)
{
	struct kmview_tracer *kmt=filp->private_data;
	long ret;

	if(down_interruptible(&kmt->sem))
		return -EIO;
	poll_wait(filp, &kmt->event_waitqueue, wait);
#ifdef KMDEBUG
	printk("POLL %d\n",current->pid);
#endif
	if (list_empty(&kmt->event_queue))
		ret=0;
	else {
		if (kmt->magicpoll_addr) {
			int i;
			unsigned long addr;
			struct kmview_event event;
			for (i=0,addr=kmt->magicpoll_addr;
					i<kmt->magicpoll_cnt && !(list_empty(&kmt->event_queue));
					i++,addr+=sizeof(event))
			{
				kmview_fill_event(kmt, &event);
				if (copy_to_user((void *)addr, &event, sizeof(event)))
				{
					up(&kmt->sem);
					return -EACCES;
				}
				/* if the event is a KMVIEW_EVENT_NEWTHREAD, do not fill the
				 * magicpoll event array. The KMVIEW_EVENT_NEWTHREAD must be
				 * processed prior to any other event of the same process 
				 * (a KMVIEW_UMPID call is needed to assign an umpid */
				if (event.tag == KMVIEW_EVENT_NEWTHREAD) {
					i++;
					break;
				}
			}
			if (i<kmt->magicpoll_cnt) {
				event.tag=KMVIEW_EVENT_NONE;
				if (copy_to_user((void *)addr, &event, sizeof(unsigned long)))
				{
					up(&kmt->sem);
					return -EACCES;
				}
			}
		} 
		ret=POLLIN;
	}
	up(&kmt->sem);
	return ret;
}

struct file_operations kmview_fops = {
	.owner = THIS_MODULE,
	.open  = kmview_open,
	.release = kmview_release,
	.read  = kmview_read,
	.ioctl = kmview_ioctl,
	.poll = kmview_poll
};

static struct miscdevice kmview_dev =
{
	.minor      = VIEWOS_MINOR,
	.name       = "kmview",
	.fops       = &kmview_fops,
};

static void kmview_exit(void)
{
	if(kmview_major)
		unregister_chrdev(kmview_major, "kmview");
	else
		misc_deregister (&kmview_dev);

	kmpid_fini();
	fdsysset_fini();
	kmview_trace_fini();
#ifdef USE_KMEM_CACHE
	if (kmview_tracer_cache)
		    kmem_cache_destroy(kmview_tracer_cache);
#endif
}

static int kmview_init(void)
{
	int result;

	if (kmview_major) {
		result = register_chrdev(kmview_major, "kmview", &kmview_fops);
		if (result < 0) {
			printk("kmview: could not get major %d\n", kmview_major);
			return result;
		}
	} else {
		result=misc_register(&kmview_dev);
		if (result < 0) {
			printk("kmview: could not create device\n");
			return result;
		}
	}
	kmpid_init();
#ifdef USE_KMEM_CACHE
	kmview_tracer_cache = KMEM_CACHE(kmview_tracer, 0);
	if (!kmview_tracer_cache) {
		printk("kmview: memory error\n");
		kmview_exit();
		return -ENOMEM;
	}
#endif
	if (kmview_trace_init() < 0) {
		printk("kmview: memory error\n");
		kmview_exit();
		return result;
	}
	if (fdsysset_init() < 0) {
		printk("kmview: memory error\n");
		kmview_exit();
		return result;
	}
	return 0;
}

module_init(kmview_init);
module_exit(kmview_exit);

