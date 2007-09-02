/*
 * Main kmview module file.
 *  (part of the View-OS project: wiki.virtualsquare.org) 
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

#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>

/*
 * Access another process' address space to/from user space
 * Do not walk the page table directly, use get_user_pages
 */
int kmview_access_process_vm(struct task_struct *tsk, unsigned long addr, char __user *ubuf, int len, int write, int string)
{
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	struct page *page;
	char *buf;
	unsigned long old_addr = addr;

	mm = get_task_mm(tsk);
	if (!mm)
		return 0;

	buf=kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buf)
		return 0;

	down_read(&mm->mmap_sem);
	/* ignore errors, just check how much was sucessfully transfered */
	while (len) {
		int bytes, ret, offset;
		void *maddr;

		ret = get_user_pages(tsk, mm, addr, 1,
				write, 1, &page, &vma);
		if (ret <= 0)
			break;

		bytes = len;
		offset = addr & (PAGE_SIZE-1);
		if (bytes > PAGE_SIZE-offset)
			bytes = PAGE_SIZE-offset;

		maddr = kmap(page);
		if (write) {
			__copy_from_user(buf,ubuf,bytes);
			copy_to_user_page(vma, page, addr,
					maddr + offset, buf, bytes);
			if (!PageCompound(page))
				set_page_dirty_lock(page);
		} else {
			copy_from_user_page(vma, page, addr,
					buf, maddr + offset, bytes);
			if (string) {
				for (offset=0;offset<bytes;offset++)
					if (buf[offset]==0)
						break;
				if (offset < bytes)
					bytes=len=offset+1;
			}
			ret=__copy_to_user(ubuf,buf,bytes);
		}
		kunmap(page);
		page_cache_release(page);
		len -= bytes;
		ubuf += bytes;
		addr += bytes;
	}
	up_read(&mm->mmap_sem);
	mmput(mm);

	kfree(buf);
	return addr - old_addr;
}

