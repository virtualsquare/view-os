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

#ifndef KMVIEW_ACCESS_PROCESS
#define KMVIEW_ACCESS_PROCESS
int kmview_access_process_vm(struct task_struct *tsk, unsigned long addr, char __user *ubuf, int len, int write, int string);
#endif
