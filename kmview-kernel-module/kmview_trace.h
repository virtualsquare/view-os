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

#ifndef _KMVIEW_TRACE_H
#define _KMVIEW_TRACE_H
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/module.h>

#include "kmview_data.h"
#include "kmview_alloc.h"

pid_t kmview_root_thread(struct task_struct *task, struct kmview_tracer *tracer);
void kmview_kmpid_resume(pid_t kmpid);
void kmview_thread_free(struct kmview_thread *kmt, int kill);
void kmview_module_event_free(struct kmview_module_event *kme);
int kmview_trace_init(void);
void kmview_trace_fini(void);
#endif
