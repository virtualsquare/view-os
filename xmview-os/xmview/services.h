/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   services.h: structure for service mgmt
 *   
 *   Copyright 2005 Renzo Davoli University of Bologna - Italy
 *   
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License, version 2, as
 *   published by the Free Software Foundation.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA.
 *
 *   $Id$
 *
 */   
#ifndef __SERVICES_H
#define __SERVICES_H
#include "treepoch.h"

typedef long (*sysfun)();

typedef unsigned long c_set;
#define MC_USER 1
#define MC_CORECTLCLASS(x) ((x) << 1)
#define MC_CORECTLOPT(x) ((x) << 6)
#define MC_USERCTL(ctl) (MC_USER | (ctl << 1))

#define MC_PROC			MC_CORECTLCLASS(0)
#define MC_MODULE		MC_CORECTLCLASS(1)
#define MC_MOUNT		MC_CORECTLCLASS(2)

#define MC_ADD			MC_CORECTLOPT(0)
#define MC_REM			MC_CORECTLOPT(1)

#define MCH_SET(c, set)		*(set) |= (1 << c)
#define MCH_CLR(c, set)		*(set) &= ~(1 << c)
#define MCH_ISSET(c, set)	(*(set) & (1 << c))
#define MCH_ZERO(set)		*(set) = 0;

#define PSEUDO_CHECK  0x80
#define CHECKMODULE   0
#define CHECKPATH     1
#define CHECKSOCKET   2
#define CHECKCHRDEVICE   3
#define CHECKBLKDEVICE   4
#define CHECKSC 5
#define CHECKBINFMT 6
#define CHECKFSALIAS 7
#define NCHECKS 8
#define CHECKFSTYPE      (PSEUDO_CHECK | CHECKMODULE)
#define CHECKPATHEXACT   (PSEUDO_CHECK | CHECKPATH)

// for IOCTL mgmt
#define CHECKIOCTLPARMS   0x40000000
#define IOCTLLENMASK      0x07ffffff
#define IOCTL_R           0x10000000
#define IOCTL_W           0x20000000
	
#define BINFMT_MODULE_ALLOC 1
#define BINFMT_KEEP_ARG0 2
struct binfmt_req {
	char *path;
	char *interp;
	char *extraarg;
	char *buf;
	int flags;
};

struct ht_elem;

#define ERESTARTSYS 512

struct service {
	char *name;
	char *description;

	/* handle to service data. It is used by um_service.c to store
	 * dynamic lib handle (see dlopen (3))*/
	void *dlhandle;
	/* destructor for ht_elem's defined by this module */
	void (*destructor)(int type, struct ht_elem *hte);

	/* Generic notification/callback function. See ../include/module.h for
	 * details. */
	long (*ctl)();

	/* Mask of ctl classes for which the module want synthetized
	 * notifications. For example, at module loading time, it may want one
	 * ctl(MC_PROC | MC_ADD) for each currently running process.
	 */
	c_set ctlhs;

	/* 
	 * 	(int fd, void *req) 
	 *  returns: the length of the field bit_or IOCTL_R/IOCTL_W if the parameter is input/output
	 */
	sysfun ioctlparms;

	/* proactive management of select/poll system call. The module provides this function
	 * to activate a callback when an event occurs.
	 * it has the followin args:
	 * (void (* cb)(), void *arg, int fd, int how)   
	 * cb: the callback function (if NULL, it means that a previous registration for callback
	 *     must be deleted).
	 * arg: argument passed to the callback function
	 * fd: fd (i.e. sfd, the fd as seen by the service module)
	 * how: 0x1 READ_OK, 0x2 WRITE_OK, 0x4 EXTRA
	 */
	sysfun event_subscribe;

	/* the syscall table, the arguments are the same of the "real world" syscalls,*/
	sysfun *um_syscall;

	/* the socket call table, the arguments are the same of the "real world" syscalls,*/
	sysfun *um_socket;

	/* the virtual call table, the arguments are the same of the "real world" syscalls,*/
	sysfun *um_virsc;
};

#define UM_NONE 0xff
#define UM_ERR 0x00

int add_service(char *file,int permanent);
int del_service(char *name);
int list_services(char *buf,int len);
int name_service(char *name,char *buf,int len);
void service_ctl(unsigned long type, char *sender, char *destination, ...);
void _service_init();
void service_addregfun(int, sysfun, sysfun);

#endif
