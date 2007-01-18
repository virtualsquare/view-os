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
typedef unsigned char service_t;

#define CHECKNOCHECK 0 //to bee or not to bee!! :-D
#define CHECKPATH 1
#define CHECKSOCKET 2
#define CHECKFSTYPE 3
#define CHECKDEVICE 4
#define CHECKSC 5
#define CHECKBINMFT 6
// for IOCTL mgmt
#define CHECKIOCTLPARMS   0x40000000
#define IOCTLLENMASK      0x07ffffff
#define IOCTL_R           0x10000000
#define IOCTL_W           0x20000000
struct ioctl_len_req {
	int fd;
	int req;
};
	
#define BINFMT_MODULE_ALLOC 1
#define BINFMT_KEEP_ARG0 2
struct binfmt_req {
	char *path;
	char *interp;
	int flags;
};

#define ERESTARTSYS 512

struct service {
	char *name;
	service_t code;

	/* handle to service data. It is used by um_service.c to store
	 * dynamic lib handle (see dlopen (3))*/
	void *dlhandle;

	/*addproc is called when a new process is created
	 * (int umpid, int pumpid, int numproc)
	 * umpid is the um_pid pf the process, pumpid is the parent id
	 * max is the current max number of processes: service implementation can use it
	 * to realloc their internal structures*/
	sysfun addproc;

  /*delproc is called when a process terminates.
	 * is the garbage collection function for the data that addproc may have created
	 */
	sysfun delproc;

	/* choice function: returns TRUE if this path must be managed by this module
	 * FALSE otherwise.
	 * Nesting modules: returns the epoch of best match (0 if non found).
	 * checkfun functions has the following args:
	 * 	(int type, void *arg) 
	 * 	type is defined by CHECK... constants above
	 * if type == CHECKIOCTLPARMS
	 *  *arg is the ioctl code
	 *  returns: the length of the field bit_or IOCTL_R/IOCTL_W if the parameter is input/output
	 */
	epochfun checkfun;

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
	sysfun *socket;
};

#define UM_NONE 0xff
#define UM_ERR 0x00
int isnosys(sysfun f);
int add_service(struct service *s);
int set_handle_new_service(void *dlhandle,int position);
void *get_handle_service(service_t code);
int del_service(service_t code);
int mov_service(service_t code, int position);
int list_services(service_t *buf,int len);
int name_service(service_t code,char *buf,int len);
void lock_services();
void invisible_services();
void service_addproc(service_t code,int umpid, int pumpid, int max);
void service_delproc(service_t code,int umpid);
service_t service_check(int type,void *arg,int setepoch);
sysfun service_syscall(service_t code, int scno);
sysfun service_socketcall(service_t code, int scno);
epochfun service_checkfun(service_t code);
sysfun service_event_subscribe(service_t code);
void _service_init(sysfun register_service,sysfun deregister_service);

#endif
