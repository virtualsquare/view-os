/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   services.h: structure for service mgmt
 *   
 *   Copyright 2005 Renzo Davoli University of Bologna - Italy
 *   
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 *   $Id$
 *
 */   
#ifndef __SERVICES_H
#define __SERVICES_H

typedef int (*intfun)();
typedef unsigned char service_t;

/* all the control functions and system call implementations have an optional
 * "void *umph" (user-mode process handle) trailing argument.
 * This argument can be used to retrieve information about the calling process
 */

#define CHECKNOCHECK 0 //to bee or not to bee!! :-D
#define CHECKPATH 1
#define CHECKSOCKET 2
#define CHECKFSTYPE 3
#define CHECKDEVICE 4
#define CHECKSC 5
// for IOCTL mgmt
#define CHECKIOCTLPARMS   0x40000000
#define IOCTLLENMASK      0x07ffffff
#define IOCTL_R           0x10000000
#define IOCTL_W           0x20000000
struct ioctl_len_req {
	int fd;
	int req;
};
	
// flag that specifies register requests...
#define FLAG_WANTREGISTER	0x80000000

struct service {
	char *name;
	service_t code;

	/* handle to service data. It is used by um_service.c to store
	 * dynamic lib handle (see dlopen (3))*/
	void *dlhandle;

	/*addproc is called when a new process is created
	 * (int id, int max, void *umph)
	 * max is the current max number of processes: service implementation can use it
	 * to realloc their internal structures*/
	intfun addproc;

  /*delproc is called when a process terminates.
	 * is the garbage collection function for the data that addproc may have created
	 */
	intfun delproc;

	/* choice function: returns TRUE if this path must be managed by this module
	 * FALSE otherwise.
	 * checkfun functions has the following args:
	 * 	(int type, void *arg) or
	 * 	(int type, void *arg, void *umph)
	 * 	type is defined by CHECK... constants above
	 * if type == CHECKIOCTLPARMS
	 *  *arg is the ioctl code
	 *  returns: the length of the field bit_or IOCTL_R/IOCTL_W if the parameter is input/output
	 */
	intfun checkfun;

	/* proactive management of select/poll system call. The module provides this function
	 * to activate a callback when an event occurs.
	 * it has the followin args:
	 * (void (* cb)(), void *arg, int fd, int how)    (plus umph if needed)
	 * cb: the callback function (if NULL, it means that a previous registration for callback
	 *     must be deleted).
	 * arg: argument passed to the callback function
	 * fd: fd (i.e. sfd, the fd as seen by the service module)
	 * how: 0x1 READ_OK, 0x2 WRITE_OK, 0x4 EXTRA
	 */
	intfun select_register;

	/* the syscall table, the arguments are the same of the "real world" syscalls,
	 * plus umph if needed*/
	intfun *um_syscall;

	/* the socket call table, the arguments are the same of the "real world" syscalls,
	 * plus umph if needed*/
	intfun *socket;
};

#define UM_NONE 0xff
int add_service(struct service *s);
int set_handle_new_service(void *dlhandle,int position);
void *get_handle_service(service_t code);
int del_service(service_t code);
int mov_service(service_t code, int position);
int list_services(service_t *buf,int len);
int name_service(service_t code,char *buf,int len);
void lock_services();
void invisible_services();
void service_addproc(service_t code,int id,int max, void *arg);
void service_delproc(service_t code,int id, void *arg);
service_t service_check(int type,void *arg,void *umph);
intfun service_syscall(service_t code, int scno);
intfun service_socketcall(service_t code, int scno);
intfun service_checkfun(service_t code);
intfun service_select_register(service_t code);
void _service_init(intfun register_service,intfun deregister_service);

#endif
