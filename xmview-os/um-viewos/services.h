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

	/* pathname choice: returns TRUE if this path must be managed by this module
	 * FALSE otherwise.
	 * checkpath functions has the following args:
	 * 	(char *path) or
	 * 	(char *path, void *umph)
	 * path is either the absolute path of the file (has always a leading '/')
	 * or a filesystem type for mount system call.
	 */
	intfun checkpath;

	/* socket choice: returns TRUE if this socket must be managed by this module
	 * FALSE otherwise.
	 * checkpath functions has the following args:
	 * 	(int domain) or
	 * 	(int domain, void *umph)
	 * it is invoked when a process use a "socket" system call.
	 */
	intfun checksocket;

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
	intfun *syscall;

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
service_t service_path(char *path,void *umph);
service_t service_socket(int domain,void *umph);
intfun service_syscall(service_t code, int scno);
intfun service_socketcall(service_t code, int scno);
intfun service_select_register(service_t code);
void _service_init(intfun register_service,intfun deregister_service);

#endif
