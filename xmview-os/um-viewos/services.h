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

struct service {
	char *name;
	service_t code;
	void *handle;
	intfun checkpath;
	intfun checksocket;
	intfun select_register;
	intfun *syscall;
	intfun *socket;
};

#define UM_NONE 0xff
int add_service(struct service *s);
int set_handle_new_service(void *handle,int position);
void *get_handle_service(service_t code);
int del_service(service_t code);
int mov_service(service_t code, int position);
int list_services(service_t *buf,int len);
int name_service(service_t code,char *buf,int len);
void lock_services();
void invisible_services();
service_t service_path(char *path);
service_t service_socket(int domain);
intfun service_syscall(service_t code, int scno);
intfun service_socketcall(service_t code, int scno);
intfun service_select_register(service_t code);

#endif
