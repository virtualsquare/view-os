/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   services.c: management of virtualization services
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
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "services.h"
#include "defs.h"

/* servmap[service code] - 1 is the index of the service description into
 * 'services' */
static char servmap[255];

static int locked=0;
static int invisible=0;
static int noserv=0;
static int maxserv=0;
/* descriptor of all services */
static struct service **services=NULL;
static intfun reg_service,dereg_service;

#define OSER_STEP 8 /*only power of 2 values */
#define OSER_STEP_1 (OSER_STEP - 1)

static int s_error(int err)
{
	errno=err;
	return -1;
}

int add_service(struct service *s)
{
	if (invisible)
		return s_error(ENOSYS);
	else if (locked)
		return s_error(EACCES);
	else if (s->code == UM_NONE)
		return s_error(EFAULT);
	else if (servmap[s->code] != 0)
		return s_error(EEXIST);
	else {
		noserv++;
		if (noserv > maxserv) {
			maxserv= (noserv + OSER_STEP) & ~OSER_STEP_1;
			services= (struct service **) realloc (services, maxserv*sizeof(struct service *));
			assert(services);
		}
		services[noserv-1]=s;
		servmap[services[noserv-1]->code] = noserv;
		s->dlhandle=NULL;
		if (reg_service)
			reg_service(s->code);
		return 0;
	}
}

int set_handle_new_service(void *dlhandle,int position)
{
	if (noserv == 0 || services[noserv-1]->dlhandle != NULL)
		return s_error(EFAULT);
	else {
		services[noserv-1]->dlhandle = dlhandle;
		mov_service(services[noserv-1]->code,position);
		return 0;
	}
}

void *get_handle_service(service_t code) {
	int i=servmap[code]-1;
	if (invisible || locked || i<0)
		return NULL;
	else {
		return services[i]->dlhandle;
	}
}

int del_service(service_t code)
{
	if (invisible)
		return s_error(ENOSYS);
	else if (locked)
		return s_error(EACCES);
	else if (servmap[code] == 0)
		return s_error(ENOENT);
	else {
		int i;
		if (dereg_service)
			dereg_service(code);
		for (i= servmap[code]-1; i<noserv-1; i++)
			services[i]=services[i+1];
		noserv--;
		servmap[code] = 0;
		for (i=0;i<noserv;i++)
			servmap[services[i]->code] = i+1;
	}
	return 0;
}

int mov_service(service_t code, int position)
{
	if (invisible)
		return s_error(ENOSYS);
	else if (locked)
		return s_error(EACCES);
	else if (servmap[code] == 0)
		return s_error(ENOENT);
	else {
		int i;
		int oldposition=servmap[code]-1;
		struct service *s=services[oldposition];
		position--;
		if (position < 0 || position >= noserv)
			position=noserv-1;
		if (position < oldposition) /* left shift */
		{
			for (i=oldposition; i>position; i--)
				services[i]=services[i-1];
			assert(i==position);
			services[i]=s;
		}
		else if (position > oldposition) /*right shift */
		{
			for (i=oldposition; i<position; i++)
				services[i]=services[i+1];
			assert(i==position);
			services[i]=s;
		}
		for (i=0;i<noserv;i++)
			servmap[services[i]->code] = i+1;
		return 0;
	}
}

int list_services(service_t *buf,int len)
{
	if (invisible)
		return s_error(ENOSYS);
	else if (len < noserv)
		return s_error(ENOBUFS);
	{
		int i;
		for (i=0;i<noserv;i++)
			buf[i]=services[i]->code;
		return noserv;
	}
}

int name_service(service_t code,char *buf,int len)
{
	if (invisible)
		return s_error(ENOSYS);
	else if (servmap[code] == 0)
		return s_error(ENOENT);
	else {
		int pos=servmap[code]-1;
		struct service *s=services[pos];
		strncpy(buf,s->name,len-1);
		buf[len]=0;
		return 0;
	}
}

void lock_services()
{
	locked=1;
}

void invisible_services()
{
	invisible=1;
}

void service_addproc(service_t code,int id,int max, void *arg)
{
	int pos;
	if (code == UM_NONE) {
		for (pos=0;pos<noserv;pos++)
			if (services[pos]->addproc)
				services[pos]->addproc(id,max,arg);
	} else {
		int pos=servmap[code]-1;
		if (services[pos]->addproc)
				services[pos]->addproc(id,max,arg);
	}
}

void service_delproc(service_t code,int id, void *arg)
{
	int pos;
	if (code == UM_NONE) {
		for (pos=0;pos<noserv;pos++)
			if (services[pos]->delproc)
				services[pos]->delproc(id,arg);
	} else {
		int pos=servmap[code]-1;
		if (services[pos]->delproc)
				services[pos]->delproc(id,arg);
	}
}

service_t service_path(char *path,void *umph)
{
	int i;
	if (path == NULL) 
		return(UM_NONE);
	else {
		for (i=0;i<noserv;i++) {
			struct service *s=services[i];
			if (s->checkpath != NULL && s->checkpath(path,umph))
				return(s->code);
		}
		return(UM_NONE);
	}
}

//char service_socket(int domain, int type, int protocol)
service_t service_socket(int domain,void *umph)
{
	int i;
	for (i=0;i<noserv;i++) {
		struct service *s=services[i];
		//if (s->checksocket != NULL && s->checksocket(domain, type, protocol))
		if (s->checksocket != NULL && s->checksocket(domain,umph))
			return(s->code);
	}
	return(UM_NONE);
}

static int errnosys()
{
	errno=ENOSYS;
	return -1;
}

intfun service_syscall(service_t code, int scno)
{
	if (code == UM_NONE)
		return NULL;
	else {
		int pos=servmap[code]-1;
		struct service *s=services[pos];
		assert( s != NULL);
		return (s->syscall[scno] == NULL) ? errnosys : s->syscall[scno];
	}
}

intfun service_socketcall(service_t code, int scno)
{
	if(code == UM_NONE)
		return NULL;
	else {
		int pos=servmap[code]-1;
		struct service *s=services[pos];
		assert( s != NULL );
		return (s->socket[scno] == NULL) ? errnosys : s->socket[scno];
	}
}


intfun service_select_register(service_t code)
{
	int pos=servmap[code]-1;
	struct service *s=services[pos];
	return (s->select_register);
}

void _service_init(intfun register_service,intfun deregister_service)
{
	reg_service=register_service;
	dereg_service=deregister_service;
}
