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
#include <dlfcn.h>
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
// services maintain list of all modules loaded.
static struct service **services=NULL;

#ifdef NEW_SERVICE_LIST
#define registered_service_check service_check
// registered services sorted by registration requests
// FIX: 1) maybe better a dinamically allocated array?
//  2) when should be initialized?
static char registered_services[255];
static int registered_no = 0;

int new_register_service(struct service *s){
	printf("new_register_service: %d\n",s->code);
	registered_services[registered_no]=s->code;
	registered_no++;
	return registered_no;
}

// deregister tells if a module can be deleted from list of active modules
// dumb management: when serv_no is the last service registerd, it 
// can be deregistered, otherwise it can't...
int new_deregister_service(int serv_no){
	printf("new_deregister_service: %d\n",serv_no);
	if( serv_no == registered_no ){
		printf("\tderegister ok\n");
		registered_services[serv_no]=UM_NONE;
		registered_no--;
		return 1;
	}
	else{
		printf("\tdon't deregister \n");
		return 0;
	}
}

// retrieve service structure in sorted registered list of services
service_t registered_service_check(int type, void *arg,void *umph)
{
	int i,j;
/*    printf("new_registered_service_check: type: %d - %d \n",type, noserv);*/
	if (arg == NULL || noserv == 0) 
		return(UM_NONE);
	if ( registered_no != 0 ){
		for (i = registered_no-1 ; i>=0 ; i--) {
			struct service *s;
			unsigned char check_code = registered_services[i];
/*            printf("checking code:%u\n",check_code);*/
			for( j = 0; j<noserv ; j++)
				if( services[j]->code == check_code )
					s=services[j];
			if (s->checkfun != NULL && s->checkfun(type,arg,umph)){
/*                printf("\tregister choice: %d\n",s->code);*/
				return(s->code);
			}
		}
	}
	// if no services were found then we request if some module want 
	// to be registered.

/* NB: DEVELOPMENT PHASE !! */
	for (i=0 ; i<noserv ; i++) { //maybe: for (i = noserv-1 ; i>=0 ; i--)
		struct service *s=services[i];
/*
		if (s->checkfun != NULL && s->checkfun(type,arg,umph)){
			return s->code;
		}*/
		if (s->checkfun != NULL && s->checkfun(type | FLAG_WANTREGISTER,arg,umph)){
/*            new_register_service(s);*/
			fprintf(stderr,"passed through here... :-P \n");
			if( s->checkfun(type,arg,umph) )
				return s->code;
			else
				return UM_NONE;
		}
/**/
	}
	return(UM_NONE);
}
#endif

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

#ifndef NEW_SERVICE_LIST
service_t service_check(int type, void *arg,void *umph)
{
	int i;
	if (arg == NULL || noserv == 0) 
		return(UM_NONE);
	else {
// beginning to make some nesting-related changes
// in this case it make more sense in beginning from last inserted service.
		for (i=0 ; i<noserv ; i++) {
/*        for (i = noserv-1 ; i>=0 ; i--) {*/
			struct service *s=services[i];
			if (s->checkfun != NULL && s->checkfun(type,arg,umph))
				return(s->code);
		}
		return(UM_NONE);
	}
}
#endif

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
		return (s->um_syscall[scno] == NULL) ? errnosys : s->um_syscall[scno];
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

intfun service_checkfun(service_t code)
{
	int pos=servmap[code]-1;
	struct service *s=services[pos];
	return (s->checkfun);
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

void _service_fini()
{
	int i;
	void *hdl;
	for (i=0;i<0xff;i++)
		if ((hdl=get_handle_service(i)) != NULL)
			dlclose(hdl);
}

