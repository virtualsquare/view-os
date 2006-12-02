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
#include "sctab.h"
#include "syscallnames.h"
#include "gdebug.h"
#include "scmap.h"
#include "bits/wordsize.h"

/* Each service module has its unique code 1..254 (0x01..0xfe)
	0x00 is UM_ERR and 0xff is UM_NONE */
/* When a module is loaded the index of the services array is loaded into
 * the corresponding element in servmap (if a module has its code 0x9b,
 * servmap[0x9b] -1 is the index where the service has been loaded.
 * (This method gives complexity O(1) to the service code 2
 * service implementation mapping)*/
/* servmap[service code] - 1 is the index of the service description into
 * 'services'. with -1 there is no need for initialization */
static char servmap[256];

static int locked=0;
static int invisible=0;
static int noserv=0;
static int maxserv=0;

/* the array "services" maintains list of all modules loaded.*/
/* the sorting of the array services is the search order */
static struct service **services=NULL;

static sysfun reg_service,dereg_service;

static struct syscall_unifier
{
	long proc_sc; // System call nr. as called by the process
	long mod_sc;  // System call nr. as seen by the module
} scunify[] = {
	{__NR_creat,	__NR_open},
	{__NR_readv,	__NR_read},
	{__NR_writev,	__NR_write},
	{__NR_time,	  __NR_gettimeofday},
#if ! defined(__x86_64__)
	{__NR_umount,	__NR_umount2},
	{__NR_stat,		__NR_stat64},
	{__NR_lstat,	__NR_lstat64},
	{__NR_fstat,	__NR_fstat64},
	{__NR_getdents,	__NR_getdents64},
	{__NR_truncate,	__NR_truncate64},
	{__NR_ftruncate,__NR_ftruncate64},
	{__NR_statfs,	__NR_statfs64},
	{__NR_fstatfs,	__NR_fstatfs64},
#endif 
};

#define SIZESCUNIFY (sizeof(scunify)/sizeof(struct syscall_unifier))

#define OSER_STEP 8 /*only power of 2 values */
#define OSER_STEP_1 (OSER_STEP - 1)

static int s_error(int err)
{
	errno=err;
	return -1;
}

/* System call remapping (i.e. stat->stat64, creat->open) etc.
 * This functions takes a struct service and, for each system call defined in
 * scunify[] (field proc_sc), sets the corresponding entry in the um_syscall array to be
 * the manager for syscall mod_sc. */
void modify_um_syscall(struct service *s)
{
	int i;

	for (i = 0; i < SIZESCUNIFY; i++)
	{
		GDEBUG(9, "i = %d < %d", i, SIZESCUNIFY);
		/* The entry in um_syscall is not NULL, so someone has defined a
		 * manager for this syscall. It won't be used, so print a warning.
		 * XXX This can cause false positives if the um_syscall is allocated
		 * with malloc (instead of calloc) and not memset'd to all NULLs. */
		if (s->um_syscall[uscno(scunify[i].proc_sc)])
		{
			GERROR("WARNING: a module has defined syscall %s that will not be used:",
					SYSCALLNAME(scunify[i].proc_sc));
			GERROR("         %s will be managed by the module function for %s.", 
					SYSCALLNAME(scunify[i].proc_sc), SYSCALLNAME(scunify[i].mod_sc));
		}

		s->um_syscall[uscno(scunify[i].proc_sc)] = s->um_syscall[uscno(scunify[i].mod_sc)];
	}
	GDEBUG(9, "i = %d >= %d", i, SIZESCUNIFY);
}

/* add a new service module */
int add_service(struct service *s)
{
	/* locking/error management */
	if (invisible)
		return s_error(ENOSYS);
	else if (locked)
		return s_error(EACCES);
	else if (s->code == UM_NONE || s->code == UM_ERR)
		return s_error(EFAULT);
	else if (servmap[s->code] != 0)
		return s_error(EEXIST);
	else {
		GDEBUG(9, "noserv == %d, adding 1", noserv);
		noserv++;
		/* the "services" array is realloc-ed when there are no more
		 * free elements */
		if (noserv > maxserv) {
			GDEBUG(9, "noserv > maxserv (%d > %d)", noserv, maxserv);
			maxserv= (noserv + OSER_STEP) & ~OSER_STEP_1;
			GDEBUG(9, "maxserv = %d", maxserv);
			services= (struct service **) realloc (services, maxserv*sizeof(struct service *));
			GDEBUG(9, "reallocating services to %d * %d", maxserv, sizeof(struct service*));
			assert(services);
		}
		/* set the new element */
		services[noserv-1]=s;
		/* set the servmap. noserv is the index where the service is, + 1 */
		servmap[services[noserv-1]->code] = noserv;
		/* dl handle is the dynamic library handle, it is set in a second time */
		s->dlhandle=NULL;
		if (reg_service)
			reg_service(s->code);
		modify_um_syscall(s);
		return 0;
	}
}

/* set the new service dl handle and move it to the right position */
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

/* get the dynamic library handle */
void *get_handle_service(service_t code) {
	int i=servmap[code]-1;
	if (invisible || locked || i<0)
		return NULL;
	else {
		return services[i]->dlhandle;
	}
}

/* delete a service */
int del_service(service_t code)
{
	/* locking and error management */
	if (invisible)
		return s_error(ENOSYS);
	else if (locked)
		return s_error(EACCES);
	else if (servmap[code] == 0)
		return s_error(ENOENT);
	else {
		int i;
		/* call deregistrationn upcall (if any) */
		if (dereg_service)
			dereg_service(code);
		/* compact the table */
		for (i= servmap[code]-1; i<noserv-1; i++)
			services[i]=services[i+1];
		noserv--;
		/* update the indexes in servmap */
		servmap[code] = 0;
		for (i=0;i<noserv;i++)
			servmap[services[i]->code] = i+1;
	}
	return 0;
}

/* mov a service */
int mov_service(service_t code, int position)
{
	/* locking and error management */
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
		/* shift the elements */
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
		/* update the indexes in servmap */
		for (i=0;i<noserv;i++)
			servmap[services[i]->code] = i+1;
		return 0;
	}
}

/* list services: returns a list of codes */
int list_services(service_t *buf,int len)
{
	/* error management */
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

/* name services:  maps a service code to its description */
int name_service(service_t code,char *buf,int len)
{
	/* error management */
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

void service_addproc(service_t code,int umpid, int pumpid,int max)
{
	int pos;
	GDEBUG(9, "code %d, umpid %d, pumpid %d, max %d", code, umpid, pumpid, max);
	if (code == UM_NONE) {
		for (pos=0;pos<noserv;pos++)
		{
			GDEBUG(9, "services[%d] == %p", services?services[pos]:(void *)(-1));
			if (services[pos]->addproc)
				services[pos]->addproc(umpid,pumpid,max);
		}
	} else {
		int pos=servmap[code]-1;
		if (services[pos]->addproc)
				services[pos]->addproc(umpid,pumpid,max);
	}
	GDEBUG(9, "done");
}

void service_delproc(service_t code,int id)
{
	int pos;
	if (code == UM_NONE) {
		for (pos=0;pos<noserv;pos++)
			if (services[pos]->delproc)
				services[pos]->delproc(id);
	} else {
		int pos=servmap[code]-1;
		if (services[pos]->delproc)
				services[pos]->delproc(id);
	}
}

service_t service_check(int type,void* arg,int setepoch)
{
	int i,max_index=-1;
	struct service* s;
	epoch_t	matchepoch=0;
	if (arg == NULL || noserv == 0) 
		return(UM_NONE);
	else {
		for (i = noserv-1 ; i>=0 ; i--) {
			epoch_t returned_epoch;
			s=services[i];
			if (s->checkfun != NULL && (returned_epoch=s->checkfun(type,arg)) &&
					(returned_epoch>matchepoch)) {
				matchepoch=returned_epoch;
				max_index=i;
			}
		}
		if (setepoch)
			um_setepoch(matchepoch);
		if(max_index<0)
			return(UM_NONE);
		else 
			return services[max_index]->code;
	}
}

/*
service_t service_check(int type, void *arg)
{
	int i;
	if (arg == NULL || noserv == 0) 
		return(UM_NONE);
	else {
		for (i = noserv-1 ; i>=0 ; i--) {
			struct service *s=services[i];
			if (s->checkfun != NULL && s->checkfun(type,arg))
				return(s->code);
		}
		return(UM_NONE);
	}
}
*/

static long errnosys()
{
	errno=ENOSYS;
	return -1;
}

int isnosys(sysfun f)
{
	return (f==errnosys);
}

sysfun service_syscall(service_t code, int scno)
{
	if (code == UM_NONE || code == UM_ERR)
		return NULL;
	else {
		int pos=servmap[code]-1;
		struct service *s=services[pos];
		assert( s != NULL);
		return (s->um_syscall[scno] == NULL) ? errnosys : s->um_syscall[scno];
	}
}

sysfun service_socketcall(service_t code, int scno)
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

epochfun service_checkfun(service_t code)
{
	int pos=servmap[code]-1;
	struct service *s=services[pos];
	return (s->checkfun);
}

sysfun service_event_subscribe(service_t code)
{
	int pos=servmap[code]-1;
	struct service *s=services[pos];
	return (s->event_subscribe);
}

static void _service_fini()
{
	/*
	int i;
	void *hdl;
	for (i=0;i<0xff;i++)
		if ((hdl=get_handle_service(i)) != NULL)
			dlclose(hdl);
			*/
}

/* service initialization: upcalls for new services/deleted services
 * may be supplied */
void _service_init(sysfun register_service,sysfun deregister_service)
{
	atexit(_service_fini);
	reg_service=register_service;
	dereg_service=deregister_service;
}

