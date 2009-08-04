/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   services.c: management of virtualization services
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
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <config.h>
#include <stdarg.h>
#include <linux/net.h>
#include "services.h"
#include "defs.h"
#include "sctab.h"
#include "syscallnames.h"
#include "gdebug.h"
#include "scmap.h"
#include "hashtab.h"
#include "bits/wordsize.h"

/* Each service module has its unique code 1..254 (0x01..0xfe) 0x00 is UM_ERR
 * and 0xff is UM_NONE.
 *
 * When a module is loaded the index of the services array is loaded into the
 * corresponding element in servmap (if a module has its code 0x9b,
 * servmap[0x9b] -1 is the index where the service has been loaded.  (This
 * method gives complexity O(1) to the service code 2 service implementation
 * mapping)
 *
 * servmap[service code] - 1 is the index of the service description into
 * 'services'. with -1 there is no need for initialization.
 */
static char servmap[256];

static int noserv=0;
static int maxserv=0;

/* the array "services" maintains list of all modules loaded.*/
/* the sorting of the array services is the search order */
static struct service **services=NULL;

static sysfun reg_service[sizeof(c_set)], dereg_service[sizeof(c_set)];

struct syscall_unifier
{
	long proc_sc; // System call nr. as called by the process
	long mod_sc;  // System call nr. as seen by the module
};

static struct syscall_unifier scunify[] = {
	{__NR_creat,	__NR_open},
	{__NR_readv,	__NR_read},
	{__NR_writev,	__NR_write},
	{__NR_time,	  __NR_gettimeofday},
	{__NR_fchown,	__NR_chown},
	{__NR_fchmod,	__NR_chmod},
#if (__NR_olduname != __NR_doesnotexist)
	{__NR_olduname, __NR_uname},
#endif
#if (__NR_oldolduname != __NR_doesnotexist)
	{__NR_oldolduname, __NR_uname},
#endif
#if (__NR_setpgrp != __NR_doesnotexist)
	{__NR_setpgrp,__NR_setpgid},
#endif
	{__NR_getpgrp,__NR_getpgid},
#if ! defined(__x86_64__)
	{__NR_umount,	__NR_umount2},
	{__NR_stat,		__NR_stat64},
	{__NR_lstat,	__NR_lstat64},
	{__NR_fstat,	__NR_stat64},
	{__NR_fstat64,__NR_stat64},
	{__NR_getdents,	__NR_getdents64},
	{__NR_truncate,	__NR_truncate64},
	{__NR_ftruncate,__NR_ftruncate64},
	{__NR_statfs,	__NR_statfs64},
	{__NR_fstatfs,	__NR_statfs64},
	{__NR_fstatfs64,	__NR_statfs64},
#else
	{__NR_fstatfs,	__NR_statfs},
	{__NR_fstat,	__NR_stat},
#endif 
	{__NR_openat,	__NR_open},
	{__NR_mkdirat,	__NR_mkdir},
	{__NR_mknodat,	__NR_mknod},
	{__NR_fchownat,	__NR_chown},
	{__NR_futimesat,	__NR_utimes},
#ifdef __NR_utimensat
	{__NR_utimensat,	__NR_utimes},
#endif
	{__NR_utime,	__NR_utimes},
#ifdef __NR_newfstatat
	{__NR_newfstatat,	__NR_stat64},
#endif
#ifdef __NR_fstatat64
	{__NR_fstatat64,	__NR_stat64},
#endif
	{__NR_unlinkat,	__NR_unlink},
	{__NR_renameat,	__NR_rename},
	{__NR_linkat,	__NR_link},
	{__NR_symlinkat,	__NR_symlink},
	{__NR_readlinkat,	__NR_readlink},
	{__NR_fchmodat,	__NR_chmod},
	{__NR_faccessat,	__NR_access},
#if defined(__NR_getuid32) && __NR_getuid32 != __NR_getuid
	{__NR_getuid, __NR_getuid32},
	{__NR_getgid, __NR_getgid32},   
	{__NR_geteuid, __NR_geteuid32},
	{__NR_getegid, __NR_getegid32},
	{__NR_setreuid, __NR_setreuid32},
	{__NR_setregid, __NR_setregid32},
	{__NR_getgroups, __NR_getgroups32},
	{__NR_setgroups, __NR_setgroups32},
	{__NR_setresuid, __NR_setresuid32},
	{__NR_getresuid, __NR_getresuid32},
	{__NR_setresgid, __NR_setresgid32},
	{__NR_getresgid, __NR_getresgid32},
	{__NR_setuid, __NR_setuid32},
	{__NR_setgid, __NR_setgid32},
	{__NR_setfsuid, __NR_setfsuid32},
	{__NR_setfsgid, __NR_setfsgid32},
#endif
#if defined(__NR_chown32) && __NR_chown32 != __NR_chown
	//{__NR_chown, __NR_chown32},
	//{__NR_lchown, __NR_lchown32},
	//{__NR_fchown, __NR_chown32},
	{__NR_fchown32, __NR_chown32},
#endif
#ifdef SNDRCVMSGUNIFY
#if (__NR_socketcall == __NR_doesnotexist)
	{__NR_send, __NR_sendmsg},
	{__NR_sendto, __NR_sendmsg},
	{__NR_recv, __NR_recvmsg},
	{__NR_recvfrom, __NR_recvmsg},
#endif
#endif
};

#define SIZESCUNIFY (sizeof(scunify)/sizeof(struct syscall_unifier))
#if (__NR_socketcall != __NR_doesnotexist)
/*WIP this "unification" is not active yet */
static struct syscall_unifier sockunify[] = {
#ifdef SNDRCVMSGUNIFY
/* unify to *msg */
	{SYS_SEND, SYS_SENDMSG},
	{SYS_SENDTO, SYS_SENDMSG},
	{SYS_RECV, SYS_RECVMSG},
	{SYS_RECVFROM, SYS_RECVMSG},
#endif
};

#define SIZESOCKUNIFY (sizeof(sockunify)/sizeof(struct syscall_unifier))
#endif

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
#if (__NR_socketcall != __NR_doesnotexist)
	for (i = 0; i < SIZESOCKUNIFY; i++)
	{
		GDEBUG(9, "i = %d < %d", i, SIZESOCKUNIFY);
		/* The entry in um_syscall is not NULL, so someone has defined a
		 * manager for this syscall. It won't be used, so print a warning.
		 * XXX This can cause false positives if the um_syscall is allocated
		 * with malloc (instead of calloc) and not memset'd to all NULLs. */
		if (s->um_socket[sockunify[i].proc_sc])
		{
			GERROR("WARNING: a module has defined syscall %s that will not be used:",
					SOCKCALLNAME(sockunify[i].proc_sc));
			GERROR("         %s will be managed by the module function for %s.",
					SOCKCALLNAME(sockunify[i].proc_sc), SOCKCALLNAME(sockunify[i].mod_sc));
		}
		s->um_socket[sockunify[i].proc_sc] = s->um_socket[sockunify[i].mod_sc];
	}
#endif
	if (s->um_virsc && s->um_virsc[VIRSYS_MSOCKET]) {
		if
#if (__NR_socketcall != __NR_doesnotexist)
			(s->um_socket[SYS_SOCKET])
#else
				(s->um_syscall[uscno(__NR_socket)])
#endif
				{
					GERROR("WARNING: a module has defined syscall socket that will not be used");
					GERROR("         socket will be managed by the module function for msocket.");
				}
#if (__NR_socketcall != __NR_doesnotexist)
		s->um_socket[SYS_SOCKET]=s->um_virsc[VIRSYS_MSOCKET];
#else
		s->um_syscall[uscno(__NR_socket)]=s->um_virsc[VIRSYS_MSOCKET];
#endif
	}
}

/* add a new service module */
int add_service(void *handle)
{
	int i;

	struct service *s=dlsym(handle,"viewos_service");
	if (!s) 
		return s_error(EINVAL);
	/* locking/error management */
	else if (s->code == UM_NONE || s->code == UM_ERR)
		return s_error(EFAULT);
	else if (servmap[s->code] != 0)
		return s_error(EEXIST);
	else {
		GDEBUG(9, "noserv == %d, adding 1", noserv);
		noserv++;
		/* DEPRECATED: code registration */
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
		/* NEW: hash table registration */
		ht_tab_add(CHECKMODULE,s->name,strlen(s->name),NULL,NULL,s);
		/* dl handle is the dynamic library handle, it is set in a second time */
		s->dlhandle=handle;
		

		for (i = 0; i < sizeof(c_set); i++)
			if (MCH_ISSET(i, &(s->ctlhs)))
				if (reg_service[i])
				{
					GDEBUG(3, "calling reg_service[%d](0x%02x)", i, s->code);
					reg_service[i](s->code);
				}


		modify_um_syscall(s);

		service_ctl(MC_MODULE | MC_ADD, UM_NONE, s->code, s->code);
		return 0;
	}
} 

/* delete a service */
int del_service(char *name)
{
	struct ht_elem *hte=ht_check(CHECKMODULE,name,NULL,0);
	if (!hte)
		return s_error(ENOENT);
	struct service *s=ht_get_private_data(hte);
	int code=s->code;
	if (code==UM_NONE || code==UM_ERR)
		return s_error(EINVAL);
	else if (services[servmap[code]-1]->count != 0)
		return s_error(EBUSY);
	/* locking and error management */
	else if (servmap[code] == 0)
		return s_error(ENOENT);
	else {
		int i;
		void *handle=services[servmap[code]-1]->dlhandle;
		/* call deregistrationn upcall (if any) */
		for (i = 0; i < sizeof(c_set); i++)
			if (MCH_ISSET(i, &(services[servmap[code]-1]->ctlhs)))
				if (dereg_service[i])
				{
					GDEBUG(3, "calling dereg_service[%d](0x%02x)", i, code);
					dereg_service[i](code);
				}
		/* compact the table */
		for (i= servmap[code]-1; i<noserv-1; i++)
			services[i]=services[i+1];
		noserv--;
		/* update the indexes in servmap */
		servmap[code] = 0;
		for (i=0;i<noserv;i++)
			servmap[services[i]->code] = i+1;
		ht_tab_del(hte);
		/* notify other modules of service removal */
		service_ctl(MC_MODULE | MC_REM, UM_NONE, -1, code);
		dlclose(handle);
	}
	return 0;
}

/* list services: returns a list of codes */
void list_item(struct ht_elem *hte, void *arg)
{
	FILE *f=arg;
	struct service *s=ht_get_private_data(hte);
	fprintf(f,"%s:",s->name);
}

int list_services(char *buf,int len)
{
	FILE *f=fmemopen(buf,len,"w");
	forall_ht_tab_do(CHECKMODULE,list_item,f);
	fclose(f);
	return(strlen(buf));
}

/* name services:  maps a service code to its description */
int name_service(char *name,char *buf,int len)
{
	struct ht_elem *hte=ht_check(CHECKMODULE,name,NULL,0);
	if (!hte)
		return s_error(ENOENT);
	else {
		struct service *s=ht_get_private_data(hte);
		snprintf(buf,len,"%s",s->description);
		return 0;
	}
}

/*
 * Call the ctl function of a specific service or of every service except
 * at most one.
 *
 * - type is the ctl function to be called (e.g. MC_PROC | MC_ADD is the same as
 *   the old "addproc"
 * - code is the service code. If UM_NONE, every service will be called.
 * - skip is the code of a service to be skipped if code is UM_NONE. If no
 *   services have to be skipped, use -1.
 * - the remaining arguments are containe in the va_list ap and depend on the type.
 */
static void vservice_ctl(unsigned long type, service_t code, int skip, va_list ap)
{
	va_list aq;
	int pos;
	GDEBUG(2, "type %d code %d skip %d...", type, code, skip);

	if (!services)
		return;

	if (code == UM_NONE)
	{
		for (pos = 0; pos < noserv; pos++)
		{
			if (!services[pos])
				continue;

			if (services[pos]->code == skip)
			{
				GDEBUG(2, "skipping services[%d] because its code is 0x%02x", pos, skip);
				continue;
			}

			GDEBUG(2, "services[%d] == %p", pos, services[pos]);
			if (services[pos]->ctl)
			{
				va_copy(aq, ap);
				GDEBUG(2, "calling service 0x%02x!", services[pos]->code);
				services[pos]->ctl(type, aq);
				va_end(aq);
			}
		}
	}
	else
	{
		int pos = servmap[code] - 1;
		if (services[pos]->ctl)
		{
			GDEBUG(2, "calling service 0x%02x!", services[pos]->code);
			services[pos]->ctl(type, ap);
			va_end(ap);
		}
	}
	GDEBUG(2, "done");
}

/* vararg wrapper for vservice_ctl */
void service_ctl(unsigned long type, service_t code, int skip, ...)
{
	va_list ap;
	va_start(ap, skip);
	vservice_ctl(type, code, skip, ap);
	va_end(ap);
}


/* Call the ctl function of a specific service (or every one except the
 * caller). This is similar to service_ctl but to be used by umview modules
 * for inter-module communication.
 *
 * - type is the ctl function to be called. It is contained in k bits, where k
 *   is the number of bits in a long, minus the number of bits of service_t,
 *   minus one. Currently, on 32 bits architecture, it is 32 - 8 - 1 = 23.
 * - sender is the service code of the caller module. It is used to build the
 *   full ctl code and to avoid self-calling. That is, this function never
 *   calls back the module who made the call UNLESS it is explicitly the
 *   recipient (see next).
 * - recipient is the service code of the module whose ctl function is to be
 *   called. It can be MC_ALLSERVICES (i.e. every registerend service except
 *   the caller) or an integer (i.e. the service with that specific code,
 *   possibly including the caller itself)
 * - the remaining arguments depend on the type
 */
void service_userctl(unsigned long type, service_t sender, service_t recipient, ...)
{
	va_list ap;
	va_start(ap, recipient);

	if (recipient == MC_ALLSERVICES)
		vservice_ctl(MC_USERCTL(sender, type), UM_NONE, sender, ap);
	else
		vservice_ctl(MC_USERCTL(sender, type), recipient, -1, ap);

	va_end(ap);
}

void reg_modules(service_t code)
{
	int i;
	for (i = 0; i < noserv; i++)
		if(services[i] && (services[i]->code != code))
			service_ctl(MC_MODULE | MC_ADD, code, -1, services[i]->code);
}

void dereg_modules(service_t code)
{
	int i;
	for (i = 0; i < noserv; i++)
		if(services[i] && (services[i]->code != code))
			service_ctl(MC_MODULE | MC_REM, code, -1, services[i]->code);
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
void service_addregfun(int class, sysfun regfun, sysfun deregfun)
{
	GDEBUG(3, "adding register/deregister function for class %d", class);
	reg_service[class] = regfun;
	dereg_service[class] = deregfun;
}

/* set exit function */
void _service_init()
{
	atexit(_service_fini);
	service_addregfun(MC_MODULE, (sysfun)reg_modules, (sysfun)dereg_modules);
}




