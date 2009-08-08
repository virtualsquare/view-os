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
#include "modutils.h"
#include "bits/wordsize.h"

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

static inline int s_error(int err)
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

static inline int s_error_dlclose(int err,void *handle) {
	dlclose(handle);
	errno=err;
	return -1;
}

static void *nullinit(char *args) {
	return NULL;
}

/* add a new service */
int add_service(char *file,int permanent)
{
	char *args;
	void *handle;
	for (args=file;*args != 0 && *args != ',';args++)
		;
	if (*args == ',') {
		*args = 0;
		args++;
	}
	handle=openmodule(file,RTLD_LAZY|RTLD_GLOBAL);
	if (handle != NULL) {
		struct service *s=dlsym(handle,"viewos_service");
		if (!s) 
			return s_error_dlclose(EINVAL,handle);
		else if (ht_check(CHECKMODULE,s->name,NULL,0))
			return s_error_dlclose(EEXIST,handle);
		else {
			int i;
			struct timestamp *tst=um_x_gettst();
			struct ht_elem *hte;
			void *(*pinit)() = dlsym(handle,"viewos_init");
			if (s->dlhandle==NULL)
				modify_um_syscall(s);
			/* dl handle is the dynamic library handle*/
			s->dlhandle=handle;
			if (pinit == NULL) 
				pinit=nullinit;
			hte=ht_tab_add(CHECKMODULE,s->name,strlen(s->name),s,NULL,pinit(args));
			if (permanent) {
				ht_count_plus1(hte);
			}
			/* update the process time */
			tst->epoch=get_epoch();
			for (i = 0; i < sizeof(c_set); i++)
				if (MCH_ISSET(i, &(s->ctlhs)))
					if (reg_service[i])
					{
						GDEBUG(3, "calling reg_service[%d](%s)", i, s->name);
						reg_service[i](s->name);
					}
			/* NEW: hash table registration */
			service_ctl(MC_MODULE | MC_ADD, s->name, NULL);
			return 0;
		}
	} else {
		printk("module error: %s\n",dlerror());
		return s_error(EFAULT);
	}
}



/* delete a service */
static void del_service_internal(struct ht_elem *hte,void *arg)
{
	int i;
	struct service *s=ht_get_service(hte);
	/* notify other modules of service removal */
	service_ctl(MC_MODULE | MC_REM, s->name, NULL);
	/* call deregistration upcall (if any) */
	for (i = 0; i < sizeof(c_set); i++)
		if (MCH_ISSET(i, &(s->ctlhs)))
			if (dereg_service[i])
			{
				GDEBUG(3, "calling dereg_service[%d](%s)", i, s->name);
				dereg_service[i](s->name);
			}
	ht_tab_invalidate(hte);
}

int del_service(char *name)
{
	struct ht_elem *hte=ht_check(CHECKMODULE,name,NULL,0);
	if (!hte)
		return s_error(ENOENT);
	struct service *s=ht_get_service(hte);
	if (ht_get_count(hte) != 0)
		return s_error(EBUSY);
	else {
		void *handle=s->dlhandle;
		void (*pfini)() = dlsym(handle,"viewos_fini");
		if (pfini != NULL)
			pfini(ht_get_private_data(hte));
		del_service_internal(hte,NULL);
		ht_tab_del(hte);
		dlclose(handle);
	}
	return 0;
}

/* list services: returns a list of codes */
void list_item(struct ht_elem *hte, void *arg)
{
	FILE *f=arg;
	struct service *s=ht_get_service(hte);
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
		struct service *s=ht_get_service(hte);
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

struct vservice {
	unsigned long type;
	char *sender;
	va_list ap;
};

static void vservice_ctl_item(struct ht_elem *hte, void *arg)
{
	struct service *s=ht_get_service(hte);
	struct vservice *varg=arg;
	if (s->ctl && varg->sender != s->name) {
		va_list aq;
		va_copy(aq, varg->ap);
		GDEBUG(2, "calling service %s!", s->name);
		s->ctl(varg->type, varg->sender, aq);
		va_end(aq);
	}
}

static void vservice_ctl(unsigned long type, char *sender, char *destination,
	 va_list ap)
{
	struct vservice varg={.type=type,.sender=sender};
	va_copy(varg.ap,ap);
	GDEBUG(2, "type %d sender %s destination %s...", type, sender, destination);

	if (destination == NULL) {
		forall_ht_tab_do(CHECKMODULE,vservice_ctl_item,&varg);
	} else {
		struct ht_elem *hte=ht_check(CHECKMODULE,destination,NULL,0);
		if (hte) 
			vservice_ctl_item(hte,&varg);
	}
}

/* vararg wrapper for vservice_ctl */
void service_ctl(unsigned long type, char *sender, char *destination, ...)
{
	va_list ap;
	va_start(ap, destination);
	vservice_ctl(type, sender, destination, ap);
	va_end(ap);
}

/* Call the ctl function of a specific service (or every one except the
 * caller). This is similar to service_ctl but to be used by umview modules
 * for inter-module communication.
 *
 * - type is the ctl function to be called. It is contained in k bits, where k
 *   is the number of bits in a long, minus the number of bits of service_t,
 *   minus one. Currently, on 32 bits architecture, it is 32 - 8 - 1 = 23.
 * - sender is the service struct of the caller module. 
 * - destination is the service name of the module whose ctl function is to be
 *   called. It can be NULL (i.e. every registerend service except
 *   the caller) 
 * - the remaining arguments depend on the type. sender and receipients must
 *   agree on the args.
 */
void service_userctl(unsigned long type, struct service *sender, 
			    char *destination, ...)
{
	if (sender && sender->name) {
		va_list ap;
		va_start(ap, destination);

		vservice_ctl(MC_USERCTL(type), sender->name, destination, ap);

		va_end(ap);
	}
}

static void reg_mod_item(struct ht_elem *ht, void *arg)
{
	struct service *s=ht_get_service(ht);
	service_ctl(MC_MODULE | MC_ADD, s->name, arg, NULL);
}

static void reg_modules(char *destination)
{
	forall_ht_tab_do(CHECKMODULE,reg_mod_item,destination);
}

static void dereg_mod_item(struct ht_elem *ht, void *arg)
{
	struct service *s=ht_get_service(ht);
	service_ctl(MC_MODULE | MC_REM, s->name, arg, NULL);
}

static void dereg_modules(char *destination)
{
	forall_ht_tab_do(CHECKMODULE,dereg_mod_item,destination);
}

/* service initialization: upcalls for new services/deleted services
 * may be supplied */
void service_addregfun(int class, sysfun regfun, sysfun deregfun)
{
	GDEBUG(3, "adding register/deregister function for class %d", class);
	reg_service[class] = regfun;
	dereg_service[class] = deregfun;
}

static void _service_fini()
{
	forall_ht_tab_do(CHECKMODULE,del_service_internal,NULL);
}

/* set exit function */
void _service_init()
{
	atexit(_service_fini);
	service_addregfun(MC_MODULE, (sysfun)reg_modules, (sysfun)dereg_modules);
}
