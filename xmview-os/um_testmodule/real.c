/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   example of um-ViewOS module:
 *   Identity module.
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
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <string.h>
#include <config.h>
#include "module.h"
#include "libummod.h"
#include "gdebug.h"

// int read(), write(), close();

static struct service s;
VIEWOS_SERVICE(s)

static long addproc(int id, int max)
{
	GDEBUG(3, "new process id %d  pid %d   max %d",id,um_mod_getpid(),max);
	return 0;
}

static long delproc(int id)
{
	GDEBUG(3, "terminated process id %d  pid %d",id,um_mod_getpid());
	return 0;
}

static long addmodule(char *sender)
{
	GDEBUG(3, "new module loaded. %s", sender);
	return 0;
}

static long delmodule(char *sender)
{
	GDEBUG(3, "module %s removed", sender);
	return 0;
}


static long ctl(int type, char *sender, va_list ap)
{
	int id, ppid, max, code;

	switch(type)
	{
		case MC_PROC | MC_ADD:
			id = va_arg(ap, int);
			ppid = va_arg(ap, int);
			max = va_arg(ap, int);
			return addproc(id, max);
			
		case MC_PROC | MC_REM:
			id = va_arg(ap, int);
			return delproc(id);

		case MC_MODULE | MC_ADD:
			return addmodule(sender);

		case MC_MODULE | MC_REM:
			return delmodule(sender);
		
		default:
			return -1;
	}
}

void *viewos_init(char *args)
{
	return ht_tab_pathadd(CHECKPATH,"/","/","real",0,"",&s,0,NULL,NULL);
}

void *viewos_fini(void *data)
{
	struct ht_elem *proc_ht=data;
	ht_tab_del(proc_ht);
}

static void
__attribute__ ((constructor))
init (void)
{
	GMESSAGE("real init");
	s.name="real";
	s.description="Identity (server side)";
	s.ctl = ctl;
	

	MCH_ZERO(&(s.ctlhs));
	MCH_SET(MC_PROC, &(s.ctlhs));
	MCH_SET(MC_MODULE, &(s.ctlhs));

	s.syscall=(sysfun *)calloc(scmap_scmapsize,sizeof(sysfun));
	s.socket=(sysfun *)calloc(scmap_sockmapsize,sizeof(sysfun));
	SERVICESYSCALL(s, open, (sysfun)open);
	SERVICESYSCALL(s, read, read);
	SERVICESYSCALL(s, write, write);
	SERVICESYSCALL(s, close, close);
#if !defined(__x86_64__)
	SERVICESYSCALL(s, stat64, stat64);
	SERVICESYSCALL(s, lstat64, lstat64);
#endif
	SERVICESYSCALL(s, readlink, readlink);
	SERVICESYSCALL(s, getdents64, getdents64);
	SERVICESYSCALL(s, access, access);
	SERVICESYSCALL(s, fcntl, fcntl32);
#if !defined(__x86_64__)
	SERVICESYSCALL(s, fcntl64, fcntl64);
	SERVICESYSCALL(s, _llseek, _llseek);
#endif
}

static void
__attribute__ ((destructor))
fini (void)
{
	free(s.syscall);
	free(s.socket);
	GMESSAGE("real fini");
}
