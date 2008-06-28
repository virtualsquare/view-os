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
static struct timestamp t1;

static epoch_t real_path(int type, void *arg)
{
	if (type == CHECKPATH) {
		/*char *path=arg;*/
		epoch_t e=0;
		e=tst_matchingepoch(&t1);
		/*return (strncmp(path,"/lib",4) != 0);*/
		/*if (strncmp(path,"/tmp",4)!=0)
			return 0;
		else */
			return e;
	}
	else
		return 0;
}

static long addproc(int id, int max)
{
	fprintf(stderr, "new proc %d %d\n", id, max);
	GDEBUG(3, "new process id %d  pid %d   max %d",id,um_mod_getpid(),max);
	return 0;
}

static long delproc(int id)
{
	GDEBUG(3, "terminated process id %d  pid %d",id,um_mod_getpid());
	return 0;
}

static long addmodule(int code)
{
	GDEBUG(3, "new module loaded. code", code);
	return 0;
}

static long delmodule(int code)
{
	GDEBUG(3, "module %d removed", code);
}


static long ctl(int type, va_list ap)
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
			code = va_arg(ap, int);
			return addmodule(code);

		case MC_MODULE | MC_REM:
			code = va_arg(ap, int);
			return delmodule(code);
		
		default:
			return -1;
	}
}

static void
__attribute__ ((constructor))
init (void)
{
	GMESSAGE("real init");
	s.name="Identity (server side)";
	s.code=0xf8;
	s.checkfun=real_path;
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
	SERVICESYSCALL(s, fstat64, fstat64);
#endif
	SERVICESYSCALL(s, readlink, readlink);
	SERVICESYSCALL(s, getdents64, getdents64);
	SERVICESYSCALL(s, access, access);
	SERVICESYSCALL(s, fcntl, fcntl32);
#if !defined(__x86_64__)
	SERVICESYSCALL(s, fcntl64, fcntl64);
	SERVICESYSCALL(s, _llseek, _llseek);
#endif
	add_service(&s);
	t1=tst_timestamp();
}

static void
__attribute__ ((destructor))
fini (void)
{
	free(s.syscall);
	free(s.socket);
	GMESSAGE("real fini");
}
