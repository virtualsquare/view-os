/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   example of um-ViewOS module:
 *   Identity module.
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
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <string.h>
#include "module.h"
#include "libummod.h"
#include "gdebug.h"

// int read(), write(), close();

static struct service s;

static epoch_t real_path(int type, void *arg)
{
	if (type == CHECKPATH) {
		char *path=arg;
		return (strncmp(path,"/lib",4) != 0);
	}
	else
		return 0;
}

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

static void
__attribute__ ((constructor))
init (void)
{
	GMESSAGE("real init");
	s.name="Identity (server side)";
	s.code=0x00;
	s.checkfun=real_path;
	s.addproc=addproc;
	s.delproc=delproc;
	s.syscall=(sysfun *)calloc(scmap_scmapsize,sizeof(sysfun));
	s.socket=(sysfun *)calloc(scmap_sockmapsize,sizeof(sysfun));
	SERVICESYSCALL(s, open, (sysfun)open);
	SERVICESYSCALL(s, read, read);
	SERVICESYSCALL(s, write, write);
	SERVICESYSCALL(s, close, close);
	SERVICESYSCALL(s, stat, stat);
	SERVICESYSCALL(s, lstat, lstat);
	SERVICESYSCALL(s, fstat, fstat);
#if !defined(__x86_64__)
	SERVICESYSCALL(s, stat64, stat64);
	SERVICESYSCALL(s, lstat64, lstat64);
	SERVICESYSCALL(s, fstat64, fstat64);
#endif
	SERVICESYSCALL(s, readlink, readlink);
	SERVICESYSCALL(s, getdents, getdents);
	SERVICESYSCALL(s, getdents64, getdents64);
	SERVICESYSCALL(s, access, access);
	SERVICESYSCALL(s, fcntl, fcntl32);
#if !defined(__x86_64__)
	SERVICESYSCALL(s, fcntl64, fcntl64);
	SERVICESYSCALL(s, _llseek, _llseek);
#endif
	add_service(&s);
}

static void
__attribute__ ((destructor))
fini (void)
{
	free(s.syscall);
	free(s.socket);
	GMESSAGE("real fini");
}
