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
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include "module.h"
#include "libummod.h"

int read(), write(), close();

static struct service s;

static int alwaysfalse()
{
	return 0;
}

static int realpath(char *path)
{
	return (strncmp(path,"/lib",4) != 0);
}

static void
__attribute__ ((constructor))
init (void)
{
	printf("real init\n");
	s.name="Identity (server side)";
	s.code=0x00;
	s.checkpath=realpath;
	s.checksocket=alwaysfalse;
	s.syscall=(intfun *)malloc(scmap_scmapsize * sizeof(intfun));
	s.socket=(intfun *)malloc(scmap_sockmapsize * sizeof(intfun));
	s.syscall[uscno(__NR_open)]=(intfun)open;
	s.syscall[uscno(__NR_read)]=read;
	s.syscall[uscno(__NR_write)]=write;
	s.syscall[uscno(__NR_readv)]=readv;
	s.syscall[uscno(__NR_writev)]=writev;
	s.syscall[uscno(__NR_close)]=close;
	s.syscall[uscno(__NR_stat)]=stat;
	s.syscall[uscno(__NR_lstat)]=lstat;
	s.syscall[uscno(__NR_fstat)]=fstat;
	s.syscall[uscno(__NR_stat64)]=stat64;
	s.syscall[uscno(__NR_lstat64)]=lstat64;
	s.syscall[uscno(__NR_fstat64)]=fstat64;
	s.syscall[uscno(__NR_readlink)]=readlink;
	s.syscall[uscno(__NR_getdents)]=getdents;
	s.syscall[uscno(__NR_getdents64)]=getdents64;
	s.syscall[uscno(__NR_access)]=access;
	s.syscall[uscno(__NR_fcntl)]=fcntl32;
	s.syscall[uscno(__NR_fcntl64)]=fcntl64;
	s.syscall[uscno(__NR__llseek)]=_llseek;
	add_service(&s);
}

static void
__attribute__ ((destructor))
fini (void)
{
	free(s.syscall);
	free(s.socket);
	printf("real fini\n");
}
