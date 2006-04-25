/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   capture_nested.c : capture and divert system calls from modules
 *   
 *   Copyright 2006 Renzo Davoli University of Bologna - Italy
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
#include <stdio.h>
#include <dlfcn.h>
#include <string.h>
#include <stdarg.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <alloca.h>
#include "scmap.h"

typedef long int (*sfun)(long int __sysno, ...);

static long int capture_nested_socketcall(long int sysno, ...){
	va_list ap;
	register int i;
	register int narg=sockmap[sysno].nargs;
	long int *args;
	{
		static char buf[128];
		snprintf(buf,128,"SkC=%ld\n",sysno);
		syscall(__NR_write,2,buf,strlen(buf));
	}
	args=alloca(narg*sizeof(long int));
	va_start(ap, sysno);
	for (i=0; i<narg;i++)
		args[i]=va_arg(ap,long int);
	va_end(ap);
	return syscall(__NR_socketcall,sysno,args);
}

static long int capture_nested_syscall(long int sysno, ...)
{
	va_list ap;
	long int a1,a2,a3,a4,a5,a6;
	va_start (ap, sysno);
	/*debug of nested calls*/
	{
		static char buf[128];
		snprintf(buf,128,"SyC=%ld\n",sysno);
		syscall(__NR_write,2,buf,strlen(buf));
	}
	a1=va_arg(ap,long int);
	a2=va_arg(ap,long int);
	a3=va_arg(ap,long int);
	a4=va_arg(ap,long int);
	a5=va_arg(ap,long int);
	a6=va_arg(ap,long int);
	va_end(ap);
	return syscall(sysno,a1,a2,a3,a4,a5,a6);
}

void capture_nested_init()
{
	sfun *_pure_syscall;
	sfun *_pure_socketcall;
	if ((_pure_syscall=dlsym(RTLD_DEFAULT,"_pure_syscall")) != NULL) {
		fprintf(stderr, "pure_libc library found: module nesting allowed\n\n");
		*_pure_syscall=capture_nested_syscall;
	}
	if ((_pure_socketcall=dlsym(NULL,"_pure_socketcall")) != NULL) {
		*_pure_syscall=capture_nested_socketcall;
	}
}

