/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   gdebug.c: debugging functions
 *   
 *   Copyright 2005 Ludovico Gardenghi
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
#include <stdarg.h>
#include <sys/types.h>
#include <unistd.h>
#include <dlfcn.h>

//#include "defs.h"
#include "gdebug.h"

#ifdef MULTI_THREAD
#include <pthread.h>
#endif

FILE *gdebug_ofile = NULL;

static void* libc_handle;
static int (*libc_fprintf)(FILE *stream, const char *format, ...);
static int (*libc_vfprintf)(FILE *stream, const char *format, va_list ap);

void gdebug_set_ofile(FILE* new_ofile)
{
	gdebug_ofile = new_ofile;
}

void fgdebug(FILE *ofile, int gdebug_level, int level, const char *file, const int line, const char *func, const char *fmt, ...)
{
	va_list ap;

	if (gdebug_level >= level)
	{
		va_start(ap, fmt);

#ifdef _PTHREAD_H
		libc_fprintf(ofile, "[%d:%lu] %s:%d %s(): ", getpid(), pthread_self(), file, line, func);
#else
		libc_fprintf(ofile, "[%d] %s:%d %s(): ", getpid(), file, line, func);
#endif

		libc_vfprintf(ofile, fmt, ap);
		libc_fprintf(ofile, "\n");

		va_end(ap);
	}
}

void fghexdump(FILE *ofile, int gdebug_level, int level, const char *file, const int line, const char *func, char* text, int len)
{
	int i;
	if (gdebug_level >= level)
	{
#ifdef _PTHREAD_H
		libc_fprintf(ofile, "[%d:%lu] %s:%d %s(): [%d] ", getpid(), pthread_self(), file, line, func, len);
#else
		libc_fprintf(ofile, "[%d] %s:%d %s(): [%d] ", getpid(), file, line, func, len);
#endif

		for (i = 0; i < len; i++)
		{
			if ((i != 0) && ((i % 4) == 0))
				libc_fprintf(ofile, " ");
			libc_fprintf(ofile, "%02x", (unsigned char)text[i]);
		}

		libc_fprintf(ofile, "\n");
	}
}	

static void __attribute__ ((constructor)) init()
{
	libc_handle = dlopen("libc.so.6", RTLD_LAZY);
	if (!libc_handle)
	{
		fprintf(stderr, "dlopen: %s", dlerror());
		fprintf(stderr, "dlopen in gdebug failed, reverting to original fprintf\n");
		libc_fprintf = fprintf;
		libc_vfprintf = vfprintf;
	}
	else
	{
		libc_fprintf = dlsym(libc_handle, "fprintf");
		libc_vfprintf = dlsym(libc_handle, "vfprintf");

		if (!libc_fprintf || !libc_vfprintf)
		{
			fprintf(stderr, "dlsym: %s", dlerror());
			fprintf(stderr, "dlsym in gdebug failed, reverting to original fprintf\n");
			libc_fprintf = fprintf;
			libc_vfprintf = vfprintf;
		}
	}
}

static void __attribute__ ((destructor)) fini()
{
	dlclose(libc_handle);
}

