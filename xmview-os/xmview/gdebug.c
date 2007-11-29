/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   gdebug.c: debugging functions
 *   
 *   Copyright 2005 Ludovico Gardenghi
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
#include <stdio.h>
#include <stdlib.h>
#include <execinfo.h>
#include <stdarg.h>
#include <sys/types.h>
#include <unistd.h>
#include <dlfcn.h>
#include <errno.h>
#include <config.h>

//#include "defs.h"
#include "gdebug.h"

#ifdef MULTI_THREAD
#include <pthread.h>
#endif

FILE *gdebug_ofile = NULL;

#define BACKTRACE_INITIAL_SIZE 10

static void *libc_handle;
static int (*libc_fprintf)(FILE *stream, const char *format, ...);
static int (*libc_vfprintf)(FILE *stream, const char *format, va_list ap);
static FILE *(*libc_fopen)(const char *path, const char *mode);
static int (*libc_getpid)(void);

static void **backtrace_array = NULL;
static int backtrace_array_size = 0;

void gdebug_set_ofile(char* new_ofile)
{
	gdebug_ofile = libc_fopen(new_ofile, "w");
	if (!gdebug_ofile)
		libc_fprintf(stderr, "gdebug: can't open log file %s: %s. Using stderr.\n",
				new_ofile, strerror(errno));
	else
		setlinebuf(gdebug_ofile);
}

void fgdebug(FILE *ofile, int gdebug_level, int level, const char *file, const int line, const char *func, const char *fmt, ...)
{
	va_list ap;

	if (gdebug_level >= level)
	{
		va_start(ap, fmt);

#ifdef _PTHREAD_H
		libc_fprintf(ofile, "[%d:%lu] %s:%d %s(): ", libc_getpid(), pthread_self(), file, line, func);
#else
		libc_fprintf(ofile, "[%d] %s:%d %s(): ", libc_getpid(), file, line, func);
#endif

		libc_vfprintf(ofile, fmt, ap);
		libc_fprintf(ofile, "\n");

		va_end(ap);
	}
}

void fgmsg(FILE *ofile, const char *fmt, ...)
{
	va_list ap;
		va_start(ap, fmt);
		libc_vfprintf(ofile, fmt, ap);
		libc_fprintf(ofile, "\n");
		va_end(ap);
}

void fghexdump(FILE *ofile, int gdebug_level, int level, const char *file, const int line, const char *func, char* text, int len)
{
	int i;
	if (gdebug_level >= level)
	{
#ifdef _PTHREAD_H
		libc_fprintf(ofile, "[%d:%lu] %s:%d %s(): [%d] ", libc_getpid(), pthread_self(), file, line, func, len);
#else
		libc_fprintf(ofile, "[%d] %s:%d %s(): [%d] ", libc_getpid(), file, line, func, len);
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

void fgbacktrace(FILE *ofile, int gdebug_level, int level, const char *file, const int line, const char *func, int maxdepth)
{
	int i;
	int btdepth;
	char **btstrings;

	/* The first entry is always ignored (it's the call to fgbacktrace), the
	 * user wants maxdepth entries so we must add 1 */
	maxdepth++;
	
	if (gdebug_level >= level)
	{
		if (maxdepth > backtrace_array_size)
		{
			backtrace_array_size = maxdepth;
			backtrace_array = realloc(backtrace_array, sizeof(void*) * backtrace_array_size);
		}
		btdepth = backtrace(backtrace_array, maxdepth);
		btstrings = backtrace_symbols(backtrace_array, btdepth);

		if (!btstrings)
		{
			fgdebug(ofile, gdebug_level, level, file, line, func, "can't obtain backtrace");
			return;
		}

		/* 1 and not 0 (0 is fgbacktrace and it's not interesting) */
		for (i = 1; i < btdepth; i++)
			fgdebug(ofile, gdebug_level, level, file, line, func, "BT: #%d  %s", i-1, btstrings[i]);
	}
}

static void __attribute__ ((constructor)) init()
{

	libc_handle = dlopen("libc.so.6", RTLD_LAZY);
	if (!libc_handle)
	{
		fprintf(stderr, "dlopen: %s", dlerror());
		fprintf(stderr, "dlopen in gdebug failed, reverting to original fprintf/vfprintf/fopen\n");
		libc_fprintf = fprintf;
		libc_vfprintf = vfprintf;
		libc_fopen = fopen;
		libc_getpid = getpid;
	}
	else
	{
		libc_fprintf = dlsym(libc_handle, "fprintf");
		libc_vfprintf = dlsym(libc_handle, "vfprintf");
		libc_fopen = dlsym(libc_handle, "fopen");
		libc_getpid = dlsym(libc_handle,"getpid");

		if (!libc_fprintf || !libc_vfprintf || !libc_fopen || !libc_getpid)
		{
			fprintf(stderr, "dlsym: %s", dlerror());
			fprintf(stderr, "dlsym in gdebug failed, reverting to original fprintf/vfprintf/fopen\n");
			libc_fprintf = fprintf;
			libc_vfprintf = vfprintf;
			libc_fopen = fopen;
			libc_getpid = getpid;
		}
	}
	backtrace_array = malloc(sizeof(void*) * BACKTRACE_INITIAL_SIZE);
	backtrace_array_size = BACKTRACE_INITIAL_SIZE;
}

static void __attribute__ ((destructor)) fini()
{
	dlclose(libc_handle);
	if (backtrace_array)
		free(backtrace_array);
	backtrace_array = NULL;
	backtrace_array_size = 0;
}

