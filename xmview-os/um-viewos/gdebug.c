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

#include "defs.h"
#include "gdebug.h"

#ifdef MULTI_THREAD
#include <pthread.h>
#endif

#ifdef GDEBUG_ENABLED

void fgdebug(FILE *ofile, int level, const char *file, const int line, const char *func, const char *fmt, ...)
{
	va_list ap;

	if (GDEBUG_LEVEL >= level)
	{
		va_start(ap, fmt);

#ifdef _PTHREAD_H
		fprintf(ofile, "[%d:%lu] %s:%d %s(): ", getpid(), pthread_self(), file, line, func);
#else
		fprintf(ofile, "[%d] %s:%d %s(): ", getpid(), file, line, func);
#endif

		vfprintf(ofile, fmt, ap);
		fprintf(ofile, "\n");

		va_end(ap);
	}
}

void fghexdump(FILE *ofile, int level, const char *file, const int line, const char *func, char* text, int len)
{
	int i;
	if (GDEBUG_LEVEL >= level)
	{
#ifdef _PTHREAD_H
		fprintf(ofile, "[%d:%lu] %s:%d %s(): [%d] ", getpid(), pthread_self(), file, line, func, len);
#else
		fprintf(ofile, "[%d] %s:%d %s(): [%d] ", getpid(), file, line, func, len);
#endif

		for (i = 0; i < len; i++)
		{
			if ((i != 0) && ((i % 4) == 0))
				fprintf(ofile, " ");
			fprintf(ofile, "%02x", (unsigned char)text[i]);
		}

		fprintf(ofile, "\n");
	}
}	

#endif

