/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   gdebug.h: debugging functions (headers)
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
#ifndef _GDEBUG_H
#define _GDEBUG_H

#include <stdio.h>
#include <string.h>

#ifdef DEBUG
#	define GDEBUG_ENABLED
#endif

#ifdef GDEBUG_ENABLED
#	ifndef GDEBUG_LEVEL
#		error "Debug enabled but GDEBUG_LEVEL undefined."
#	endif
#	define GDEBUG_OFILE (gdebug_ofile?gdebug_ofile:stderr)
#	define FGDEBUG(ofile, level, args...) fgdebug(ofile, GDEBUG_LEVEL, level, __FILE__, __LINE__, __func__, args)
#	define GDEBUG(level, args...) FGDEBUG(GDEBUG_OFILE, level, args)
#	define GPERROR(level, prefix) GDEBUG(level, "%s: %s", prefix, strerror(errno))
#	define FGHEXDUMP(ofile, level, text, len) fghexdump(ofile, GDEBUG_LEVEL, level, __FILE__, __LINE__, __func__, text, len)
#	define GHEXDUMP(level, text, len) FGHEXDUMP(GDEBUG_OFILE, level, text, len)

extern FILE* gdebug_ofile;

void gdebug_set_ofile(FILE* new_ofile);
void fgdebug(FILE *ofile, int gdebug_level, int level, const char *file, const int line, const char *func, const char *fmt, ...);
void fghexdump(FILE *ofile, int gdebug_level, int level, const char *file, const int line, const char *func, char *text, int len);

#else
#	define FGDEBUG(ofile, level, args...)
#	define GDEBUG(level, args...)
#	define GPERROR(level, prefix)
#	define FGHEXDUMP(ofile, level, text, len)
#	define GHEXDUMP(level, text, len)
#endif

#endif
