/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   gdebug.h: debugging functions (headers)
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
#ifndef _GDEBUG_H
#define _GDEBUG_H

#include <stdio.h>
#include <string.h>

#ifdef DEBUG
#	define GDEBUG_ENABLED
#endif

#define GDEBUG_OFILE (gdebug_ofile?gdebug_ofile:stderr)
extern FILE* gdebug_ofile;

void gdebug_set_ofile(char* new_ofile);
void fgmsg(FILE *ofile, const char *fmt, ...);

#ifdef GDEBUG_ENABLED
#	ifndef GDEBUG_LEVEL
#		error "Debug enabled but GDEBUG_LEVEL undefined."
#	endif
#	define FGDEBUG(ofile, level, args...) fgdebug(ofile, GDEBUG_LEVEL, level, __FILE__, __LINE__, __func__, args)
#	define GDEBUG(level, args...) FGDEBUG(GDEBUG_OFILE, level, args)
#	define GPERROR(level, prefix) GDEBUG(level, "%s: %s", prefix, strerror(errno))
#	define FGHEXDUMP(ofile, level, text, len) fghexdump(ofile, GDEBUG_LEVEL, level, __FILE__, __LINE__, __func__, text, len)
#	define GHEXDUMP(level, text, len) FGHEXDUMP(GDEBUG_OFILE, level, text, len)
#	define GBACKTRACE(level, maxdepth) FGBACKTRACE(gdebug_ofile?gdebug_ofile:stderr, level, maxdepth)
#	define FGBACKTRACE(ofile, level, maxdepth) fgbacktrace(ofile, GDEBUG_LEVEL, level, __FILE__, __LINE__, __func__, maxdepth)
#	define FGERROR(ofile, args...) fgdebug(ofile, -1, -1, __FILE__, __LINE__, __func__, args)
#	define GERROR(args...) FGERROR(GDEBUG_OFILE, args)
#	define GMESSAGE(args...) FGERROR(GDEBUG_OFILE, args)

void fgdebug(FILE *ofile, int gdebug_level, int level, const char *file, const int line, const char *func, const char *fmt, ...);
void fghexdump(FILE *ofile, int gdebug_level, int level, const char *file, const int line, const char *func, char *text, int len);
void fgbacktrace(FILE *ofile, int gdebug_level, int level, const char *file, const int line, const char *func, int maxdepth);

#else
#	define FGDEBUG(ofile, level, args...)
#	define GDEBUG(level, args...)
#	define GPERROR(level, prefix)
#	define FGHEXDUMP(ofile, level, text, len)
#	define GHEXDUMP(level, text, len)
#	define GBACKTRACE(level, maxdepth)
#	define FGERROR(ofile, args...) fgmsg(ofile, args)
#	define GERROR(args...) FGERROR(GDEBUG_OFILE, args)
#	define GMESSAGE(args...) FGERROR(GDEBUG_OFILE, args)
#endif

/* COLOR DEBUG */
#define BK 0
#define RD 1
#define GN 2
#define YL 3
#define BL 4
#define MG 5
#define CY 6
#define WH 7
#define BBK (BK<<16)
#define BRD (RD<<16)
#define BGN (GN<<16)
#define BYL (YL<<16)
#define BBL (BL<<16)
#define BMG (MG<<16)
#define BCY (CY<<16)
#define BWH (WH<<16)
#define BGND(level) (((level)>>16) & 07)
#define FBK (BK<<19)
#define FRD (RD<<19)
#define FGN (GN<<19)
#define FYL (YL<<19)
#define FBL (BL<<19)
#define FMG (MG<<19)
#define FCY (CY<<19)
#define FWH (WH<<19)
#define FGND(level) (((level)>>19) & 07)
#define BOLD (1<<22)
#define BLINK (1<<23)
#define UNDER (1<<24)
#define COLOR(level) ((level) & (0777 << 16))
#define LEVEL(level) ((level) & 0xffff)
#endif
