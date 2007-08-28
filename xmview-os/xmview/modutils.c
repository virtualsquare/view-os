/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   modutils.c: misc utilites for modules
 *   
 *   Copyright 2007 Ludovico Gardenghi University of Bologna - Italy
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

#include <dlfcn.h>
#include <alloca.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <config.h>
#include "gdebug.h"

/*
 * Try to dlopen a module (o submodule) trying different names and locations:
 * 
 * 1) dlopen(modname)
 * 2) dlopen(modname.so)
 * 3) dlopen(umview_plugin_directory/modname)
 * 4) dlopen(umview_plugin_directory/modname.so)
 *
 */

void *openmodule(const char *modname, int flag)
{
	void *handle;
	char *testpath;
	int tplen;

	if (!modname)
		return NULL;

	if ((handle = dlopen(modname, flag)))
		return handle;

	tplen = strlen(modname) +
		strlen(MODULES_EXT) +
		strlen(MODULES_DIR) + 2; // + 1 is for a '/' and + 1 for \0

	testpath = alloca(tplen);

	snprintf(testpath, tplen, "%s%s", modname, MODULES_EXT);
	if ((handle = dlopen(testpath, flag)))
		return handle;

	snprintf(testpath, tplen, "%s/%s", MODULES_DIR, modname);
	if ((handle = dlopen(testpath, flag)))
		return handle;
	
	snprintf(testpath, tplen, "%s/%s%s", MODULES_DIR, modname, MODULES_EXT);
	if ((handle = dlopen(testpath, flag)))
		return handle;
	
	return NULL;
}


