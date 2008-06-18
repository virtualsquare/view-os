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
#include <stdlib.h>
#include <config.h>
#include "gdebug.h"

/* This will be prefixed with getent("$HOME") */
#define USER_MODULES_DIR "/.umview/modules"

#ifndef MAX
#	define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif
/*
 * Try to dlopen a module (o submodule) trying different names and locations:
 * 
 * 1) dlopen(modname)
 * 2) dlopen(modname.so)
 * 3) dlopen(user_umview_plugin_directory/modname)
 * 4) dlopen(user_umview_plugin_directory/modname.so)
 * 5) dlopen(global_umview_plugin_directory/modname)
 * 6) dlopen(global_umview_plugin_directory/modname.so)
 *
 */

#define TRY_DLOPEN(fmt...) \
{ \
	snprintf(testpath, tplen, fmt); \
	fprintf(stderr, "trying %s\n", testpath); \
	if ((handle = dlopen(testpath, flag))) \
	{ \
		free(testpath); \
		return handle; \
	} \
}

void *openmodule(const char *modname, int flag)
{
	void *handle;
	char *testpath;
	int tplen;
	char *homedir = getenv("HOME");

	if (!modname)
		return NULL;

	if ((handle = dlopen(modname, flag)))
		return handle;

	/* If there is no home directory, use CWD */
	if (!homedir)
		homedir = ".";

	tplen = strlen(modname) +
		strlen(MODULES_EXT) + 2 + // + 1 is for a '/' and + 1 for \0
		MAX(strlen(MODULES_DIR),
		    strlen(homedir) + strlen(USER_MODULES_DIR));

	testpath = malloc(tplen);

	TRY_DLOPEN("%s%s", modname, MODULES_EXT);
	TRY_DLOPEN("%s%s/%s", homedir, USER_MODULES_DIR, modname);
	TRY_DLOPEN("%s%s/%s%s", homedir, USER_MODULES_DIR, modname, MODULES_EXT);
	TRY_DLOPEN("%s%s", MODULES_DIR, modname);
	TRY_DLOPEN("%s/%s%s", MODULES_DIR, modname, MODULES_EXT);
	
	return NULL;
}


