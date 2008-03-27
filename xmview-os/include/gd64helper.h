/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   Helper for getdents64
 *
 *   Copyright 2007 Ludovico Gardenghi
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

#ifndef _GD64HELPER_H
#define _GD64HELPER_H

#include <glib.h>
#include <linux/types.h>
#include <linux/dirent.h>


typedef struct _dirdata dirdata;
enum ddmode { DDFULL, DDFAST };

dirdata *dirdata_new(enum ddmode mode);
int dirdata_lseek(dirdata *dd, int fd, unsigned long long offset, loff_t *result, unsigned int whence);
int dirdata_getdents64(dirdata *dd, unsigned int fd, struct dirent64 *dirp, unsigned int count);
void dirdata_transform_remove(dirdata *dd, char *d_name);
void dirdata_transform_add(dirdata *dd, long d_ino, char *d_name, int replace);
void dirdata_free(dirdata *dd);

#endif
