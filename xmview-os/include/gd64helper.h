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

typedef struct _telem telem;
typedef struct _ddreq ddreq;
typedef struct _dirdata dirdata;

enum ddreqtype { ddadd, ddrem };

struct _ddreq {
	enum ddreqtype type;
	char *d_name;
	long d_ino;
	ddreq *next;
};



struct _telem {

	/* Pointer to the element in dents */
	struct dirent64 *cur;

	/* Pointers to prev/next elements of dents, via telem so we can navigate */
	telem *prev;
	telem *next;

	unsigned long index;
	int slot;
};


struct _dirdata {
	unsigned long long pos;

	/* If true, it means that the first getdents64 must take care of
	 * populating this structure with the data from the real getdents.
	 * It is turned off in 2 ways: either when dirdata is populated by
	 * a getdents, or when the user manually wants to add elements to
	 * an empty structure (i.e. for showing no elements but one or two
	 * inside a directory) */
	int empty;


	/* Array of pointers to buffers filled by getdents64 */
	struct dirent64 **dents;
	unsigned long dents_size;
	/* Array which keeps count of how many non-removed items are in each
	 * buffer of dents. */
	unsigned long *dents_usage;

	telem **dents_index;
	unsigned long dents_index_size;
	
	/* tree is a tree of telem which contains a pointer to a dirent
	 * in dents */
	GTree *tree;
	
	/* telem of the first and last elements */
	telem *first, *last;

	/* List of pending requests (additions or removals of files) */
	ddreq *pending;
};

dirdata *dirdata_new(void);
int dirdata_lseek(dirdata *dd, int fd, unsigned long long offset, loff_t *result, unsigned int whence);
int dirdata_getdents64(dirdata *dd, unsigned int fd, struct dirent64 *dirp, unsigned int count);
void dirdata_transform_remove(dirdata *dd, char *d_name);
void dirdata_transform_add(dirdata *dd, long d_ino, char *d_name, int replace);
void dirdata_free(dirdata *dd);

#endif
