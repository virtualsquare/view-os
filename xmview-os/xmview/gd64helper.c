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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/types.h>
#include <linux/dirent.h>
#include <linux/unistd.h>
#include <glib.h>
#include <assert.h>
#include "gdebug.h"

#define DCAST(x) (struct dirent64 *)((char *) x )

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


struct _dirdata {
	off_t pos;

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

struct _telem {

	/* Pointer to the element in dents */
	struct dirent64 *cur;

	/* Pointers to prev/next elements of dents, via telem so we can navigate */
	telem *prev;
	telem *next;

	unsigned long index;
	int slot;
};





dirdata *dirdata_new()
{
	dirdata *new = malloc(sizeof(dirdata));

	new->dents = NULL;
	new->dents_index = NULL;
	new->dents_index_size = 0;
	new->dents_size = 0;
	new->dents_usage = NULL;

	new->first = NULL;
	new->last = NULL;
	new->tree = g_tree_new((GCompareFunc)*strcmp);
	new->pos = 0;
	new->empty = 1;
	new->pending = NULL;

	return new;
}


static unsigned long dirdata_add_dirents(dirdata *dd, struct dirent64 *dents, unsigned int count, int copy)
{
	int pos = 0;
	struct dirent64 *curdent;
	telem *first, *new, *cur;
	int i, nelem;

	dd->dents_size++;

	dd->dents = realloc(dd->dents, dd->dents_size * sizeof(struct dirent64*));
	dd->dents_usage = realloc(dd->dents_usage, dd->dents_size * sizeof(long));
	if (copy)
	{
		GDEBUG(10, "allocating %u bytes in slot %ld", count, dd->dents_size - 1);
		dd->dents[dd->dents_size - 1] = malloc(count);
		memcpy(dd->dents[dd->dents_size-1], dents, count);
	}
	else
		dd->dents[dd->dents_size - 1] = dents;
	
	nelem = 0;
	first = NULL;


	while (pos < count)
	{
		curdent = (struct dirent64*)((char*)(dd->dents[dd->dents_size-1]) + pos);

		new = malloc(sizeof(telem));
		GDEBUG(10, " ++ adding %s, pos: %d, count: %d, telem@%p, dent@%p", curdent->d_name, pos, count, new, curdent);

		new->cur = curdent;
		new->next = NULL;
		new->prev = dd->last;
		new->slot = dd->dents_size - 1;

		if (dd->last)
			dd->last->next = new;

		dd->last = new;

		if (!dd->first)
			dd->first = new;

		if (!first)
		{
			first = new;
			nelem = 0;
		}

		nelem++;
		GDEBUG(10, "nelem == %d", nelem);
		
		g_tree_insert(dd->tree, curdent->d_name, new);
		pos = pos + curdent->d_reclen;
	}

	dd->dents_index_size += nelem;
	GDEBUG(10, "dis == %lu", dd->dents_index_size);
	dd->dents_usage[dd->dents_size - 1] = nelem;
	dd->dents_index = realloc(dd->dents_index, dd->dents_index_size * sizeof(telem*));

	cur = first;

	for (i = dd->dents_index_size - nelem; i < dd->dents_index_size; i++)
	{
		assert(cur);
		dd->dents_index[i] = cur;
		cur->index = i;
		cur->cur->d_off = i+1;
		GDEBUG(10, "i == %d, cur == %p, d_off = %lld", i, cur, cur->cur->d_off);
		cur = cur->next;
	}

	return i-1;
}

static unsigned long dirdata_add_dirent(dirdata *dd, struct dirent64 *dent, int copy)
{
	return dirdata_add_dirents(dd, dent, dent->d_reclen, copy);
}

static unsigned long dirdata_remove_dirent(dirdata *dd, char *name)
{
	telem *result;
	int slot;
	enum position_e { only = 0, first = 1, last = 2, inside = 3 } position;

	result = g_tree_lookup(dd->tree, name);

	if (!result)
	{
		GDEBUG(10, "g_tree_lookup(%p, \"%s\") is null, ignoring request...", dd->tree, name);
		return 0;
	}

	position = (result->prev ? 1 : 0) | (result->next ? 2 : 0);
	slot = result->slot;

	GDEBUG(10, "removing %s from tree...", name);

	g_tree_remove(dd->tree, name);

	GDEBUG(10, "removed. position is %d, slot is %d (old usage: %ld)", position, slot, dd->dents_usage[slot]);


	dd->dents_index[result->index] = NULL;

	switch(position)
	{
		case only:
			dd->first = NULL;
			dd->last = NULL;
			break;

		case first:
			result->next->prev = NULL;
			dd->first = result->next;
			break;

		case last:
			result->prev->next = NULL;
			result->prev->cur->d_off++;
			dd->last = result->prev;
			break;

		case inside:
			result->prev->next = result->next;
			result->prev->cur->d_off++;
			result->next->prev = result->prev;
			break;
	}

	dd->dents_usage[slot]--;


	if (dd->dents_usage[slot] == 0)
	{
		GDEBUG(10, "slot %d is empty, freeing", slot);
		free(dd->dents[slot]);
		dd->dents[slot] = NULL;
		if (slot == (dd->dents_size - 1))
			dd->dents_size--;
	}

	return 1;
}

int dirdata_seek(dirdata *dd, int where)
{
	int min = dd->first->index;
	int max = dd->last->index;
	if (where < min)
		dd->pos = min;
	else if (where > max)
		dd->pos = max;
	else
		dd->pos = where;

	while (!dd->dents_index[dd->pos] && (dd->pos <= max))
		dd->pos++;

	return dd->pos;
}

#define RLROUND 8

static struct dirent64 *build_dirent(long d_ino, char *d_name)
{
	struct dirent64 *new;
	unsigned int newsize;

	newsize = sizeof(struct dirent64) - NAME_MAX + strlen(d_name);
	if (newsize % RLROUND)
		newsize += RLROUND - (newsize % RLROUND);
	
	GDEBUG(10, "sizes: %d %d %d %d", sizeof(struct dirent64) ,NAME_MAX , strlen(d_name), newsize);

	new = malloc(newsize);
	new->d_ino = d_ino;
	strcpy(new->d_name, d_name);
	new->d_reclen = newsize;
	new->d_off = 1;

	return new;

}

/* Only applies if !empty */
static int apply_pending(dirdata *dd)
{
	ddreq *cur;
	int i = 0;
	int last = 2;

	if (dd->empty)
	{
		GDEBUG(10, "dd is empty, not applying pending requests");
		return -1;
	}

	if (!dd->pending)
		return 0;

	do
	{
		cur = dd->pending->next;
		GDEBUG(10, "####### applying type %d on %s", cur->type, cur->d_name);
		switch(cur->type)
		{
			case ddadd:
				dirdata_add_dirent(dd, build_dirent(cur->d_ino, cur->d_name), 0);
				break;

			case ddrem:
				dirdata_remove_dirent(dd, cur->d_name);
				break;
		}
		i++;
		dd->pending->next = cur->next;
		GDEBUG(10, ">>>>>>>>> done (freeing) with %s, dd->pending becomes %s and next %s", cur->d_name, dd->pending->d_name, dd->pending->next->d_name);
		if (dd->pending->next != dd->pending)
			last++;
		else
			GDEBUG(10, "not increasing last!");

		free(cur);
	}
	while(--last);

	dd->pending = NULL;

	return i;


}
static int getdents64(unsigned int fd, struct dirent64 *dirp, unsigned int count)
{
	return syscall(__NR_getdents64, fd, dirp, count);
}


int dirdata_getdents64(dirdata *dd, unsigned int fd, struct dirent64 *dirp, unsigned int count)
{
	int curcount, nextcount;
	//struct dirent64 *startdent, *curdent, *nextdent;
	telem *cur;

	if (dd->empty)
	{
		// Fill the dirdata structure
		GDEBUG(10, "filling dirdata structure");

		int rv;
		do
		{
			GDEBUG(10, "calling getdents... ");
			rv = getdents64(fd, dirp, count);
			GDEBUG(10, "returns %d", rv);
			if (rv > 0)
				dirdata_add_dirents(dd, dirp, rv, 1);
		}
		while (rv > 0);

		if (rv < 0)
			return rv;

		dd->empty = 0;
	}
	else
		GDEBUG(10, "not filling, already full, pos is %ld", dd->pos);

	apply_pending(dd);

	GDEBUG(10, "all pending requests applied");

	if (!dd->first)
		return 0;

	cur = dd->dents_index[dd->pos];

	if (!cur)
	{
		GDEBUG(10, "end of directory, returning 0");
		return 0;
	}

	curcount = 0;
	GDEBUG(10, "calculating nextcount, cur == %p...", cur);
	nextcount = cur->cur->d_reclen;
	GDEBUG(10, "                         is %d", nextcount);
	
	while (cur && (nextcount <= count))
	{
		GDEBUG(10, " + copying %s (ino %llu) at %p+%08x, len %d/%d", cur->cur->d_name, cur->cur->d_ino, dirp, curcount, cur->cur->d_reclen, count);
		memcpy(((char *)dirp) + curcount, cur->cur, cur->cur->d_reclen);
		curcount = nextcount;
		dd->pos = cur->cur->d_off;
		if (cur->next)
		{
			GDEBUG(10, "2 calculating nextcount, cur == %p, cur->cur == %p...", cur, cur->cur);
			nextcount += cur->next->cur->d_reclen;
			GDEBUG(10, "                           is %d", nextcount);
			GDEBUG(10, "  pos set to %ld", dd->pos);
		}
		cur = cur->next;
		GDEBUG(10, "   curcount at end is %d, cur is %p", curcount, cur);
	}

	

	return curcount;

}

void dirdata_transform_remove(dirdata *dd, char *d_name)
{
	ddreq *new;
	assert(dd);

	new = malloc(sizeof(ddreq));

	new->type = ddrem;
	new->d_name = d_name;
	
	if (!dd->pending)
	{
		new->next = new;
		dd->pending = new;
	}
	else
	{
		new->next = dd->pending->next;
		dd->pending->next = new;
		dd->pending = new;
	}

	apply_pending(dd);
}



/*
 * If replace is non-zero, an existing file with the same name will be
 * replaced. If replace is zero, and a file with the same file exists, this
 * call will result in a no-op. 
 */
void dirdata_transform_add(dirdata *dd, long d_ino, char *d_name, int replace)
{
	ddreq *new;
	assert(dd);

	if (replace)
		dirdata_transform_remove(dd, d_name);

	new = malloc(sizeof(ddreq));

	new->type = ddadd;
	new->d_ino = d_ino;
	new->d_name = d_name;

	if (!dd->pending)
	{
		new->next = new;
		dd->pending = new;
	}
	else
	{
		new->next = dd->pending->next;
		dd->pending->next = new;
		dd->pending = new;
	}
		

	apply_pending(dd);
}


void dirdata_free(dirdata *dd)
{
	ddreq *req;
	int i;
	g_tree_destroy(dd->tree);

	if (dd->pending)
	{
		req = dd->pending->next;
		dd->pending->next = NULL;
		dd->pending = req;
		while (dd->pending)
		{
			req = dd->pending;
			dd->pending = req->next;
			free(req);
		}
	}

	for (i = 0; i < dd->dents_size; i++)
		if (dd->dents[i])
			free(dd->dents[i]);

	free(dd->dents_index);
	free(dd->dents_usage);
	free(dd->dents);
	free(dd);
}
