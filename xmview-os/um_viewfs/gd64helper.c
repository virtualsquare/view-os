#include <stdio.h>
#include <stdlib.h>
#include <glib.h>
#include <string.h>
#include <unistd.h>
#include <linux/types.h>
#include <linux/dirent.h>
#include <linux/unistd.h>
#include "gdebug.h"

#define DCAST(x) (struct dirent64 *)((char *) x )

struct _dirdata {
	long pos;
	long size;
	
	/* dents is a flat "array" with variable sized elements */
	struct dirent64 *dents;

	/* Pointer to the last element of dents */
	struct dirent64 *last;

	/* The initial starting address must be saved if we want to correctly
	 * free() it at the end */
	struct dirent64 *origdents;

	/* tree is a tree of telem which contains a pointer to a dirent
	 * in dents */
	GTree *tree;
};

struct _telem {
	struct dirent64 *cur;
	struct dirent64 *prev;
	struct dirent64 *next;
};

typedef struct _dirdata dirdata;
typedef struct _telem telem;


dirdata *dirdata_new()
{
	dirdata *new = malloc(sizeof(dirdata));

	new->dents = NULL;
	new->origdents = NULL;
	new->last = NULL;
	new->size = 0;
	new->tree = g_tree_new((GCompareFunc)*strcmp);
	new->pos = 0;

	return new;
}

void dirdata_add_dirent(dirdata *dd, struct dirent64 *dent)
{
	telem *tnew;
	struct dirent64 *dnew;

	dd->size += dent->d_reclen;
	
	/* dents might be moved forward when the first element is removed, but
	 * d_off is always relative to the initial dents position, so we save it
	 */
	dd->origdents = realloc(dd->origdents, dd->size);
	if (!dd->dents)
		dd->dents = dd->origdents;

	if (dd->size == dent->d_reclen) // First element
		dnew = dd->dents;
	else
		dnew = DCAST(dd->origdents + dd->last->d_off);

	memcpy(dnew, dent, dd->size);

	tnew = malloc(sizeof(tnew));
	tnew->cur = dnew;
	tnew->next = NULL;

	if (dd->size == dent->d_reclen) // First element
	{
		tnew->prev = NULL;
		dnew->d_off = dnew->d_reclen;
	}
	else
	{
		tnew->prev = dd->last;
		dnew->d_off = dd->last->d_off + dnew->d_reclen;
	}

	dd->last = dnew;

	g_tree_insert(dd->tree, dnew->d_name, dnew);
}

void dirdata_add_dirents(dirdata *dd, struct dirent64 *dents, unsigned int count)
{
	int pos = 0;
	struct dirent64 *curdent;

	while (pos < count)
	{
		curdent = DCAST(dents + pos);
		dirdata_add_dirent(dd, curdent);
		pos = pos + curdent->d_reclen;
	}
}

int dirdata_remove_dirent(dirdata *dd, char *name)
{
	telem *result;

	result = g_tree_lookup(dd->tree, name);

	if (!result)
		return 0;

	if (result->prev && result->next) // Inside element
	{
	}
	else if (result->prev && !result->next) // Last element
	{
		dd->last = result->prev;
		dd->last->next = NULL;
		dd->last->d_off = (char*)dd->last - (char*)dd->origdents + dd->last->d_reclen);
		dd->size = dd->last->d_off;
	}
	else if (!result->prev && result->next) // First element
	{
		dd->dents = DCAST(dd->origdents + result->d_off);
		dd->dents->prev = NULL;
	}
	else // only one element
	{
	}



	g_tree_remove(dd->tree, name);





}

void dirdata_free(dirdata *dd)
{
	g_tree_destroy(dd->tree);
	free(dd->dents);
}

