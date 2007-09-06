#include <stdio.h>
#include <stdlib.h>
#include <glib.h>
#include <string.h>
#include <unistd.h>
#include <linux/types.h>
#include <linux/dirent.h>
#include <linux/unistd.h>
#include "gdebug.h"

struct _dirdata {
	long pos;
	long size;
	
	/* dents is a flat "array" with variable sized elements */
	struct dirent64 *dents;
	struct dirent64 *last;

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
	dd->dents = realloc(dd->dents, dd->size);

	if (dd->size == dent->d_reclen) // First element
		dnew = dd->dents;
	else
		dnew = dd->dents + dd->last->d_off;

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

	dd->last = dd->dents + dnew->d_off;

	g_tree_insert(dd->tree, dd->last->d_name, dd->last);
}

void dirdata_add_dirents(dirdata *dd, struct dirent64 *dents, unsigned int count)
{
	int pos = 0;
	struct dirent64 *curdent;

	while (pos < count)
	{
		curdent = (struct dirent64 *)((char *)dents + pos);
		dirdata_add_dirent(dd, curdent);
		pos = dents
	}
}

int dirdata_remove_dirent(dirdata *dd, char *name)
{
	telem *result;

	result = g_tree_lookup(dd->tree, name);

	if (!result)
		return 0;

	if (result->prev == NULL) // First element
	{

	}

	if (result->next == NULL) // Last element
	{

	}

	g_tree_remove(dd->tree, name);





}

void dirdata_free(dirdata *dd)
{
	g_tree_destroy(dd->tree);
	free(dd->dents);
}

