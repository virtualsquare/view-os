#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/types.h>
#include <linux/dirent.h>
#include <linux/unistd.h>
#include <glib.h>
#include "gdebug.h"

#define DCAST(x) (struct dirent64 *)((char *) x )

typedef struct _telem telem;

struct _dirdata {
	long pos;
	long size;
	
	/* dents is a flat "array" with variable sized elements */
	struct dirent64 *dents;

	/* The initial starting address must be saved if we want to correctly
	 * free() it at the end */
	struct dirent64 *origdents;

	/* tree is a tree of telem which contains a pointer to a dirent
	 * in dents */
	GTree *tree;
	
	/* Pointer to the last element of dents, via the tree (so we can navigate) */
	telem *last;
};

struct _telem {

	/* Pointer to the element in dents */
	struct dirent64 *cur;

	/* Pointers to prev/next elements of dents, via telem so we can navigate */
	telem *prev;
	telem *next;
};

typedef struct _dirdata dirdata;


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

int dirdata_add_dirent(dirdata *dd, struct dirent64 *dent)
{
	telem *tnew;
	struct dirent64 *dnew;

	printf("adding %s\n", dent->d_name);

	dd->size += dent->d_reclen;
	
	/* dents might be moved forward when the first element is removed, but
	 * d_off is always relative to the initial dents position, so we save it
	 */
	dd->origdents = realloc(dd->origdents, dd->size);

	printf("realloc ok\n");

	if (!dd->dents)
		dd->dents = dd->origdents;

	if (dd->size == dent->d_reclen) // First element
		dnew = dd->dents;
	else
		dnew = DCAST(dd->origdents + dd->last->cur->d_off);

	printf("offset is %d\n", (char*)dnew-(char*)dd->origdents);

	memcpy(dnew, dent, dent->d_reclen);

	printf("before malloc(%d)\n", sizeof(telem));
	tnew = malloc(sizeof(telem));
	printf("after malloc\n");
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
		dnew->d_off = dd->last->cur->d_off + dnew->d_reclen;
	}

	dd->last = tnew;

	g_tree_insert(dd->tree, dnew->d_name, dnew);

	return dd->last->cur->d_off;
}

int dirdata_add_dirents(dirdata *dd, struct dirent64 *dents, unsigned int count)
{
	int pos = 0;
	struct dirent64 *curdent;
	int last_d_off;

	while (pos < count)
	{
		curdent = DCAST(dents + pos);
		last_d_off = dirdata_add_dirent(dd, curdent);
		pos = pos + curdent->d_reclen;
	}

	return last_d_off;
}

int dirdata_remove_dirent(dirdata *dd, char *name)
{
	telem *result;

	result = g_tree_lookup(dd->tree, name);

	if (!result)
		return 0;

	if (result->prev && result->next) // Inside element
	{
		result->prev->next = result->next;
		result->next->prev = result->prev;
		result->prev->cur->d_off = (char*)result->next->cur - (char*)dd->origdents;
	}
	else if (result->prev && !result->next) // Last element
	{
		dd->last = result->prev;
		dd->last->next = NULL;
		dd->last->cur->d_off = ((char*)dd->last - (char*)dd->origdents) + dd->last->cur->d_reclen;
		dd->size = dd->last->cur->d_off;
	}
	else if (!result->prev && result->next) // First element
	{
		dd->dents = DCAST(dd->origdents + result->cur->d_off);
		result->next->prev = NULL;
	}
	else // only one element
	{
		dd->dents = dd->origdents;
		dd->size = 0;
		dd->last = NULL;
	}
	g_tree_remove(dd->tree, name);

	return 1;

}

int dirdata_seek(dirdata *dd, int where)
{
	int min = (char*)dd->dents - (char*)dd->origdents;
	if (where < min)
		dd->pos = min;
	dd->pos = where;

	return dd->pos;
}


void dirdata_free(dirdata *dd)
{
	g_tree_destroy(dd->tree);
	free(dd->dents);
}

       #include <sys/types.h>
       #include <sys/stat.h>
       #include <fcntl.h>


int main()
{
	struct dirent64 *dirp;
	int pos = 0;
	int count;
	int fd=open(".", O_RDONLY);
	int len;

	
	dirdata *dd = dirdata_new();

	setlinebuf(stdout);
	
	if (!fd)
		exit(1);

	dirp=malloc(1024);

	count = syscall(__NR_getdents64, fd, dirp, 1024);

	dirdata_add_dirents(dd, dirp, count);


	while (pos<count)
	{
		printf("%s\n", dirp->d_name);
		dirdata_add_dirent(dd,dirp);
		len = dirp->d_reclen;
		dirp = (struct dirent64*)((char*)dirp + len);
		pos += len;
	}
}



