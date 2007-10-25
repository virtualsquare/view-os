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
	long pos;
	long size;

	/* If true, it means that the first getdents64 must take care of
	 * populating this structure with the data from the real getdents.
	 * It is turned off in 2 ways: either when dirdata is populated by
	 * a getdents, or when the user manually wants to add elements to
	 * an empty structure (i.e. for showing no elements but one or two
	 * inside a directory) */
	int empty;
	
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

	/* List of pending requests (additions or removals of files) */
	ddreq *pending;
};

struct _telem {

	/* Pointer to the element in dents */
	struct dirent64 *cur;

	/* Pointers to prev/next elements of dents, via telem so we can navigate */
	telem *prev;
	telem *next;
};





dirdata *dirdata_new()
{
	dirdata *new = malloc(sizeof(dirdata));

	new->dents = NULL;
	new->origdents = NULL;
	new->last = NULL;
	new->size = 0;
	new->tree = g_tree_new((GCompareFunc)*strcmp);
	new->pos = 0;
	new->empty = 1;
	new->pending = NULL;

	return new;
}

static int dirdata_add_dirent(dirdata *dd, struct dirent64 *dent)
{
	telem *tnew;
	struct dirent64 *dnew;

	printf("adding %s, len=%d\n", dent->d_name, dent->d_reclen);

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

	printf("memcpying %d bytes\n", dent->d_reclen);
	memcpy(dnew, dent, dent->d_reclen);
	

	tnew = malloc(sizeof(telem));
	tnew->cur = dnew;
	tnew->next = NULL;

	if (dd->size == dent->d_reclen) // First element
	{
		printf("first element, prev will be null and off will be %d\n", dnew->d_reclen);
		tnew->prev = NULL;
		dnew->d_off = dnew->d_reclen;
	}
	else
	{
		tnew->prev = dd->last;
		tnew->prev->next = tnew;
		dnew->d_off = dd->last->cur->d_off + dnew->d_reclen;
		printf("not first element, prev=%p, prev->next=%p, d_off=%d, d_reclen=%d\n",
				tnew->prev, tnew->prev->next, dnew->d_off, dnew->d_reclen);
	}

	dd->last = tnew;

	g_tree_insert(dd->tree, dnew->d_name, tnew);
	
	printf("name in dnew@%p: %s\n", tnew->cur,tnew->cur->d_name);
	printf(" off=%d reclen=%d\n", tnew->cur->d_off, tnew->cur->d_reclen);
	printf(" prev=%p next=%p\n", tnew->prev, tnew->next);
	if (tnew->prev)
		printf("  prev->cur=%p (%s)\n", tnew->prev->cur, tnew->prev->cur->d_name);
	if (tnew->next)
		printf("  next->cur=%p\n", tnew->next->cur);

	return dd->last->cur->d_off;
}

static int dirdata_add_dirents(dirdata *dd, struct dirent64 *dents, unsigned int count)
{
	int pos = 0;
	struct dirent64 *curdent;
	int last_d_off;

	while (pos < count)
	{
		printf("pos: %d, count: %d\n", pos, count);
		curdent = DCAST(dents + pos);
		last_d_off = dirdata_add_dirent(dd, curdent);
		pos = pos + curdent->d_reclen;
	}

	return last_d_off;
}

static int dirdata_remove_dirent(dirdata *dd, char *name)
{
	telem *result;

	result = g_tree_lookup(dd->tree, name);
	
	if (!result)
		return 0;

	printf("asked to remove %s, lookup result: %p %p\n", name, result, result->cur);
	printf("prev=%p next=%p\n", result->prev, result->next);

	printf("result: name=%s, inode=%d, reclen=%d, off=%d\n",
			result->cur->d_name, result->cur->d_ino, result->cur->d_reclen,
			result->cur->d_off);


	if (result->prev && result->next) // Inside element
	{
		printf("inside element\n");
		
		memset(result->cur->d_name, 'A', strlen(result->cur->d_name));

		result->prev->next = result->next;
		result->next->prev = result->prev;
		printf("  -- old reclen: %d\n", result->prev->cur->d_reclen);
		result->prev->cur->d_reclen += result->cur->d_reclen;
		printf("  ++ new reclen: %d\n", result->prev->cur->d_reclen);
		printf("  -- old offset: %d\n", result->prev->cur->d_off);
		result->prev->cur->d_off = (char*)result->next->cur - (char*)dd->origdents;
		printf("  ++ new offset: %d\n", result->prev->cur->d_off);
	}
	else if (result->prev && !result->next) // Last element
	{
		assert(result->cur == dd->last->cur);
		printf("last element. old values: size=%d, last=%p last->next=%p last->cur->d_off=%ld last->cur->d_reclen=%d\n", 
				dd->size, dd->last, dd->last->next, dd->last->cur->d_off, dd->last->cur->d_reclen);
		dd->last = result->prev;
		dd->last->next = NULL;
		dd->last->cur->d_off = ((char*)dd->last - (char*)dd->origdents) + dd->last->cur->d_reclen;
		dd->last->cur->d_reclen += result->cur->d_reclen;
		dd->size = dd->last->cur->d_off;
		printf("              NEW values: size=%d, last=%p last->next=%p last->cur->d_off=%d last->cur->d_reclen=%d\n", 
				dd->size, dd->last, dd->last->next, dd->last->cur->d_off, dd->last->cur->d_reclen);
	}
	else if (!result->prev && result->next) // First element
	{
		printf("first element\n");
		dd->dents = DCAST(dd->origdents + result->cur->d_off);
		result->next->prev = NULL;
	}
	else // only one element
	{
		printf("only element\n");
		dd->dents = dd->origdents;
		dd->size = 0;
		dd->last = NULL;
	}
	g_tree_remove(dd->tree, name);
	
	printf("end remove\n");

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

#define RLROUND 8

static struct dirent64 *build_dirent(long d_ino, char *d_name)
{
	struct dirent64 *new;
	unsigned int newsize;

	newsize = sizeof(struct dirent64) - NAME_MAX + strlen(d_name);
	if (newsize % RLROUND)
		newsize += RLROUND - (newsize % RLROUND);
	
	printf("sizes: %d %d %d %d\n", sizeof(struct dirent64) ,NAME_MAX , strlen(d_name), newsize);

	new = malloc(newsize);
	new->d_ino = d_ino;
	strcpy(new->d_name, d_name);
	new->d_reclen = newsize;
	new->d_off = newsize;


}

/* Only applies if !empty */
static int apply_pending(dirdata *dd)
{
	ddreq *cur;
	int i = 0;

	if (dd->empty)
		return -1;

	while (cur = dd->pending)
	{
		printf("applying type %d on %s\n", cur->type, cur->d_name);
		switch(cur->type)
		{
			case ddadd:
				dirdata_add_dirent(dd, build_dirent(cur->d_ino, cur->d_name));
				break;

			case ddrem:
				dirdata_remove_dirent(dd, cur->d_name);
				break;
		}
		i++;
		dd->pending = cur->next;
		free(cur);
	}

	return i;


}
static int getdents64(unsigned int fd, struct dirent64 *dirp, unsigned int count)
{
	return syscall(__NR_getdents64, fd, dirp, count);
}


int dirdata_getdents64(dirdata *dd, unsigned int fd, struct dirent64 *dirp, unsigned int count)
{
	int curcount, nextcount;
	struct dirent64 *startdent, *curdent, *nextdent;

	if (dd->empty)
	{
		// Fill the dirdata structure
		printf("filling dirdata structure\n");

		int rv;
		do
		{
			printf("calling getdents... ");
			rv = getdents64(fd, dirp, count);
			printf("returns %d\n", rv);
			if (rv > 0)
				dirdata_add_dirents(dd, dirp, rv);
		}
		while (rv > 0);

		if (rv < 0)
			return rv;

		dd->empty = 0;
	}

	apply_pending(dd);

	if (dd->size == 0)
		return 0;

	startdent = curdent = DCAST(dd->origdents + dd->pos);
	curcount = 0;
	nextcount = curdent->d_off - dd->pos;

	while ((nextcount < count) && (curdent <= dd->last->cur))
	{
		printf("iterating. curcount=%d, nextcount=%d, count=%d\n", curcount, nextcount, count);
		curcount = nextcount;
		curdent = DCAST(dd->origdents + curdent->d_off);
		if (curdent <= dd->last->cur)
			nextcount = curdent->d_off - dd->pos;
	}

	memcpy(dirp, startdent, curcount);
	dd->pos += curcount;

	return curcount;

}

/*
 * If replace is non-zero, an existing file with the same name will be
 * replaced. If replace is zero, and a file with the same file exists, this
 * call will result in a no-op. 
 */
int dirdata_transform_add(dirdata *dd, long d_ino, char *d_name, int replace)
{
	ddreq *new;
	assert(dd);

	if (replace)
		dirdata_transform_remove(dd, d_name);

	new = malloc(sizeof(ddreq));

	new->type = ddadd;
	new->d_ino = d_ino;
	new->d_name = d_name;
	new->next = NULL;

	if (!dd->pending)
		dd->pending = new;
	else
		dd->pending->next = new;

	apply_pending(dd);
}

int dirdata_transform_remove(dirdata *dd, char *d_name)
{
	ddreq *new;
	assert(dd);

	new = malloc(sizeof(ddreq));

	new->type = ddrem;
	new->d_name = d_name;
	new->next = NULL;
	
	if (!dd->pending)
		dd->pending = new;
	else
		dd->pending->next = new;

	apply_pending(dd);
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

	dirdata_transform_remove(dd, "gd64helper.c");
	dirdata_transform_remove(dd, "gd64helper");
	dirdata_transform_add(dd, 0, "passwd", 0);
	
	count=dirdata_getdents64(dd, fd, dirp, 1024);



	while (pos<count)
	{
		printf("%s\n", dirp->d_name);
		len = dirp->d_reclen;
		dirp = (struct dirent64*)((char*)dirp + len);
		pos += len;
	}
}



