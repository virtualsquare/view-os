/*
 *
 * Copyright (C) 2007 Renzo Davoli (renzo@cs.unibo.it)
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  Due to this file being licensed under the GPL there is controversy over
 *  whether this permits you to write a module that #includes this file
 *  without placing your module under the GPL.  Please consult a lawyer for
 *  advice before doing this.
 *
 */

#include "kmview_data.h"
#include "kmview_fdsysset.h"

#ifdef USE_KMEM_CACHE
static struct kmem_cache *kmview_fdsysset_cache;
#endif

static inline struct kmview_fdsysset *fdsysset_internal_malloc(void)
{
#ifdef USE_KMEM_CACHE
	return kmem_cache_alloc(kmview_fdsysset_cache,GFP_KERNEL);
#else
	return kmalloc(sizeof(struct kmview_fdsysset),GFP_KERNEL);
#endif
}

static inline void fdsysset_internal_free(struct kmview_fdsysset *fds)
{
#ifdef USE_KMEM_CACHE
	kmem_cache_free(kmview_fdsysset_cache,fds);
#else
	kfree(fds);
#endif
}

struct kmview_fdsysset *fdsysset_copy(struct kmview_fdsysset *fds)
{
	if (fds == NULL)
		return NULL;
	else {
		fds->ncopy++;
		return(fds);
	}
}

struct kmview_fdsysset *fdsysset_set(int fd, struct kmview_fdsysset *fds)
{
	struct kmview_fdsysset *ret;
	if (fds == NULL) {
		ret=fdsysset_internal_malloc();
		ret->ncopy=1;
		ret->nfd=1;
		FD_ZERO(&ret->fdset);
		FD_SET(fd,&ret->fdset);
	} else if (!FD_ISSET(fd,&fds->fdset)) {
		if (fds->ncopy > 1) {
			ret=fdsysset_internal_malloc();
			*ret=*fds;
			ret->nfd=fds->nfd;
			ret->ncopy=1;
			fds->ncopy--;
		} else
			ret=fds;
		FD_SET(fd,&ret->fdset);
		ret->nfd++;
	} else
		ret=fds;
	return ret;
}

struct kmview_fdsysset *fdsysset_clr(int fd, struct kmview_fdsysset *fds)
{ 
	struct kmview_fdsysset *ret;
	if (fds != NULL && FD_ISSET(fd,&fds->fdset)) {
		if (fds->ncopy > 1) {
			fds->ncopy--;
			if (fds->nfd == 1)
				ret=NULL;
			else {
				ret=fdsysset_internal_malloc();
				*ret=*fds;
				ret->nfd=fds->nfd;
				ret->ncopy=1;
				fds->ncopy--;
			}
		} else {
			if (fds->nfd == 1) {
				ret=NULL;
				fdsysset_internal_free(fds);
			} else
				ret=fds;
		}
		if (ret) {
			FD_CLR(fd,&ret->fdset);
			ret->nfd--;
		}
	} else
		ret=fds;
	return ret;
}

void fdsysset_free(struct kmview_fdsysset *fds) {
	if (fds) {
		if (fds->ncopy > 1)
			fds->ncopy--;
		else 
			fdsysset_internal_free(fds);
	}
}

int fdsysset_init(void)
{
#ifdef USE_KMEM_CACHE
	if ((kmview_fdsysset_cache = KMEM_CACHE(kmview_fdsysset, 0)))
		return 0;
	else
		return -ENOMEM;
#else
	return 0;
#endif
}

void fdsysset_fini(void)
{
#ifdef USE_KMEM_CACHE
	if (kmview_fdsysset_cache)
		kmem_cache_destroy(kmview_fdsysset_cache);
#endif
}
