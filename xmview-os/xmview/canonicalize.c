/* xmview is moving to a new recursive implementation of the
	 path canonicalize function.
   define RECURSIVE_CANONICALIZE for the new one
   undef RECURSIVE_CANONICALIZE for the old one */

#define RECURSIVE_CANONICALIZE
#ifdef RECURSIVE_CANONICALIZE
/*   This is part of ViewOS
 *   umview-kmview -- A Process with a View
 *
 *   canonicalize.c: recursively canonicalize filenames
 *   
 *   Copyright 2009 Renzo Davoli University of Bologna - Italy
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
 */

#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <alloca.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include "services.h"
#include "sctab.h"
 
#define PERMIT_NONEXISTENT_LEAF
#define DOTDOT 1
#define ROOT 2

struct canonstruct {
	void *xpc;
	char *ebuf;
	char *start;
	char *end;
	char *resolved;
	short rootlen;
	struct stat64 *statbuf;
	short num_links;
	int dontfollowlink;
};

/* recursive construction of canonical absolute form of a filename.
	 This function gets called recursively for each component of the resolved path.
   return value: 0 successful canonicalize
                 DOTDOT (..) return to the previous level
                 ROOT, canonicalize stepped onto an absolute symlink
                       resulution must return back to the root (or chroot rootcage) 
								 -1 error
 */

static int rec_realpath(struct canonstruct *cdata, char *dest)
{
	char *newdest;
	/* LOOP (***) This loop manages '.'
		 '..' (DOTDOT) from an inner call
		 ROOT if this is the root dir layer */
	while (1) {
		*dest=0;
		/*fprintf(stderr,"looprealpath %s -> %s\n",cdata->ebuf,cdata->resolved);*/
		/* delete multiple slashes / */
		while (*cdata->start == '/')
			cdata->start++;
		/* find the next component */
		for (cdata->end = cdata->start; *cdata->end && *cdata->end != '/'; ++cdata->end)
			;
		/* '.': continue with the next component of the path, forget this */
		if (cdata->end-cdata->start == 1 && cdata->start[0] == '.') {
			cdata->start=cdata->end;
			continue; /* CONTINUE: NEXT ITERATION OF THE LOOP (***) */
		}
		/* '..' */
		if (cdata->end-cdata->start == 2 && cdata->start[0] == '.' && cdata->start[1] == '.') {
			cdata->start=cdata->end;
			/* return DOTDOT only if this does not goes outside the current root */
			if (dest > cdata->resolved+cdata->rootlen)
				return DOTDOT;
			else
				continue; /* CONTINUE: NEXT ITERATION OF THE LOOP (***) */
		}
		if (cdata->statbuf->st_mode==0)
			um_x_lstat64(cdata->resolved,cdata->statbuf,cdata->xpc);
		/* nothing more to do */
		if (cdata->end-cdata->start == 0) 
			return 0;
		/* overflow check */
		if (dest + (cdata->end - cdata->start) > cdata->resolved + PATH_MAX) {
			um_set_errno(cdata->xpc,ENAMETOOLONG);
			return -1;
		}
		/* add the new component */
		newdest=dest;
		if (newdest[-1] != '/')
			*newdest++='/';
		newdest=mempcpy(newdest,cdata->start,cdata->end-cdata->start);
		*newdest=0;
		/* does the file exist? */
		if (um_x_lstat64(cdata->resolved,cdata->statbuf,cdata->xpc) < 0) {
			cdata->statbuf->st_mode=0;
#ifdef PERMIT_NONEXISTENT_LEAF
			if (errno != ENOENT || *cdata->end == '/') {
				um_set_errno(cdata->xpc,ENOENT);
				return -1;
			} else
				return 0;
#else
			um_set_errno(cdata->xpc,ENOENT);
			return -1;
#endif
		}
		/* Symlink case */
		if (S_ISLNK(cdata->statbuf->st_mode) &&
				((*cdata->end == '/') || !cdata->dontfollowlink))
		{
			/* root dir must be already canonicalized.
				 symlinks navigating inside the root link are errors */
			if (dest <= cdata->resolved+cdata->rootlen) {
				um_set_errno(cdata->xpc,ENOENT);
				return -1;
			} else
			{
				char buf[PATH_MAX];
				size_t len,n;
				/* test for symlink loops */
				if (++cdata->num_links > MAXSYMLINKS) {
					um_set_errno(cdata->xpc,ELOOP);
					return -1;
				}
				/* read the link */
				n = readlink(cdata->resolved, buf, PATH_MAX-1);
				if (n<0)  {
					um_set_errno(cdata->xpc,errno);
					return -1;
				}
				buf[n]=0;
				/* overflow check */
				len=strlen(cdata->end);
				if (n+len >= PATH_MAX) {
					um_set_errno(cdata->xpc,ENAMETOOLONG);
					return -1;
				}
				/* append symlink and remaining part of the path,
					 the latter part is moved inside ebuf itself */
				memmove(cdata->ebuf+n,cdata->end,len+1);
				cdata->end = memcpy(cdata->ebuf,buf,n);
				/* if the symlink is absolute the scan must return
					 back to the current root otherwise from the
				   same dir of the symlink */
				if (*buf == '/') {
					cdata->start=cdata->ebuf;
					return ROOT;
				} else {
					cdata->start=cdata->end;
					continue; /* CONTINUE: NEXT ITERATION OF THE LOOP (***) */
				}
			}
		}
		/* consistency checks on dirs:
			 all the components of the path but the last one must be
			 directories and must have 'x' permission */
		if (*cdata->end == '/') {
		 	if (!S_ISDIR(cdata->statbuf->st_mode)) {
				um_set_errno(cdata->xpc,ENOTDIR);
				return -1;
			} else if (um_x_access(cdata->resolved,X_OK,cdata->xpc) < 0) {
				um_set_errno(cdata->xpc,errno);
				return -1;
			}
		}
		/* okay: recursive call for the next component */
		cdata->start=cdata->end;
		switch(rec_realpath(cdata,newdest)) {
			/* success. close recursion */
			case 0 : return 0;
			/* DOTDOT: cycle at this layer */
			case DOTDOT: 
							   cdata->statbuf->st_mode=0;
							   continue; /* CONTINUE: NEXT ITERATION OF THE LOOP (***) */
			/* ROOT: close recursive calls up the root */
			case ROOT: cdata->statbuf->st_mode=0;
								 if (dest > cdata->resolved+cdata->rootlen) 
									 return ROOT;
								 else
									 continue; /* CONTINUE: NEXT ITERATION OF THE LOOP (***) */
			/* Error */
			default: return -1;
		}
	}
}


/* realpath: 
name: path to be canonicalized,
root: current root (chroot), must already be in canonical form
cwd: current working directory, must already be in canonical form
resolved: a buffer of PATH_MAX chars for the result
return resolved or NULL on failures.
errno is set consistently */
char *um_realpath(const char *name, const char *cwd, char *resolved, 
		struct stat64 *pst, int dontfollowlink, void *xpc)
{
	char *root=um_getroot(xpc);
	struct canonstruct cdata= {
		.ebuf=alloca(PATH_MAX),
		.resolved=resolved,
		.rootlen=strlen(root),
		.statbuf=pst,
		.dontfollowlink=dontfollowlink,
		.xpc=xpc,
		.num_links=0
	};
	/* arg consistency check */
	if (name==NULL) {
		um_set_errno(xpc,EINVAL);
		return NULL;
	}
	if (*name==0) {
		um_set_errno(xpc,ENOENT);
		return NULL;
	}
	/* absolute path: 
	   append 'name' to the current root */
	if (*name=='/') {
		int namelen=strlen(name);
		memcpy(cdata.ebuf,root,cdata.rootlen);
		if (cdata.ebuf[cdata.rootlen-1] != '/') {
			cdata.ebuf[cdata.rootlen]='/';
			cdata.rootlen++;
		}
		/* overflow check */
		if (cdata.rootlen + namelen >= PATH_MAX) {
			um_set_errno(xpc,ENAMETOOLONG);
			return NULL;
		}
		memcpy(cdata.ebuf+cdata.rootlen,name+1,namelen);
	} else 
		/* relative path 
		   append 'name' to the cwd */
	{ 
		int namelen=strlen(name);
		int cwdlen=strlen(cwd);
		memcpy(cdata.ebuf,cwd,cwdlen);
		if (cdata.ebuf[cwdlen-1] != '/') {
			cdata.ebuf[cwdlen]='/';
			cwdlen++;
		}
		/* cwd inside the current root:
			 set the immutable part of the path (inside the chroot cage) */
		if (strncmp(cdata.ebuf,root,cdata.rootlen)==0 &&
				(root[cdata.rootlen-1]=='/' || cdata.ebuf[cdata.rootlen]=='/')) {
			if (root[cdata.rootlen-1]!='/')
				cdata.rootlen++;
		} else
			cdata.rootlen=1;
		/* overflow check */
		if (cwdlen + namelen>= PATH_MAX) {
			um_set_errno(xpc,ENAMETOOLONG);
			return NULL;
		}
		memcpy(cdata.ebuf+cwdlen,name,namelen+1);
	}
	/* fprintf(stderr,"PATH! %s (inside %s)\n",cdata.ebuf,cdata.ebuf+cdata.rootlen);*/
	resolved[0]='/';
	cdata.start=cdata.ebuf+1;
	pst->st_mode=0;
	/* start the recursive canonicalization function */
	if (rec_realpath(&cdata,resolved+1) < 0) {
		*resolved=0;
		return NULL;
	} else {
		um_set_errno(xpc,0);
		return resolved;
	}
}
#else 
/* Return the canonical absolute name of a given file.
	 Copyright (C) 1996-2001, 2002 Free Software Foundation, Inc.
	 This file is part of the GNU C Library.
	 Modified for um-viewos (C) Renzo Davoli 2005-2006

	 The GNU C Library is free software; you can redistribute it and/or
	 modify it under the terms of the GNU Lesser General Public
	 License as published by the Free Software Foundation; either
	 version 2.1 of the License, or (at your option) any later version.

	 The GNU C Library is distributed in the hope that it will be useful,
	 but WITHOUT ANY WARRANTY; without even the implied warranty of
	 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
	 Lesser General Public License for more details.

	 You should have received a copy of the GNU Lesser General Public
	 License along with the GNU C Library; if not, write to the Free
	 Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
	 02110-1301 USA.  */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <errno.h>
#include <stddef.h>
#include <config.h>
#include "sctab.h"

/* Return the canonical absolute name of file NAME.  A canonical name
	 does not contain any `.', `..' components nor any repeated path
	 separators ('/') or symlinks.  All path components must exist.  If
	 RESOLVED is null, the result is malloc'd; otherwise, if the
	 canonical name is PATH_MAX chars or more, returns null with `errno'
	 set to ENAMETOOLONG; if the name fits in fewer than PATH_MAX chars,
	 returns the name in RESOLVED.  If the name cannot be resolved and
	 RESOLVED is non-NULL, it contains the path of the first component
	 that cannot be resolved.  If the path can be resolved, RESOLVED
	 holds the same value as the value returned.  */

char *
um_realpath (const char *name, const char *cwd, char *resolved, struct stat64 *pst, int dontfollowlink,void *xpc)
{
	char *dest, extra_buf[PATH_MAX];
	const char *start, *end, *resolved_limit; 
	char *resolved_root;
	int num_links = 0;
	int validstat = 0;
	char *root=um_getroot(xpc);
	int rootlen=strlen(root);

	if (!resolved)
		return NULL;
	if (name == NULL)
	{
		/* As per Single Unix Specification V2 we must return an error if
			 either parameter is a null pointer.  We extend this to allow
			 the RESOLVED parameter to be NULL in case the we are expected to
			 allocate the room for the return value.  */
		um_set_errno (xpc,EINVAL);
		goto error;
	}

	if (name[0] == '\0')
	{
		/* As per Single Unix Specification V2 we must return an error if
			 the name argument points to an empty string.  */
		um_set_errno (xpc,ENOENT);
		goto error;
	}

	resolved_limit = resolved + PATH_MAX;

	/* relative path, the first char is not '/' */
	if (name[0] != '/')
	{
		if (cwd == NULL)
			goto error;
		strncpy(resolved,cwd,PATH_MAX);
		/* if the cwd is inside the chroot cage, set the unchangeable
		 * part of the path */
		if (strncmp(root,resolved,rootlen) == 0)
			resolved_root=resolved+rootlen;
		else
			resolved_root = resolved+1;
		dest = strchr (resolved, '\0');
	}
	else
	{
	/* absolute path */
		if (rootlen > PATH_MAX) {
			um_set_errno (xpc,ENAMETOOLONG);
			goto error;
		}
		dest=resolved;
		/* '/' is converted to the current root */
		dest=resolved_root=mempcpy(dest,root,rootlen);
		resolved[0] = '/';
		/* special case "/" */
		if (name[1] == 0) {
			*dest='\0';
			if (um_x_lstat64 (resolved, pst, xpc) < 0)
				um_set_errno (xpc,errno);
			else
				um_set_errno (xpc,0);
			return resolved;
		}
	}

	/* now resolved is the current wd or "/", navigate through the 
	 * path */
	for (start = end = name; *start; start = end)
	{
		int n;

		/* Skip sequence of multiple path-separators.  */
		while (*start == '/')
			++start;

		/* Find end of path component.  */
		for (end = start; *end && *end != '/'; ++end)
			/* Nothing.  */;

		if (end - start == 0)
			break;
		else if (end - start == 1 && start[0] == '.')
			/* nothing */;
		else if (end - start == 2 && start[0] == '.' && start[1] == '.')
		{
			/* Back up to previous component, ignore if at root already.  */
			validstat = 0;
			if (dest > resolved_root)
				while ((--dest)[-1] != '/');
		}
		else
		{
			if (dest[-1] != '/')
				*dest++ = '/';

			if (dest + (end - start) >= resolved_limit)
			{
				um_set_errno (xpc,ENAMETOOLONG);
				if (dest > resolved_root)
					dest--;
				*dest = '\0';
				goto error;
			}

			/* copy the component */
			dest = mempcpy (dest, start, end - start);
			*dest = '\0';

			/*check the dir along the path */
			validstat = 1;
			if (um_x_lstat64 (resolved, pst, xpc) < 0) {
				pst->st_mode=0;
				if (errno != ENOENT || *end == '/') {
					um_set_errno (xpc,errno);
					goto error;
				}
			} else {
				/* this is a symbolic link, thus restart the navigation from
				 * the symlink location */
				if (S_ISLNK (pst->st_mode) &&
						((*end == '/') || !dontfollowlink))
				{
					char buf[PATH_MAX];
					size_t len;

					if (++num_links > MAXSYMLINKS)
					{
						um_set_errno (xpc,ELOOP);
						goto error;
					}

					/* symlink! */
					validstat=0;
					n = um_x_readlink (resolved, buf, PATH_MAX, xpc);
					if (n < 0) {
						um_set_errno (xpc,errno);
						goto error;
					}
					buf[n] = '\0';

					len = strlen (end);
					if ((long int) (n + len) >= PATH_MAX)
					{
						um_set_errno (xpc,ENAMETOOLONG);
						goto error;
					}

					/* Careful here, end may be a pointer into extra_buf... */
					memmove (&extra_buf[n], end, len + 1);
					name = end = memcpy (extra_buf, buf, n);

					if (buf[0] == '/')
						dest = resolved_root;	/* It's an absolute symlink */
					else
						/* Back up to previous component, ignore if at root already: */
						if (dest > resolved + 1)
							while ((--dest)[-1] != '/');
				}
				else if (*end == '/' && !S_ISDIR(pst->st_mode)) {
					um_set_errno (xpc,ENOTDIR);
					goto error;
				}
				else if (*end == '/') {
					if (um_x_access(resolved,X_OK,xpc)!=0) {
						um_set_errno (xpc,EACCES);
						goto error;
					}
				}
			}
		}
	}
	if (dest > resolved + 1 && dest[-1] == '/')
		--dest;
	*dest = '\0';

	if (!validstat && um_x_lstat64 (resolved, pst, xpc) < 0) 
		pst->st_mode=0;

	um_set_errno (xpc,0);
	return resolved;

error:
	pst->st_mode=0;
	*resolved = 0;
	return NULL;
}
#endif
