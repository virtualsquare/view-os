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
	 Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
	 02111-1307 USA.  */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <errno.h>
#include <stddef.h>
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
um_realpath (struct pcb *umph, const char *name, char *resolved, struct stat64 *pst)
{
	char *dest, extra_buf[PATH_MAX];
	const char *start, *end, *resolved_limit;
	int num_links = 0;

	if (!resolved)
		return NULL;
	if (name == NULL)
	{
		/* As per Single Unix Specification V2 we must return an error if
			 either parameter is a null pointer.  We extend this to allow
			 the RESOLVED parameter to be NULL in case the we are expected to
			 allocate the room for the return value.  */
		um_set_errno (umph,EINVAL);
		return NULL;
	}

	if (name[0] == '\0')
	{
		/* As per Single Unix Specification V2 we must return an error if
			 the name argument points to an empty string.  */
		um_set_errno (umph,ENOENT);
		return NULL;
	}

	resolved_limit = resolved + PATH_MAX;

	if (name[0] != '/')
	{
		if (!um_getcwd (umph,resolved, PATH_MAX))
		{
			resolved[0] = '\0';
			goto error;
		}
		dest = strchr (resolved, '\0');
	}
	else
	{
		resolved[0] = '/';
		dest = resolved + 1;
	}

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
			if (dest > resolved + 1)
				while ((--dest)[-1] != '/');
		}
		else
		{
			if (dest[-1] != '/')
				*dest++ = '/';

			if (dest + (end - start) >= resolved_limit)
			{
				um_set_errno (umph,ENAMETOOLONG);
				if (dest > resolved + 1)
					dest--;
				*dest = '\0';
				goto error;
			}

			dest = mempcpy (dest, start, end - start);
			*dest = '\0';

			/*check the dir along the path */
			if (um_x_lstat64 (resolved, pst, umph) < 0) {
				um_set_errno (umph,errno);
				goto error;
			}
			if (*end == '/' && !S_ISDIR(pst->st_mode)) {
				um_set_errno (umph,ENOTDIR);
				goto error;
			}

			if (S_ISLNK (pst->st_mode))
			{
				char buf[PATH_MAX];
				size_t len;

				if (++num_links > MAXSYMLINKS)
				{
					um_set_errno (umph,ELOOP);
					goto error;
				}

				/* symlink! */
				n = um_x_readlink (resolved, buf, PATH_MAX, umph);
				if (n < 0) {
					um_set_errno (umph,errno);
					goto error;
				}
				buf[n] = '\0';

				len = strlen (end);
				if ((long int) (n + len) >= PATH_MAX)
				{
					um_set_errno (umph,ENAMETOOLONG);
					goto error;
				}

				/* Careful here, end may be a pointer into extra_buf... */
				memmove (&extra_buf[n], end, len + 1);
				name = end = memcpy (extra_buf, buf, n);

				if (buf[0] == '/')
					dest = resolved + 1;	/* It's an absolute symlink */
				else
					/* Back up to previous component, ignore if at root already: */
					if (dest > resolved + 1)
						while ((--dest)[-1] != '/');
			}
		}
	}
	if (dest > resolved + 1 && dest[-1] == '/')
		--dest;
	*dest = '\0';

	um_set_errno (umph,0);
	return resolved;

error:
	*resolved = 0;
	return NULL;
}

