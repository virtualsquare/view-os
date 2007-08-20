/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   ViewFS
 *   It is possible to remap files and directories
 *   
 *   Copyright 2005, 2006 Ludovico Gardenghi
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

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>
#include <config.h>

#include "gdebug.h"
#include "module.h"
#include "libummod.h"
#include "syscallnames.h"

#define VIEWFS_SERVICE_CODE 0x05
#define TABSTEP 4

#define TRUE (0 == 0)
#define FALSE (!TRUE)

/*
 * N_{DATA, META, RMETA} must be of the same length (N_LEN)
 * RMETA stays for ROOT META and is used because the root directory
 * does not have a "name"
 */

#define N_DATA  "d/"
#define N_META  "m/"
#define N_RMETA "rm"
#define N_LEN 2

#define T_DATA 0x01
#define T_META 0x02
#define T_DIR  0x04

/*
 * VNUL must be OR'ed to every flag before using the result as the argument to
 * symlink(). VDIR tells if the object is a file or a directory. VINV stays
 * for "invalid" and should never be found on the file system but will be
 * returned by read_flags as an error condition.
 */

#define VDIR 0x01 // .......o
#define VCOW 0x02 // ......o.
#define VMOV 0x04 // .....o..
#define VMRG 0x08 // ....o...
#define VADD 0x10 // ...o....
#define VREM 0x20 // ..o.....
#define VNUL 0x40 // .o......
#define VINV 0x80 // o.......

/* VALL does not include VINV, but does include VNUL. It is the set of all
 * valid bits for a symlink. */
#define VALL (VNUL | VREM | VADD | VMRG | VMOV | VCOW | VDIR)

typedef unsigned char vflag_t;

static struct service s;

struct viewfs_proc
{
	struct viewfs_layer *l;
};

static struct viewfs_proc **proctab = NULL;
static int proctabmax = 0;

static char fnbuf[2*PATH_MAX];

struct viewfs_layer
{
	// Where ViewFS must start to apply this layer
	char *mountpoint;
	// Location of the description tree for this layer
	char *vfspath;
	
	char *testpath;
	char *userpath;

	unsigned long mountflags;
	struct timestamp tst;
	// Is this layer mounted in maintenance mode?
	int maint;
	unsigned long used;
};

static struct viewfs_layer **layertab = NULL;
static int layertabmax = 0;

static long action_path_enoent()
{
	errno = ENOENT;
	return -1;
}

static long action_path_invalid()
{
	return -1;
}

static long action_stat64_data()
{
	return 0;
}

static long action_stat64_link()
{
	return 0;
}


/* Action to take based on the flags found in the meta. NULL means
 * "do the real syscall". Else, the function is called. The parameters
 * depend on the system call, it's up to the caller and the callee agree on
 * them. */

static sysfun action_map_stat64[] = {
/*                                         */ NULL,
/*                                    VDIR */ NULL,
/*                             VCOW |      */ NULL,
/*                             VCOW | VDIR */ NULL,
/*                      VMOV |             */ action_stat64_link,
/*                      VMOV |        VDIR */ action_stat64_link,
/*                      VMOV | VCOW |      */ action_stat64_link,
/*                      VMOV | VCOW | VDIR */ action_stat64_link,
/*               VMRG |                    */ action_path_invalid,
/*               VMRG |               VDIR */ NULL,
/*               VMRG |        VCOW |      */ action_path_invalid,
/*               VMRG |        VCOW | VDIR */ NULL,
/*               VMRG | VMOV |             */ action_path_invalid,
/*               VMRG | VMOV |        VDIR */ NULL,
/*               VMRG | VMOV | VCOW |      */ action_path_invalid,
/*               VMRG | VMOV | VCOW | VDIR */ NULL,
/*        VADD |                           */ action_stat64_data,
/*        VADD |                      VDIR */ action_stat64_data,
/*        VADD |               VCOW |      */ action_stat64_data,
/*        VADD |               VCOW | VDIR */ action_stat64_data,
/*        VADD |        VMOV |             */ action_path_invalid,
/*        VADD |        VMOV |        VDIR */ action_path_invalid,
/*        VADD |        VMOV | VCOW |      */ action_path_invalid,
/*        VADD |        VMOV | VCOW | VDIR */ action_path_invalid,
/*        VADD | VMRG |                    */ action_path_invalid,
/*        VADD | VMRG |               VDIR */ action_stat64_data,
/*        VADD | VMRG |        VCOW |      */ action_path_invalid,
/*        VADD | VMRG |        VCOW | VDIR */ action_stat64_data,
/*        VADD | VMRG | VMOV |             */ action_path_invalid,
/*        VADD | VMRG | VMOV |        VDIR */ action_path_invalid,
/*        VADD | VMRG | VMOV | VCOW |      */ action_path_invalid,
/*        VADD | VMRG | VMOV | VCOW | VDIR */ action_path_invalid,
/* VREM |                                  */ action_path_enoent,
/* VREM |                             VDIR */ action_path_enoent,
/* VREM |                      VCOW |      */ action_stat64_data,
/* VREM |                      VCOW | VDIR */ action_stat64_data,
/* VREM |               VMOV |             */ action_path_invalid,
/* VREM |               VMOV |        VDIR */ action_path_invalid,
/* VREM |               VMOV | VCOW |      */ action_path_invalid,
/* VREM |               VMOV | VCOW | VDIR */ action_path_invalid,
/* VREM |        VMRG |                    */ action_path_invalid,
/* VREM |        VMRG |               VDIR */ action_path_invalid,
/* VREM |        VMRG |        VCOW |      */ action_path_invalid,
/* VREM |        VMRG |        VCOW | VDIR */ action_path_invalid,
/* VREM |        VMRG | VMOV |             */ action_path_invalid,
/* VREM |        VMRG | VMOV |        VDIR */ action_path_invalid,
/* VREM |        VMRG | VMOV | VCOW |      */ action_path_invalid,
/* VREM |        VMRG | VMOV | VCOW | VDIR */ action_path_invalid,
/* VREM | VADD |                           */ action_stat64_data,
/* VREM | VADD |                      VDIR */ action_stat64_data,
/* VREM | VADD |               VCOW |      */ action_stat64_data,
/* VREM | VADD |               VCOW | VDIR */ action_stat64_data,
/* VREM | VADD |        VMOV |             */ action_path_invalid,
/* VREM | VADD |        VMOV |        VDIR */ action_path_invalid,
/* VREM | VADD |        VMOV | VCOW |      */ action_path_invalid,
/* VREM | VADD |        VMOV | VCOW | VDIR */ action_path_invalid,
/* VREM | VADD | VMRG |                    */ action_path_invalid,
/* VREM | VADD | VMRG |               VDIR */ action_path_invalid,
/* VREM | VADD | VMRG |        VCOW |      */ action_path_invalid,
/* VREM | VADD | VMRG |        VCOW | VDIR */ action_path_invalid,
/* VREM | VADD | VMRG | VMOV |             */ action_path_invalid,
/* VREM | VADD | VMRG | VMOV |        VDIR */ action_path_invalid,
/* VREM | VADD | VMRG | VMOV | VCOW |      */ action_path_invalid,
/* VREM | VADD | VMRG | VMOV | VCOW | VDIR */ action_path_invalid
};

static void cutdots(char *path)
{
	int l = strlen(path);
	GDEBUG(5, "original string: %s", path);
	l--;
	if (path[l] == '.')
	{
		l--;
		if (path[l] == '/')
		{
			if (l)
				path[l] = 0;
			else
				path[l+1] = 0;
		}
		else if (path[l] == '.')
		{
			l--;
			if (path[l] == '/')
			{
				while (l > 0)
				{
					l--;
					if (path[l] == '/')
						break;
				}
				if(path[l] == '/')
				{
					if (l)
						path[l] = 0;
					else
						path[l+1] = 0;
				}
			}
		}
	}
	GDEBUG(5, "final string   : %s", path);
}

static void addlayertab(struct viewfs_layer *new)
{
	int i;
	
	// Search for an empty slot or end of table
	for (i = 0; (i < layertabmax) && layertab[i]; i++);

	if (i >= layertabmax)
	{
		int j;
		int newmax = (i + TABSTEP) & ~(TABSTEP -1);
		
		layertab = realloc(layertab, newmax * sizeof(struct viewfs_layer *));
		assert(layertab);

		for (j = i; j < newmax; j++)
			layertab[j] = NULL;
		
		layertabmax = newmax;
	}

	layertab[i] = new;

	GDEBUG(2, "inserted layer %s -> %s with timestamp %llu at index %d", new->vfspath, new->mountpoint, new->tst.epoch, i);
}

static void dellayertab(struct viewfs_layer *layer)
{
	int i;
	for (i = 0; (i < layertabmax) && (layer != layertab[i]); i++);
	if (i < layertabmax)
		layertab[i] = NULL;
}


static struct viewfs_layer *searchlayer(char *path, int exact)
{
	struct viewfs_layer *result = NULL;
	int bestmatch = -1;
	int i, j;
	epoch_t e, maxe = 0;
	char oldp;

	if (!path || !path[0])
		return NULL;

	cutdots(path);

	GDEBUG(2, "trying to match path %s", path);

	if (exact)
	{
		for (j = 0; j < layertabmax; j++)
		{
			if (!layertab[j])
				continue;

			GDEBUG(2, " - comparing with %s", layertab[j]->mountpoint);
			if ((strcmp(path, layertab[j]->mountpoint) == 0) &&
				((e = tst_matchingepoch(&(layertab[j]->tst))) > maxe))
				{
					bestmatch = j;
					maxe = e;
					GDEBUG(2, " + match! bestmatch = %d, maxe = %llu", bestmatch, maxe);
				}
			else
				GDEBUG(2, "e = %llu, maxe = %llu", e, maxe);
		}
	}
	else
	{

		for (j = 0; j < layertabmax; j++)
		{
			if (!layertab[j])
				continue;

			GDEBUG(2, " - comparing with %s", layertab[j]->mountpoint);
			
			// Search for longest common subsection starting from 1st char
			i = -1;
			do
			{
				i++;
				if ((path[i] != layertab[j]->mountpoint[i]) && layertab[j]->mountpoint[i])
					break;

				if (((path[i] == '/') || !path[i]) && (!layertab[j]->mountpoint[i]))
				{
					/**** Debug statements */
					oldp = path[i];
					path[i] = 0;
					GDEBUG(2, "   - looking for epoch for match %s", path);
					path[i] = oldp;
					/**** End of debug statements */

					if ((e = tst_matchingepoch(&(layertab[j]->tst))) > maxe)
					{
						bestmatch = j;
						maxe = e;
						GDEBUG(2, "   + match! bestmatch = %d, maxe = %d", bestmatch, maxe);
					}
				}
			}
			while (path[i] && layertab[j]->mountpoint[i]);
		}
	}

	if (bestmatch < 0)
	{
		GDEBUG(4, "no match found, returning NULL");
		return NULL;
	}

	result = layertab[bestmatch];

	GDEBUG(2, "returning %s", result->mountpoint);
	return result;
}

/*
 * Convert the path contained in `old' in a new path. The new one will be stored
 * in a buffer of size `size' pointed to by `new'. The conversion depends on
 * the value of `type': (let's assume that N_RMETA == "/rmeta", N_DATA ==
 * "/data", N_META == "/meta").
 *
 * If the given path is the empty string, it is treated as "/".
 *
 * type             old           new
 * T_DATA           /             /data   (/ is a directory, T_DIR is implied)
 * T_META           /             /rmeta  (/ is a directory, T_DIR is implied)
 * T_DATA & T_DIR   /             /data
 * T_META & T_DIR   /             /rmeta
 *
 * T_DATA           /a/b          /data/a/data/b
 * T_META           /a/b          /data/a/meta/b
 * T_DATA & T_DIR   /a/b          /data/a/data/b/data
 * T_META & T_DIR   /a/b          /data/a/meta/b (T_DIR has no effect on meta)
 */
static char *extend_path(char *old, char *new, int size, int type)
{
	int oc, nc, lastd;

	/* "/" must be treated in a special way because it has "no name" */
	if ( (old[0] == '\0') || (old[1] == '\0'))
	{
		GDEBUG(3, "old is either empty or root, adding /%s or /%s", N_RMETA, N_DATA);
		switch (type & (T_META | T_DATA))
		{
			case T_META:
				snprintf(new, size, "/%s", N_RMETA);
				break;

			case T_DATA:
				snprintf(new, size, "/%s", N_DATA);
				break;
		}
		return new;
	}

	for (oc = 0, nc = 0; old[oc] && nc < (size - 1); oc++, nc++)
	{
		GDEBUG(3, "copying '%c'@%d on '%c'@%d", old[oc], oc, new[nc], nc);
		new[nc] = old[oc];
		if (new[nc] == '/')
		{
			if ((nc + N_LEN) >= (size - 2))
				return NULL;
			
			memcpy(&new[nc + 1], N_DATA, N_LEN);
			lastd = nc + 1;

			nc += N_LEN;
		}
	}

	if (nc > size - 1)
		return NULL;

	/* 
	 * At this point nc points immediatly after the end of the 
	 * new path. Usually you should put a \0 at new[nc] now. But that's not
	 * always the case.
	 */

	if (type & T_META) // We don't care about T_DIR in this case
	{
		/*
		 * Substitute the last N_DATA with N_META, e.g.
		 * /a/b/c is now /data/a/data/b/data/c and must become
		 * /data/a/data/b/meta/c. This does not affect new's length.
		 */
		memcpy(&new[lastd], N_META, N_LEN);
	}
	else if ((type & T_DATA) && (type & T_DIR))
	{
		if ((nc + 1 + N_LEN) > (size - 1))
			return NULL;

		new[nc++] = '/';
		memcpy(&new[nc], N_DATA, N_LEN);
		nc += N_LEN;
	}
	
	new[nc] = '\0';

	return new;
}

/*
 * Converts the given path (i.e. /foo/bar) in the META path for the vfs tree
 * (e.g. /home/user/.viewfs/data/foo/data/bar) assuming that "bar" is a file
 * and not a directory.
 */
static void prepare_testpath(struct viewfs_layer *layer, char *path)
{
	char *tmp;
	int delta = strlen(layer->mountpoint);
	
	assert(strncmp(path, layer->mountpoint, strlen(layer->mountpoint)) == 0);

	if (delta == 1)
		delta--;

	tmp = path + delta;

	GDEBUG(2, "path: %s, layer->mountpoint: %s, delta: %d, tmp: %s",
			path, layer->mountpoint, delta, tmp);

	/* META is the same for directories and files */
	extend_path(tmp, layer->userpath, (2 * PATH_MAX) - strlen(layer->vfspath), T_META);

	GDEBUG(2, "layer->vfspath: %s", layer->vfspath);
	GDEBUG(2, "extend_path(\"%s\", \"%s\", %d, 0x%02x)", tmp, layer->userpath, (2*PATH_MAX)-strlen(layer->vfspath), T_DATA);

	// GDEBUG(2, "tmp: ^%s$, delta: %d", tmp, delta);
	// GDEBUG(2, "userpath: ^%s$", layer->userpath);

	GDEBUG(2, "asked for ^%s$, will check for ^%s$", path, layer->testpath);
}

static vflag_t read_flags(char *path)
{
	vflag_t lc;
	int rv;

	GDEBUG(2, "trying to read flags from %s", path);

	rv = readlink(path, &lc, 1);

	if (rv < 0)
	{
		GDEBUG(2, "  failed: %s", strerror(errno));
		return VINV;
	}

	/* symlink length must be exaclty 1 char */
	if (readlink(path, &lc, 1) != 1)
	{
		GDEBUG(2, "  failed, wrong length: %d", rv);
		return VINV;
	}

	/* There must not be invalid bits */
	if (lc & ~VALL)
	{
		GDEBUG(2, "  failed, invalid bits: 0x%02x", lc);
		return VINV;
	}

	/* VNUL is used on the file system but not internally */
	lc &= ~VNUL;

	GDEBUG(2, "  ok, flags: 0x%02x", lc);
	return lc;
}

static vflag_t make_flags(vflag_t flags)
{
	return (flags & VALL) | VNUL;
}

/**
 * Find an existing meta file.
 *
 * @param path The already meta-expanded path, relative to the start of
 * the vfs (e.g. /d/dir1/d/dir2/m/file. If this pathname does not exists, it
 * will be replaced with the deepest existing meta for one of the directories
 * of path. Else, the function does nothing.
 * Warning: this function modifies path, so you must take care of strdup()ing
 * it somewhere else if you want to retain the original one.
 * @param base_path A pointer to the absolute pathi (e.g. a pointer to
 * /home/user/.viewfs/test/d/dir1/d/dir2/m/file). This will be passed to
 * read_flags after each change made to path. The initial part of base_path
 * (from the beginning to the string pointed to by path) will not be modified.
 *
 * @return The flags associated to the meta (if found), or VINV if not found.
 */
static vflag_t find_deepest_meta(char *path, char *base_path)
{
	int found = 0;
	vflag_t rv;
	int sc;
	int pos;

	if ((rv = read_flags(base_path)) != VINV)
		return rv;

	pos = strlen(path) - 1;

	/* If the path is /rmeta (or less, though it should never be less than
	 * this), we cannot go up */

	if (pos <= N_LEN)
		return VINV;

	for (;;)
	{
		// sc is slash count, i.e. the number of slashes we must
		// traverse to transform /data/name1/meta/name2 into
		// /meta/name1
		sc = 4;
		while ((sc > 2) && (pos >= 0))
		{
			if (path[pos] == '/')
				sc--;

			pos--;
		}

		if (pos < 0)
		{
			if (strlen(path) < (N_LEN + 1))
				return VINV;
			strncpy(&(path[1]), N_RMETA, N_LEN + 1);
			if ((rv = read_flags(base_path)) != VINV)
				return rv;
			return VINV;
		}

		path[pos + 1] = '\0';

		while ((sc > 0) && (pos >= 0))
		{
			if (path[pos] == '/')
				sc--;

			pos--;
		}


		// Replace data with meta (the ending / is already there)
		memcpy(&(path[pos+2]), N_META, N_LEN - 1);

		if ((rv = read_flags(base_path)) != VINV)
			return rv;

		// Put back things as they were? I think we don't need this.
	}

}


static epoch_t check_umount2(char* path)
{
	struct viewfs_layer *l = searchlayer(path, TRUE);
	if (l)
		return l->tst.epoch;
	else
		return 0;
}

static epoch_t check_open(char *path, int flags, int umpid)
{
	struct viewfs_layer *l = searchlayer(path, FALSE);
	if (!l)
		return 0;

	prepare_testpath(l, path);

	if (flags & O_CREAT)
	{
		
	}
	else
	{
		
	}

	return 0;

}

static epoch_t check_stat64(char *path, struct stat64 *buf, int umpid)
{
	struct viewfs_layer *l = searchlayer(path, FALSE);
	vflag_t flags;
	if (!l)
		return 0;

	prepare_testpath(l, path);
	flags = find_deepest_meta(l->userpath, l->testpath);

	if (flags & VINV)
		return 0;

	if (action_map_stat64[flags])
		return l->tst.epoch;

	return 0;

}

static epoch_t wrap_check_path(char* path)
{
	int sc = um_mod_getsyscallno();
	int umpid = um_mod_getumpid();
	static struct viewfs_layer *layer;
	epoch_t retval = 0;

	GDEBUG(2, "%s(\"%s\", ...)", SYSCALLNAME(sc), path);

	/*
	layer = searchlayer(path, FALSE);
	
	if (layer)
		prepare_testpath(layer, path);
	*/

	switch(sc)
	{
		/*
		case __NR_open:
			checkresult = check_open(path,
					(int)(um_mod_getargs()[1]) | ((scno==__NR_creat) ? 
													  (O_CREAT|O_WRONLY|O_TRUNC) : 0), umpid);
			break;
		
#if ! defined(__x86_64__)
		case __NR_stat64:
		case __NR_lstat64:
#endif
		case __NR_readlink:
		case __NR_access:
		case __NR_chmod:
		case __NR_chown:
		case __NR_lchown:
		case __NR_utime:
		case __NR_utimes:
		case __NR_rmdir:
		case __NR_unlink:
		case __NR_getxattr:
		case __NR_symlink:
			checkresult = check_generic(path, umpid, NO);
			break;
		
		case __NR_chdir:
			checkresult = check_chdir(path, umpid);
			break;

		case __NR_mkdir:
			checkresult = check_mkdir(path, umpid);
			break;

		case __NR_fchdir:
			GDEBUG(1, "*CHECK* fchdir %d", (int)(um_mod_getargs()[1]));
			break;

		default:
			GDEBUG(4, "[FIXME] viewfs support for %s has to be written", SYSCALLNAME(scno));
			prepare_names(path, umpid, VIEWFS_BOTH, NO);
			break;

*/
		case __NR_stat64:
			retval = check_stat64(path, (struct stat64*)(um_mod_getargs()[1]), umpid);
			break;

		case __NR_open:
		case __NR_creat:
			retval = check_open(path, (int)(um_mod_getargs()[1]) |
						((sc == __NR_creat) ? (O_CREAT | O_WRONLY | O_TRUNC) : 0), umpid);
			break;

		case __NR_umount:
		case __NR_umount2:
			retval = check_umount2(path);
			break;

		default:
			GDEBUG(4, "[FIXME] ViewFS does not support %s yet.", SYSCALLNAME(sc));
			break;

	}

	return retval;
}



static epoch_t viewfs_check(int type, void *arg)
{
	epoch_t retval = 0;

	switch(type)
	{
		case CHECKPATH:
			GDEBUG(2, "path check: %s", arg);
			retval = wrap_check_path((char*) arg);
			break;

		case CHECKFSTYPE:
			GDEBUG(2, "fstype check: %s", arg);
			retval = ((strlen((char*) arg) == 6) &&
					(strncmp((char*) arg, "viewfs", 6) == 0));
			break;

		/* Known but useless for viewfs */
		case CHECKSOCKET:
		//case CHECKDEVICE:
		case CHECKSC:
		case CHECKBINFMT:
			break;
		
		default:
			GDEBUG(3, "unknown check type: %d, arg %p", type, arg);
			break;
	}

	GDEBUG(2, " -> %llu", retval);
	return retval;
}



static long viewfs_mount(char *source, char *target, char *filesystemtype,
		unsigned long mountflags, void *data)
{
	struct stat mstat;
	struct viewfs_layer *new;

	GDEBUG(2, "mount %s %s %s %08x %s", source, target, filesystemtype,
			mountflags, (data ? data : "(null)"));

	if (stat(target, &mstat) != 0)
	{
		// errno has been set by stat and is ok
		GDEBUG(2, "return -1 with errno %d", errno);
		return -1;
	}
	else if (!S_ISDIR(mstat.st_mode))
	{
		errno = ENOTDIR;
		GDEBUG(2, "return -1 with errno ENOTDIR");
		return -1;
	}

	new = malloc(sizeof(struct viewfs_layer));

	new->mountpoint = strdup(target);
	new->vfspath = strdup(source);
	
	new->testpath = malloc(2 * PATH_MAX);
	memset(new->testpath, 0, 2 * PATH_MAX);
	strncpy(new->testpath, source, 2 * PATH_MAX);
	new->userpath = &(new->testpath[strlen(source)]);

	GDEBUG(2, "vfspath: ^%s$ testpath: ^%s$",
			new->vfspath, new->testpath);

	new->mountflags = mountflags;
	new->tst = tst_timestamp();

	// TODO: parse options and activate maint mode
	new->maint = 0;
	new->used = 0;
	
	addlayertab(new);

	return 0;
}

static long viewfs_umount2(char *target, int flags)
{
	struct viewfs_layer *layer;

	layer = searchlayer(target, TRUE);
	if (!layer)
	{
		errno = EINVAL;
		return -1;
	}
	else if (layer->used > 0)
	{
		errno = EBUSY;
		return -1;
	}
	else
	{
		dellayertab(layer);
		free(layer->vfspath);
		free(layer->testpath);
		free(layer);
		return 0;
	}
}

static long viewfs_stat64(char *path, struct stat64 *buf, int umpid)
{

	errno = EBADF;
	return -1;
}

static long addproc(int id, int pumpid, int max)
{
	GDEBUG(2, "new process, id: %d, pumpid: %d, max: %d, array size: %d",
			id, pumpid, max, proctabmax);

	if (max > proctabmax)
	{
		proctabmax = (max + TABSTEP) & ~(TABSTEP -1);
		proctab = realloc(proctab, proctabmax * sizeof(struct viewfs_proc *));
	}

	proctab[id] = malloc(sizeof(struct viewfs_proc));

	return 0;
}

static long ctl(int type, va_list ap)
{
	int id, pumpid, max;

	switch(type)
	{
		case MC_PROC | MC_ADD:
			id = va_arg(ap, int);
			pumpid = va_arg(ap, int);
			max = va_arg(ap, int);
			return addproc(id, pumpid, max);
		
		default:
			return -1;
	}
}

static void __attribute__ ((constructor)) init(void)
{
	GDEBUG(2, "ViewFS init");

	s.name = "ViewFS Virtual FS 2";
	s.code = VIEWFS_SERVICE_CODE;
	s.checkfun = viewfs_check;
	s.ctl = ctl;
	s.syscall = (sysfun *) calloc(scmap_scmapsize, sizeof(sysfun));
	s.socket = (sysfun *) calloc(scmap_sockmapsize, sizeof(sysfun));

	SERVICESYSCALL(s, umount2, viewfs_umount2);
	SERVICESYSCALL(s, mount, viewfs_mount);
	SERVICESYSCALL(s, stat64, viewfs_stat64);
	add_service(&s);


	GDEBUG(2, "ViewFS ready");
}
