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

#define VIEWFS_SERVICE_CODE 0xf5
#define TABSTEP 4

#define TRUE (0 == 0)
#define FALSE (!TRUE)

/*
 * N_{DATA, META, DMETA} must be of the same length (N_LEN)
 * DMETA stays for DIRECTORY META
 */

#define N_DATA  "data/"
#define N_META  "meta/"
#define N_DMETA "dmeta"
#define N_LEN 5
#define T_DATA 0
#define T_META 1

/*
 * Bitmasks:
 *
 *      VNUL 0100 0000
 *      VREM 0000 0001
 *      VADD 0000 0010
 *      VMRG 0000 0100
 *      VMOV 0000 1000
 *      VCOW 0001 0000
 *      VINV 0010 0000
 *
 * VNUL must be OR'ed to every flag before using the result
 * as the argument to symlink(). VINV stays for "invalid" and should
 * never be found on the file system but will be returned by read_flags
 * as an error condition.
 */

#define VNUL 0x40
#define VREM 0x01
#define VADD 0x02
#define VMRG 0x04
#define VMOV 0x08
#define VCOW 0x10
#define VINV 0x20

#define VALL (VNUL | VREM | VADD | VMRG | VMOV | VCOW)

static struct service s;

struct viewfs_proc
{
	

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

static void cutdots(char *path)
{
	int l = strlen(path);
	GDEBUG(2, "original string: %s", path);
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
	GDEBUG(2, "final string:   %s", path);
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
		for (i = strlen(path); (i > 0) && (bestmatch < 0); i--)
		{
			oldp = path[i+1];
			path[i+1] = '\0';
			GDEBUG(2, " - cutting path to %s", path);
			for (j = 0; j < layertabmax; j++)
			{
				if (!layertab[j])
					continue;
				GDEBUG(2, "   - comparing with %s", layertab[j]->mountpoint);
				if ((strcmp(path, layertab[j]->mountpoint) == 0) &&
						((e = tst_matchingepoch(&(layertab[j]->tst))) > maxe))
				{
					bestmatch = j;
					maxe = e;
					GDEBUG(2, "   + match! bestmatch = %d, maxe = %d", bestmatch, maxe);
				}
			}
			path[i+1] = oldp;

			while ((i > 0) && path[i] != '/')
				i--;
		}
	}

	if (bestmatch < 0)
		return NULL;

	result = layertab[bestmatch];

	GDEBUG(2, "returning %s", result->mountpoint);
	return result;
}

static char *extend_path(char *old, char *new, int size, int type)
{
	int oc, nc, lastd;

	int maxlen = size - 1;

	for (oc = 0, nc = 0; old[oc] && nc < maxlen; oc++, nc++)
	{
		new[nc] = old[oc];
		if (new[nc] == '/')
		{
			if ((nc + N_LEN) >= maxlen)
				return NULL;
			
			memcpy(&new[nc + 1], N_DATA, N_LEN);
			lastd = nc + 1;

			nc += N_LEN;
		}
	}

	if (nc > maxlen)
		return NULL;

	new[nc] = '\0';

	if (type == T_META)
	{
		if (new[nc - 1] == '/')
			memcpy(&new[lastd], N_DMETA, N_LEN);
		else
			memcpy(&new[lastd], N_META, N_LEN);
	}

	return new;
}

static void prepare_testpath(struct viewfs_layer *layer, char *path)
{
	assert(strncmp(path, layer->mountpoint, strlen(layer->mountpoint)) == 0);

	char *tmp;
	int delta = strlen(layer->mountpoint);
	if (delta == 1)
		delta--;

	tmp = path + delta;

	extend_path(tmp, layer->userpath, (2 * PATH_MAX) - strlen(layer->vfspath), T_DATA);

	strncpy(layer->userpath, tmp, (2 * PATH_MAX) - strlen(layer->vfspath) - 2);

	GDEBUG(2, "tmp: ^%s$, delta: %d", tmp, delta);
	GDEBUG(2, "userpath: ^%s$", layer->userpath);
	GDEBUG(2, "asked for ^%s$, will check for ^%s$", path, layer->testpath);
}

static unsigned char read_flags(char *path)
{
	char lc;

	if (readlink(path, &lc, 1) != 1)
		return VINV;

	if (lc & ~VALL)
		return VINV;

	lc &= ~VNUL;

	return lc;
}

static char make_flags(unsigned char flags)
{
	return (flags & ~VALL) | VNUL;
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

static epoch_t wrap_check_path(char* path)
{
	int sc = um_mod_getsyscallno();
	int umpid = um_mod_getumpid();
	static struct viewfs_layer *layer;
	epoch_t retval = 0;

	GDEBUG(2, "%s(\"%s\", ...)", SYSCALLNAME(sc), path);

	layer = searchlayer(path, FALSE);
	
	if (layer)
		prepare_testpath(layer, path);

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
			GDEBUG(5, "[FIXME] ViewFS does not support %s yet.", SYSCALLNAME(sc));
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

		default:
			GDEBUG(2, "unknown check type: %d, arg %p", type, arg);
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

static long addproc(int id, int pumpid, int max)
{
	GDEBUG(2, "new process, id: %d, pumpid: %d, max: %d, array size: %d",
			id, pumpid, max, proctabmax);

	if (max > proctabmax)
	{
		proctabmax = (max + TABSTEP) & ~(TABSTEP -1);
		proctab = realloc(layertab, proctabmax * sizeof(struct viewfs_layer *));
	}

	proctab[id] = malloc(sizeof(struct viewfs_layer));

	return 0;
}

static void __attribute__ ((constructor)) init(void)
{
	GDEBUG(2, "ViewFS init");

	s.name = "ViewFS Virtual FS 2";
	s.code = VIEWFS_SERVICE_CODE;
	s.checkfun = viewfs_check;
	s.addproc = addproc;
	s.syscall = (sysfun *) calloc(scmap_scmapsize, sizeof(sysfun));
	s.socket = (sysfun *) calloc(scmap_sockmapsize, sizeof(sysfun));

	SERVICESYSCALL(s, umount2, viewfs_umount2);
	SERVICESYSCALL(s, mount, viewfs_mount);

	add_service(&s);


	GDEBUG(2, "ViewFS ready");
}
