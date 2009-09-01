/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   ModiFS - Hide file
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
#include "gd64helper.h"
#include "module.h"
#include "libummod.h"
#include "syscallnames.h"

#define TABSTEP 4
#define TABSTEP_1 (TABSTEP - 1)

#define SERVICE_CODE 0x31
#define FS_TYPE "modifshide"

enum slmode { SL_EXACT, SL_PARENT, SL_SUBTREE };

static struct service s;

struct _modifs_layer
{
	char *target;
	char *target_parent;
	char *target_basename;
	unsigned long mountflags;
	struct timestamp tst;
	int used;
};

typedef struct _modifs_layer modifs_layer;

static modifs_layer **layertab = NULL;
static int layertabsize = 0;

struct _dirinfo
{
	dirdata *dd;
	char *path;
	long fd;
};

typedef struct _dirinfo dirinfo;

static dirinfo ***ditab = NULL;
static int *ditabsize = NULL;
static int ditabprocs = 0;

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

static void addlayertab(modifs_layer *new)
{
	int i;
	
	// Search for an empty slot or end of table
	for (i = 0; (i < layertabsize) && layertab[i]; i++);

	if (i >= layertabsize)
	{
		int j;
		int newsize = (i + TABSTEP) & ~TABSTEP_1;
		
		layertab = realloc(layertab, newsize * sizeof(modifs_layer *));
		assert(layertab);

		for (j = i; j < newsize; j++)
			layertab[j] = NULL;
		
		layertabsize = newsize;
	}

	layertab[i] = new;
}

static void dellayertab(modifs_layer *layer)
{
	int i;
	for (i = 0; (i < layertabsize) && (layer != layertab[i]); i++);
	if (i < layertabsize)
		layertab[i] = NULL;
}

static int addditab(int umpid)
{
	int i;

	for (i = 0; i < ditabsize[umpid] && ditab[umpid][i] != NULL; i++);

	GDEBUG(9, "old ditabsize == %d", ditabsize[umpid]);

	if (i >= ditabsize[umpid])
	{
		int j;
	
		ditabsize[umpid] = (i + TABSTEP) & ~TABSTEP_1;
		ditab[umpid] = realloc(ditab[umpid], ditabsize[umpid] * sizeof(dirinfo*));
		assert(ditab[umpid]);

		for (j = i; j < ditabsize[umpid]; j++)
			ditab[umpid][j] = NULL;
	}
	
	GDEBUG(9, "new ditabsize == %d", ditabsize[umpid]);

	ditab[umpid][i] = malloc(sizeof(dirinfo));
	assert(ditab[umpid][i]);
	ditab[umpid][i]->path = NULL;
	ditab[umpid][i]->dd = NULL;
	ditab[umpid][i]->fd = -1;
	return i;
}

static void delditab(int umpid, int i)
{
	dirinfo *tmp = ditab[umpid][i];
	ditab[umpid][i] = NULL;
	free(tmp);
}

static int searchditab(int umpid, int fd)
{
	int i;

	GDEBUG(9, "for (i = 0; i < %d; i++)", ditabsize[umpid]);
	for (i = 0; i < ditabsize[umpid]; i++)
	{
		if (ditab[umpid][i])
		{
			GDEBUG(9, "checking ditab[%d][%d]->fd (%d) against %d", umpid, i, ditab[umpid][i]->fd, fd);
			if (ditab[umpid][i]->fd == fd)
				return i;
		}
	}

	GDEBUG(9, "not found, returning -1");

	return -1;
}

static long addproc(int id)
{
	GDEBUG(9, "addproc %d", id);
	if (id >= ditabprocs)
	{
		ditabprocs = (id + 1 + TABSTEP) & ~TABSTEP_1;
		ditab = realloc(ditab, ditabprocs * sizeof(dirinfo**));
		ditabsize = realloc(ditabsize, ditabprocs * sizeof(int));
	}

	GDEBUG(9, "settind ditabsize[%d] to 0", id);
	ditabsize[id] = 0;
	ditab[id] = malloc(sizeof(dirinfo*));

	return 0;
}

static long delproc(int id)
{
	GDEBUG(9, "delproc %d", id);
	if (id < ditabprocs)
	{
		if (ditab[id])
			free(ditab[id]);
		
		ditab[id] = NULL;
		GDEBUG(9, "setting ditabsize[%d] to -1");
		ditabsize[id] = -1;
	}

	return 0;
}


static modifs_layer *searchlayer(char *path, enum slmode mode)
{
	modifs_layer *result = NULL;
	int bestmatch = -1;
	int i, j;
	epoch_t e, maxe = 0;
	// char oldp;

	if (!path || !path[0])
		return NULL;

	cutdots(path);

	GDEBUG(9, "trying to match path %s, mode == %d", path, mode);


	switch (mode)
	{
		case SL_EXACT:
			for (j = 0; j < layertabsize; j++)
			{
				if (!layertab[j])
					continue;

				GDEBUG(9, " - comparing with %s", layertab[j]->target);
				if ((strcmp(path, layertab[j]->target) == 0) &&
						((e = tst_matchingepoch(&(layertab[j]->tst))) > maxe))
				{
					bestmatch = j;
					maxe = e;
					GDEBUG(9, " + match! bestmatch = %d, maxe = %llu", bestmatch, maxe);
				}
			}
			break;

		case SL_PARENT:
			for (j = 0; j < layertabsize; j++)
			{
				if (!layertab[j])
					continue;

				GDEBUG(9, " - comparing with %s", layertab[j]->target_parent);
				if ((strcmp(path, layertab[j]->target_parent) == 0) &&
						((e = tst_matchingepoch(&(layertab[j]->tst))) > maxe))
				{
					bestmatch = j;
					maxe = e;
					GDEBUG(9, " + match! bestmatch = %d, maxe = %llu", bestmatch, maxe);
				}
			}
			break;

		case SL_SUBTREE:
			for (j = 0; j < layertabsize; j++)
			{
				if (!layertab[j])
					continue;

				GDEBUG(9, " - comparing with %s", layertab[j]->target);

				// Search for longest common subsection starting from 1st char
				i = -1;
				do
				{
					i++;
					if ((path[i] != layertab[j]->target[i]) && layertab[j]->target[i])
						break;

					if (((path[i] == '/') || !path[i]) && (!layertab[j]->target[i]))
					{
						/**** Debug statements */
						// oldp = path[i];
						// path[i] = 0;
						// GDEBUG(9, "   - looking for epoch for match %s", path);
						// path[i] = oldp;
						/**** End of debug statements */

						if ((e = tst_matchingepoch(&(layertab[j]->tst))) > maxe)
						{
							bestmatch = j;
							maxe = e;
							GDEBUG(9, "   + match! bestmatch = %d, maxe = %d", bestmatch, maxe);
						}
					}
				}
				while (path[i] && layertab[j]->target[i]);
			}
			break;
	}


	if (bestmatch < 0)
	{
		GDEBUG(4, "no match found, returning NULL");
		return NULL;
	}

	result = layertab[bestmatch];

	GDEBUG(9, "returning %s", result->target);
	return result;
}

static long modifs_mount(char *source, char *target, char *filesystemtype,
		unsigned long mountflags, void *data)
{
	struct stat mstat;
	modifs_layer *new;
	char *tmp;

	/* source is useless for hiding */

	GDEBUG(9, "mount %s %s %s %08x %s", source, target, filesystemtype,
			mountflags, (data ? data : "(null)"));

	if (stat(target, &mstat) != 0 && (errno != ENOENT))
	{
		// errno has been set by stat and is ok
		GDEBUG(9, "return -1 with errno %d", errno);
		return -1;
	}

	new = malloc(sizeof(modifs_layer));

	new->target = strdup(target);
	new->target_parent = strdup(target);
	new->used = 0;
	tmp = new->target_parent + strlen(new->target_parent); // so *tmp == '\0'

	while (*tmp != '/')
		tmp--;

	new->target_basename = new->target + (tmp - new->target_parent) + 1;

	*tmp = '\0';

	if (strlen(new->target_parent) == 0)
		new->target_parent = NULL;
	
	new->mountflags = mountflags;
	new->tst = tst_timestamp();
	
	GDEBUG(9, "layer initialized with target = '%s' and target_parent = '%s', timestamp is %llu", new->target, new->target_parent, new->tst);
	
	addlayertab(new);

	return 0;
}

static long modifs_umount2(char *target, int flags)
{
	modifs_layer *layer;

	layer = searchlayer(target, SL_EXACT);
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
		free(layer->target);
		free(layer->target_parent);
		free(layer);
		return 0;
	}
}

static epoch_t check_open(char *path, int flags, int umpid)
{
	modifs_layer *layer;
	if ((layer = searchlayer(path, SL_PARENT)))
	{
		GDEBUG(9, "parent found, returning %llu", layer->tst.epoch);
		return layer->tst.epoch;
	}
	else if ((layer = searchlayer(path, SL_SUBTREE)))
	{
		GDEBUG(9, "non-parent found, returning %llu", layer->tst.epoch);
		return layer->tst.epoch;
	}
	else
	{
		GDEBUG(9, "nothing found, returning 0");
		return 0;
	}
}

static epoch_t wrap_check_path(char* path)
{
	int sc = um_mod_getsyscallno();
	int umpid = um_mod_getumpid();
	modifs_layer *layer;
	epoch_t retval = 0;

	GDEBUG(9, "%s(\"%s\", ...)", SYSCALLNAME(sc), path);

	switch(sc)
	{
		case __NR_creat:
		case __NR_open:
			retval = check_open(path,
					(int)(um_mod_getargs()[1]) | ((sc == __NR_creat) ? 
													  (O_CREAT|O_WRONLY|O_TRUNC) : 0), umpid);
			break;
		
		case __NR_stat64:
		case __NR_lstat64:
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
		case __NR_chdir:
		case __NR_mkdir:
			layer = searchlayer(path, SL_SUBTREE);
			if (layer)
				retval = layer->tst.epoch;
			break;

		case __NR_umount:
		case __NR_umount2:
			layer = searchlayer(path, SL_EXACT);
			if (layer)
				retval = layer->tst.epoch;
			break;

		default:
			GDEBUG(4, "[FIXME] ModiFS-Hide does not support %s yet.", SYSCALLNAME(sc));
			break;

	}

	GDEBUG(9, "retval is %llu", retval);

	return retval;
}

static epoch_t modifs_check(int type, void *arg)
{
	epoch_t retval = 0;

	switch(type)
	{
		case CHECKPATH:
			GDEBUG(9, "path check: %s", arg);
			retval = wrap_check_path((char*) arg);
			break;

		case CHECKFSTYPE:
			GDEBUG(9, "fstype check: %s", arg);
			retval = ((strlen((char*) arg) == strlen(FS_TYPE)) &&
					(strncmp((char*) arg, FS_TYPE, strlen(FS_TYPE)) == 0));
			break;
			
		case CHECKSOCKET:
#ifdef CHECKDEVICE
		case CHECKDEVICE:
#endif
		case CHECKSC:
		case CHECKBINFMT:
			break;

		default:
			GDEBUG(9, "unknown check type: %d, arg %p", type, arg);
			break;
	}

	GDEBUG(9, " -> %llu", retval);
	return retval;
}

static long modifs_noent()
{
	GDEBUG(9, "returning enoent");
	errno = ENOENT;
	return -1;
}

static long modifs_rofs()
{
	GDEBUG(9, "returning erofs");
	errno = EROFS;
	return -1;
}

static long modifs_open(char *pathname, int flags, mode_t mode)
{
	modifs_layer *layer;
	int umpid = um_mod_getumpid();
	long i, fd;

	GDEBUG(9, "OPEN");
	if ((layer = searchlayer(pathname, SL_PARENT)))
	{
		fd = open(pathname, flags, mode);
		if (fd > 0)
		{
			i = addditab(umpid);
			ditab[umpid][i]->fd = fd;
			ditab[umpid][i]->path = layer->target_basename;

			GDEBUG(9, "umpid %d called real open(%s) --> %d, stored at position %d", umpid, pathname, fd, i);
		}
		else
			GDEBUG(9, "umpid %d called real open(%s) --> %d, not stored", umpid, pathname, fd);


		return fd;
	}
	else
	{

		GDEBUG(9, "not called real open, returning an error");

		if (flags & O_CREAT)
			errno = EROFS;
		else
			errno = ENOENT;
		return -1;
	}
}

static long modifs_close(int fd)
{
	long rv;
	int umpid = um_mod_getumpid();
	int i = searchditab(umpid, fd);

	GDEBUG(9, "close(%d) gives umpid %d and i %d", fd, umpid, i);
	GBACKTRACE(9, 20);

	assert(i>=0);
	assert(ditab[umpid][i]);

	rv = close(ditab[umpid][i]->fd);

	if (ditab[umpid][i]->dd)
	{
		dirdata_free(ditab[umpid][i]->dd);
		ditab[umpid][i]->dd = NULL;
	}

	ditab[umpid][i]->path = NULL;
	ditab[umpid][i]->fd = -1;

	GDEBUG(9, "delditab");

	delditab(umpid, i);

	return rv;
}

static long ctl(int type, va_list ap)
{
	int id, pumpid, pcbtabsize;

	GDEBUG(9, "ctl %d", type);
	GBACKTRACE(9, 20);

	GDEBUG(9, "proc: %d, module: %d, mount: %d, add: %d, rem: %d",
			MC_PROC, MC_MODULE, MC_MOUNT, MC_ADD, MC_REM);

	switch(type)
	{
		case MC_PROC | MC_ADD:
			GDEBUG(9, "procadd, looking for id from %p", ap);
			id = va_arg(ap, int);
			pumpid = va_arg(ap, int);
			pcbtabsize = va_arg(ap, int);
			GDEBUG(9, "calling addproc(%d)", id);
			return addproc(id);
		
		case MC_PROC | MC_REM:
			GDEBUG(9, "procdel, looking for id from %p", ap);
			id = va_arg(ap, int);
			GDEBUG(9, "calling delproc(%d)", id);
			return delproc(id);
		
		default:
			GDEBUG(9, "unknown ctl, returning -1");
			return -1;
	}
}



static long modifs_getdents64(unsigned int fd, struct dirent64 *dirp, unsigned int count)
{
	int umpid = um_mod_getumpid();
	int di = searchditab(umpid, fd);
	assert(ditab[umpid][di]);

	if (!ditab[umpid][di]->dd)
	{
		ditab[umpid][di]->dd = dirdata_new(DDFULL);
		dirdata_transform_remove(ditab[umpid][di]->dd, ditab[umpid][di]->path);
	}

	return dirdata_getdents64(ditab[umpid][di]->dd, fd, dirp, count);
}

static long modifs_lseek(int fd, off_t offset, int whence)
{
	int umpid = um_mod_getumpid();
	int di = searchditab(umpid, fd);
	assert(ditab[umpid][di]);

	if (!ditab[umpid][di]->dd)
		ditab[umpid][di]->dd = dirdata_new(DDFULL);
	
	return dirdata_lseek(ditab[umpid][di]->dd, fd, offset, NULL, whence);
}

static long modifs__llseek(int fd, unsigned long offset_high, unsigned long offset_low, loff_t *result, unsigned int whence)
{
	int umpid = um_mod_getumpid();
	int di = searchditab(umpid, fd);
	assert(ditab[umpid][di]);

	if (!ditab[umpid][di]->dd)
		ditab[umpid][di]->dd = dirdata_new(DDFULL);
	
	return dirdata_lseek(ditab[umpid][di]->dd, fd, ((unsigned long long)(offset_high) << sizeof(long)) | offset_low, result, whence);
}


static void __attribute__ ((constructor)) init(void)
{
	GDEBUG(9, "modifshide init");

	s.name = "ModiFS Hide";
	s.code = SERVICE_CODE;
	s.checkfun = modifs_check;
	s.ctl = ctl;
	s.syscall = (sysfun *) calloc(scmap_scmapsize, sizeof(sysfun));
	s.socket = (sysfun *) calloc(scmap_sockmapsize, sizeof(sysfun));

	SERVICESYSCALL(s, umount2, modifs_umount2);
	SERVICESYSCALL(s, mount, modifs_mount);
	SERVICESYSCALL(s, stat64, modifs_noent);
	SERVICESYSCALL(s, access, modifs_noent);
	SERVICESYSCALL(s, lstat64, modifs_noent);
	SERVICESYSCALL(s, readlink, modifs_noent);
	SERVICESYSCALL(s, chmod, modifs_noent);
	SERVICESYSCALL(s, chown, modifs_noent);
	SERVICESYSCALL(s, lchown, modifs_noent);
	SERVICESYSCALL(s, utime, modifs_noent);
	SERVICESYSCALL(s, utimes, modifs_noent);
	SERVICESYSCALL(s, rmdir, modifs_noent);
	SERVICESYSCALL(s, unlink, modifs_noent);
	SERVICESYSCALL(s, getxattr, modifs_noent);
	SERVICESYSCALL(s, symlink, modifs_noent);
	SERVICESYSCALL(s, chdir, modifs_noent);
	SERVICESYSCALL(s, mkdir, modifs_rofs);
	SERVICESYSCALL(s, link, modifs_rofs);
	SERVICESYSCALL(s, symlink, modifs_rofs);
	SERVICESYSCALL(s, open, modifs_open);
	SERVICESYSCALL(s, close, modifs_close);
	SERVICESYSCALL(s, getdents64, modifs_getdents64);
	SERVICESYSCALL(s, lseek, modifs_lseek);
	SERVICESYSCALL(s, _llseek, modifs__llseek);
	SERVICESYSCALL(s, fstat64, fstat64);
	SERVICESYSCALL(s, fcntl64, fcntl64);
	add_service(&s);


	GDEBUG(9, "modifshide ready");
}
