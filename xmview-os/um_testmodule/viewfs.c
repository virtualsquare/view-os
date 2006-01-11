/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   viewfs.
 *   It is possible to remap files and directories
 *   
 *   Copyright 2005 Ludovico Gardenghi
 *   
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 *   $Id$
 *
 */   
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/types.h>
#include <linux/types.h>
#include <sys/stat.h>
#include <string.h>
#include <utime.h>
#include <errno.h>
#include <sys/time.h>
#include <limits.h>
#include <linux/dirent.h>
#include <linux/unistd.h>
#include <stdio.h>
#include <sys/uio.h>

#include "module.h"
#include "libummod.h"
// #include "gdebug.h"
#define GDEBUG(level, fmt...) fprintf(stderr, fmt)
#include "../um-viewos/syscallnames.h"

// #define VIEWFS_ENABLE_REMAP

#define EXISTS(x) ((access((x), F_OK)) == 0)

// #define DAR(x) (GDEBUG(2, "%s:%s:%d return %s\n", __FILE__, __func__, __LINE__, #x),(x))
#define DAR(x) (x)

#define VIEWFS_SERVICE_CODE 0xf5

#define VIEWFS_PREFIX			"/.viewfs"
#define VIEWFS_DEFAULTPERSPATH	"/*"
#define VIEWFS_ADDNAME			"/+"
#define VIEWFS_HIDENAME			"/-"
#define VIEWFS_MAPNAME			"/#"

#define VIEWFS_CURRENT_ADD		0x00000001
#define VIEWFS_CURRENT_HIDE		0x00000002
#define VIEWFS_DEFAULT_ADD		0x00000004
#define VIEWFS_DEFAULT_HIDE		0x00000008
#define VIEWFS_REAL				0x00000010
#define VIEWFS_CURRENT			(VIEWFS_CURRENT_ADD | VIEWFS_CURRENT_HIDE)
#define VIEWFS_DEFAULT			(VIEWFS_DEFAULT_ADD | VIEWFS_DEFAULT_HIDE)
#define VIEWFS_BOTH				(VIEWFS_DEFAULT | VIEWFS_CURRENT)

#define VIEWFS_CHECK_FALSE					0
#define VIEWFS_CHECK_CURRENT_ADD			1
#define VIEWFS_CHECK_CURRENT_HIDE			2
#define VIEWFS_CHECK_DEFAULT_ADD			3
#define VIEWFS_CHECK_DEFAULT_HIDE			4
#define VIEWFS_CHECK_PARENT_CURRENT_ADD		5
#define VIEWFS_CHECK_PARENT_CURRENT_HIDE	6
#define VIEWFS_CHECK_PARENT_DEFAULT_ADD		7
#define VIEWFS_CHECK_PARENT_DEFAULT_HIDE	8

#define VIEWFS_KEEP_FIRST					0
#define VIEWFS_KEEP_SECOND					1

#define VIEWFS_SHALLOW						0
#define VIEWFS_DEEP							1
#define VIEWFS_DEEPONLY						2

#define ISLASTCHECK(x)			(procinfo[umpid].lastcheck == (x))

#define VIEWFS_CRITCHECK(path, retval, deep) {	\
	if (is_critical(path, deep))			\
	{											\
		errno = EACCES;							\
		return (retval);						\
	}											\
}

#ifdef VIEWFS_ENABLE_REMAP
#define REMAP(x) (remap(x))
#else
#define REMAP(x) (x)
#endif

// TODO: make this editable from outside
#define pers_name "test"

struct persdirs
{
	// Start of strings
	char *real;
	char *add;
	char *hide;
	char *map;

	// Pointers to the first char of the "real" path name
	char *addr, *hider, *mapr;
};

struct procinfo_s
{
	fd_set cur;
	fd_set def;
	fd_set gd64;
	int lastcheck;
	struct d64array **gd64_data;
	int gd64_size;
};

static struct procinfo_s *procinfo;
static int procinfo_size;

struct d64array
{
	int fd;
	struct dirent64 **array;
	int size;
	int lastindex;
	struct dirent64 *dirp_orig[5];
};

// User's home directory
static char *homedir;

// viewfs base path
static char *basepath;

// Personalities directories
static struct persdirs *defaultpers, *currentpers;

// Buffers for remap readlink (declared global for speed)
static char *remapbuf;
static char *remaplinkname;

// FIXME: #include "umproc.h" leads to duplicate definitions here
extern char* sfd_getpath(int, int);

static void prepare_names_remap(char *path, int which)
{
	if (which & VIEWFS_DEFAULT)
		strcpy(defaultpers->mapr, path);

	if (which & VIEWFS_CURRENT)
		strcpy(currentpers->mapr, path);
}


#ifdef VIEWFS_ENABLE_REMAP
/* This function uses a statically allocated buffer (remapbuf). This is not
 * thread safe, but is fast and avoids keeping track of mallocs and frees for
 * the buffer. */

#define DAREMAP(x) (GDEBUG(1, "[REMAP] remapping %s -> %s\n", path, (x)), (x))
static char *remap(char *path)
{
	int retval;

	prepare_names_remap(path, VIEWFS_BOTH);

	retval = readlink(currentpers->map, remapbuf, PATH_MAX);
	if (retval >= 0)
	{
		// link found at first attempt
		remapbuf[retval] = '\0';
		return DAREMAP(remapbuf);
	}
	else if (errno == ENOTDIR)
	{
		// we're under a remapping, we must find the leaf
	
		char *curp = currentpers->mapr + 1;
		int stop = 0;
		do
		{
			if (*curp == '/')
			{
				*curp = '\0';
				retval = readlink(currentpers->map, remapbuf, PATH_MAX);
				*curp = '/';
				if (retval >= 0)
					return DAREMAP(remapbuf);
				else if (errno != EINVAL)
					stop = 1;
			}
			else if (curp == '\0')
				stop = 1;

			curp++;
		}
		while (!stop);
	}
	
	retval = readlink(defaultpers->map, remapbuf, PATH_MAX);
	if (retval >= 0)
	{
		remapbuf[retval] = '\0';
		return DAREMAP(remapbuf);
	}
	else if (errno == ENOTDIR)
	{
		// we're under a remapping, we must find the leaf

		char *curp = defaultpers->mapr + 1;
		int stop = 0;
		do
		{
			if (*curp == '/')
			{
				*curp = '\0';
				retval = readlink(defaultpers->map, remapbuf, PATH_MAX);
				*curp = '/';
				if (retval >= 0)
					return DAREMAP(remapbuf);
				else if (errno != EINVAL)
					stop = 1;
			}
			else if (curp == '\0')
				stop = 1;

			curp++;
		}
		while (!stop);
		return path;
	}
	else
		return path;
}
#endif


/* Update all persdirs structure with a given filename to be checked (e.g.
 * "/etc/passwd")
 */
static void prepare_names(char *path, int which)
{
	path = REMAP(path);
	
	if (which & VIEWFS_DEFAULT)
	{
		strcpy(defaultpers->real, path);
		strcpy(defaultpers->addr, path);
		strcpy(defaultpers->hider, path);
		strcpy(defaultpers->mapr, path);
	}

	if (which & VIEWFS_CURRENT)
	{
		strcpy(currentpers->real, path);
		strcpy(currentpers->addr, path);
		strcpy(currentpers->hider, path);
		strcpy(currentpers->mapr, path);
	}
}


/* Allocate, prepare and return a new persdirs struct */
static struct persdirs *newpers()
{
	struct persdirs *tmp = malloc(sizeof(struct persdirs));

	memset(tmp, 0, sizeof(struct persdirs));

	tmp->add = malloc(2*PATH_MAX);
	tmp->hide = malloc(2*PATH_MAX);
	tmp->map = malloc(2*PATH_MAX);
	tmp->real = malloc(PATH_MAX);

	strcpy(tmp->add, basepath);
	strcpy(tmp->hide, basepath);
	strcpy(tmp->map, basepath);
	
	return tmp;
}
/* Free a persdirs structure */
static void freepers(struct persdirs *p)
{
	if (!p)
		return;
	
	free(p->add);
	free(p->hide);
	free(p->map);
	free(p->real);
	free(p);
}

/* Update a persdirs structure with a new basename (i.e. with a new
 * personality name) */
static void update_persdirs(struct persdirs *pd, char *basename)
{
	int startlen = strlen(basepath);
	int bnlen = strlen(basename);
	
	assert(pd);
	assert(basename);

	strcpy(pd->add + startlen, basename);
	strcpy(pd->hide + startlen, basename);
	strcpy(pd->map + startlen, basename);
	
	strcpy(pd->add + startlen + bnlen, VIEWFS_ADDNAME);
	strcpy(pd->hide + startlen + bnlen, VIEWFS_HIDENAME);
	strcpy(pd->map + startlen + bnlen, VIEWFS_MAPNAME);

	pd->addr = pd->add + startlen + bnlen + strlen(VIEWFS_ADDNAME);
	pd->hider = pd->hide + startlen + bnlen + strlen(VIEWFS_HIDENAME);
	pd->mapr = pd->map + startlen + bnlen + strlen(VIEWFS_MAPNAME);
}


/* Change the current personality, updating structures as needed */
static void setpers(char *persname)
{
	char *tmp = malloc(strlen(persname) + 2);
	
	tmp[0]='/';
	strcpy(&tmp[1], persname);
	
	update_persdirs(currentpers, tmp);
}

/* Initialization routine. Checks home directory name and prepares
 * structures and variables. */
static void prepare()
{
	homedir = getenv("HOME");
	basepath = malloc(strlen(homedir) + strlen(VIEWFS_PREFIX) + 1);
	strcpy(basepath, homedir);
	strcpy(basepath + strlen(homedir), VIEWFS_PREFIX);
	defaultpers = newpers();
	currentpers = newpers();

	update_persdirs(defaultpers, VIEWFS_DEFAULTPERSPATH);
	setpers(pers_name);

	procinfo = NULL;
	procinfo_size = 0;

	remapbuf = malloc(PATH_MAX + 1);
	remaplinkname = malloc(2*PATH_MAX + 1);

	GDEBUG(2, "base path: %s\n", basepath);
	GDEBUG(2, "default pers add dir: %s\n", defaultpers->add);
	GDEBUG(2, "current pers add dir: %s\n", currentpers->add);
}

static void dispose()
{
	free(basepath);

	freepers(currentpers);
	freepers(defaultpers);

	free(remapbuf);
	free(remaplinkname);
}

static void procinfo_fd_set(int id, int fd, int pers)
{
	GDEBUG(2, "procinfo_fd_set id %d, fd %d, pers %d\n", id, fd, pers);
	if (pers & VIEWFS_CURRENT)
		FD_SET(fd, &procinfo[id].cur);
	if (pers & VIEWFS_DEFAULT)
		FD_SET(fd, &procinfo[id].def);
	GDEBUG(2, "procinfo_fd_set end\n");
}

static void procinfo_fd_clear(int id, int fd, int pers)
{
	GDEBUG(2, "procinfo_fd_clear id %d, fd %d, pers %d\n", id, fd, pers);
	if (pers & VIEWFS_CURRENT)
		FD_CLR(fd, &procinfo[id].cur);
	if (pers & VIEWFS_DEFAULT)
		FD_CLR(fd, &procinfo[id].def);
	GDEBUG(2, "procinfo_fd_clear end\n");
}

static int addproc(int id, int max, void *umph)
{
	// FIXME: is "max" the MAXIMUM value of the umpid or is it the size of
	// the umpid table? umpids start from 0, so the value depends on this
	// difference. Please specify it or rename the variable.
	if (max > procinfo_size)
	{
		procinfo = realloc(procinfo, max * sizeof(struct procinfo_s *));
		procinfo_size = max;
	}

	FD_ZERO(&procinfo[id].cur);
	FD_ZERO(&procinfo[id].gd64);
	FD_ZERO(&procinfo[id].def);

	procinfo[id].gd64_data = NULL;
	procinfo[id].gd64_size = 0;

	return 0;
}

static int delproc(int id, void *umph)
{
	FD_ZERO(&procinfo[id].cur);
	FD_ZERO(&procinfo[id].def);
	FD_ZERO(&procinfo[id].gd64);

	if (procinfo[id].gd64_data)
		free(procinfo[id].gd64_data);

	return 0;
}

/* Return 1 if the given path is at or under the ~/.viewfs directory.
 * If "deep" is set to VIEWFS_SHALLOW, return 1 only if the given
 * path is EQUAL to ~/.viewfs. If "deep" is set to VIEWFS_SHALLOW,
 * return 1 only if the given path is UNDER ~/.viewfs, but return 0
 * if it is equal to ~/.viewfs. */
inline static int is_critical(char *path, int deep)
{
	if (deep == VIEWFS_DEEP)
		return (strncmp(basepath, path, strlen(basepath)) == 0);
	else if (deep == VIEWFS_SHALLOW)
		return (strcmp(basepath, path) == 0);
	else // deep == VIEWFS_DEEPONLY
		return (is_critical(path, VIEWFS_DEEP) && 
				!is_critical(path, VIEWFS_SHALLOW));
}


/*
 * Return values:
 * >0          empty directory
 * 0           not empty directory
 * <0          error
 */
static int is_directory_empty(char *dirname)
{
	int retval;
	int fd;
	int dirp_size = 3 * sizeof(struct dirent);
	struct dirent *dirp = malloc(dirp_size);

	fd = open(dirname, O_DIRECTORY);
	if (fd < 0)
	{
		free(dirp);
		GDEBUG(1, "%s is ERROR during open\n", dirname);
		return -1;
	}

	/* A directory is empty if and only if it contains only 2 files: . and ..
	 * (unless it's a very broken directory, in that case it's an error) */
	
	retval = getdents(fd, dirp, dirp_size);

	close(fd);

	if (retval <= 0) // It could not be MORE EMPTY than this :-)
	{
		free(dirp);
		GDEBUG(1, "%s is ERROR\n", dirname);
		return -1;
	}

	if ((dirp->d_reclen < retval) && ((((struct dirent*)((char*)dirp + dirp->d_reclen))->d_reclen) + dirp->d_reclen == retval))
	{
		free(dirp);
		GDEBUG(1, "%s is empty\n", dirname);
		return 1;
	}
	else
	{
		free(dirp);
		GDEBUG(1, "%s is NOT empty\n", dirname);
		return 0;
	}
}

static int check_generic(char *path, int umpid)
{
	prepare_names(path, VIEWFS_BOTH);

	if (path[1] == 0)
	{
		procinfo[umpid].lastcheck = VIEWFS_CHECK_FALSE;
		return 0;
	}

	if (EXISTS(currentpers->add) || (errno != ENOENT))
	{
		procinfo[umpid].lastcheck = VIEWFS_CHECK_CURRENT_ADD;
		return 1;
	}

	if (EXISTS(currentpers->hide) || (errno == EACCES))
	{
		procinfo[umpid].lastcheck = VIEWFS_CHECK_CURRENT_HIDE;
		return 1;
	}
	
	if (EXISTS(defaultpers->add) || (errno != ENOENT))
	{
		procinfo[umpid].lastcheck = VIEWFS_CHECK_DEFAULT_ADD;
		return 1;
	}
	
	if (EXISTS(defaultpers->hide) || (errno == EACCES))
	{
		procinfo[umpid].lastcheck = VIEWFS_CHECK_DEFAULT_HIDE;
		return 1;
	}

	procinfo[umpid].lastcheck = VIEWFS_CHECK_FALSE;
	return 0;
}

static int check_open(char *path, int flags, int umpid)
{
	if ((flags & O_CREAT) && (!EXISTS(path)))
	{
		check_generic(path, umpid);
		return 1;
	}
	else
		return check_generic(path, umpid);
}


static int check_mkdir(char *path, int umpid)
{
	char *lastslash = strrchr(path, '/');
	int retval = 0;

	procinfo[umpid].lastcheck = VIEWFS_CHECK_FALSE;

	if (!lastslash) // No '/' in the string? Strange.
	{
		return 0;
	}

	/* Truncate the path to the parent of the given path */
	*lastslash = '\0';
	prepare_names(path, VIEWFS_BOTH);

	if (EXISTS(currentpers->add) || (errno != ENOENT))
	{
		procinfo[umpid].lastcheck = VIEWFS_CHECK_PARENT_CURRENT_ADD;
		retval = 1;
	}
	else if (EXISTS(currentpers->hide) || (errno == EACCES))
	{
		procinfo[umpid].lastcheck = VIEWFS_CHECK_PARENT_CURRENT_HIDE;
		retval = 1;
	}
	else if (EXISTS(defaultpers->add) || (errno != ENOENT))
	{
		procinfo[umpid].lastcheck = VIEWFS_CHECK_PARENT_DEFAULT_ADD;
		retval = 1;
	}
	else if (EXISTS(defaultpers->hide) || (errno == EACCES))
	{
		procinfo[umpid].lastcheck = VIEWFS_CHECK_PARENT_DEFAULT_HIDE;
		retval = 1;
	}

	/* Put the / back where it was */
	*lastslash = '/';
	prepare_names(path, VIEWFS_BOTH);

	return retval;
}

static int viewfs_open(char *pathname, int flags, mode_t mode, void *umph)
{
	int retval;
	int umpid = um_mod_getumpid(umph);

	VIEWFS_CRITCHECK(pathname, -1, VIEWFS_DEEP);
	
	if (ISLASTCHECK(VIEWFS_CHECK_CURRENT_ADD))
	{
		retval = DAR(open(currentpers->add, flags, mode));
		if (retval >= 0)
			procinfo_fd_set(umpid, retval, VIEWFS_CURRENT);
		return retval;
	}

	if (ISLASTCHECK(VIEWFS_CHECK_CURRENT_HIDE))
	{
		if (flags & O_CREAT)
		{
			retval = DAR(open(currentpers->add, flags, mode));
			if (retval >= 0)
				procinfo_fd_set(umpid, retval, VIEWFS_CURRENT);
			return retval;
		}
		else
		{
			errno = ENOENT;
			return DAR(-1);
		}
	}

	if (ISLASTCHECK(VIEWFS_CHECK_DEFAULT_ADD))
	{
		retval = DAR(open(defaultpers->add, flags, mode));
		if (retval >= 0)
			procinfo_fd_set(umpid, retval, VIEWFS_DEFAULT);
		return retval;
	}

	if (ISLASTCHECK(VIEWFS_CHECK_DEFAULT_HIDE))
	{
		if (flags & O_CREAT)
		{
			retval = DAR(open(currentpers->add, flags, mode));
			if (retval >= 0)
				procinfo_fd_set(umpid, retval, VIEWFS_CURRENT);
			return retval;
		}
		else
		{
			errno = ENOENT;
			return DAR(-1);
		}
	}

	retval = DAR(open(pathname, flags, mode));
	if (retval >= 0)
		procinfo_fd_clear(umpid, retval, VIEWFS_BOTH);
	else if (flags & O_CREAT)
	{
		int retval2 = DAR(open(currentpers->add, flags, mode));
		if (retval2 >= 0)
			procinfo_fd_set(umpid, retval2, VIEWFS_CURRENT);
		else
			return retval2;
	}
	
	return retval;
}

static void clear_cachedata(struct d64array *data, int deep)
{
	int i;

	GDEBUG(1, "clearing cache data for fd %d\n", data->fd);

	if (deep == VIEWFS_DEEP)
		for (i = 0; i < 5; i++)
			if (data->dirp_orig[i])
			{
				GDEBUG(1, "clearing original dirp pos %d\n", i);
				free(data->dirp_orig[i]);
			}
	

	GDEBUG(1, "clearing data->array\n");
	free(data->array);

	GDEBUG(1, "clearing data\n");
	free(data);

	return;
}

static int viewfs_close(int fd, void *umph)
{
	int retval = DAR(close(fd));
	int umpid;
	int i;

	// FIXME: this check is a hack I made because
	// viewfs_close is called 2 times
	if (retval == 0)
	{
		umpid = um_mod_getumpid(umph);
		if (FD_ISSET(fd, &procinfo[umpid].gd64))
		{
			FD_CLR(fd, &procinfo[umpid].gd64);
			for (i = 0; i < procinfo[umpid].gd64_size; i++)
				if (procinfo[umpid].gd64_data[i] &&
						(procinfo[umpid].gd64_data[i]->fd == fd))
				{
					clear_cachedata(procinfo[umpid].gd64_data[i], VIEWFS_DEEP);
					procinfo[umpid].gd64_data[i] = NULL;
					break;
				}
		}
	}
	
	return retval;
}

static int viewfs_stat(char *pathname, struct stat *buf, void *umph)
{
	int umpid = um_mod_getumpid(umph);

	VIEWFS_CRITCHECK(pathname, -1, VIEWFS_DEEPONLY);

	if (ISLASTCHECK(VIEWFS_CHECK_CURRENT_ADD))
		return DAR(stat(currentpers->add, buf));

	if (ISLASTCHECK(VIEWFS_CHECK_CURRENT_HIDE))
	{
		errno = ENOENT;
		return DAR(-1);
	}
	
	if (ISLASTCHECK(VIEWFS_CHECK_DEFAULT_ADD))
		return DAR(stat(defaultpers->add, buf));

	if (ISLASTCHECK(VIEWFS_CHECK_DEFAULT_HIDE))
	{
		errno = ENOENT;
		return DAR(-1);
	}

	return DAR(stat(pathname, buf));
}

static int viewfs_lstat(char *pathname, struct stat *buf, void *umph)
{
	int umpid = um_mod_getumpid(umph);

	VIEWFS_CRITCHECK(pathname, -1, VIEWFS_DEEPONLY);

	if (ISLASTCHECK(VIEWFS_CHECK_CURRENT_ADD))
		return DAR(lstat(currentpers->add, buf));

	if (ISLASTCHECK(VIEWFS_CHECK_CURRENT_HIDE))
	{
		errno = ENOENT;
		return DAR(-1);
	}
	
	if (ISLASTCHECK(VIEWFS_CHECK_DEFAULT_ADD))
		return DAR(lstat(defaultpers->add, buf));

	if (ISLASTCHECK(VIEWFS_CHECK_DEFAULT_HIDE))
	{
		errno = ENOENT;
		return DAR(-1);
	}

	return DAR(lstat(pathname, buf));
}

static int viewfs_stat64(char *pathname, struct stat64 *buf, void *umph)
{
	int umpid = um_mod_getumpid(umph);
	
	VIEWFS_CRITCHECK(pathname, -1, VIEWFS_DEEPONLY);

	if (ISLASTCHECK(VIEWFS_CHECK_CURRENT_ADD))
		return DAR(stat64(currentpers->add, buf));

	if (ISLASTCHECK(VIEWFS_CHECK_CURRENT_HIDE))
	{
		errno = ENOENT;
		return DAR(-1);
	}
	
	if (ISLASTCHECK(VIEWFS_CHECK_DEFAULT_ADD))
		return DAR(stat64(defaultpers->add, buf));

	if (ISLASTCHECK(VIEWFS_CHECK_DEFAULT_HIDE))
	{
		errno = ENOENT;
		return DAR(-1);
	}

	return DAR(stat64(pathname, buf));
}

static int viewfs_lstat64(char *pathname, struct stat64 *buf, void *umph)
{
	int umpid = um_mod_getumpid(umph);
	
	VIEWFS_CRITCHECK(pathname, -1, VIEWFS_DEEPONLY);

	if (ISLASTCHECK(VIEWFS_CHECK_CURRENT_ADD))
		return DAR(lstat64(currentpers->add, buf));

	if (ISLASTCHECK(VIEWFS_CHECK_CURRENT_HIDE))
	{
		errno = ENOENT;
		return DAR(-1);
	}
	
	if (ISLASTCHECK(VIEWFS_CHECK_DEFAULT_ADD))
		return DAR(lstat64(defaultpers->add, buf));

	if (ISLASTCHECK(VIEWFS_CHECK_DEFAULT_HIDE))
	{
		errno = ENOENT;
		return DAR(-1);
	}

	return DAR(lstat64(pathname, buf));
}

static int viewfs_readlink(char *path, char *buf, size_t bufsiz, void *umph)
{
	int umpid = um_mod_getumpid(umph);
	
	VIEWFS_CRITCHECK(path, -1, VIEWFS_DEEP);

	if (ISLASTCHECK(VIEWFS_CHECK_CURRENT_ADD))
		return DAR(readlink(currentpers->add, buf, bufsiz));

	if (ISLASTCHECK(VIEWFS_CHECK_CURRENT_HIDE))
	{
		errno = ENOENT;
		return DAR(-1);
	}
	
	if (ISLASTCHECK(VIEWFS_CHECK_DEFAULT_ADD))
		return DAR(readlink(defaultpers->add, buf, bufsiz));

	if (ISLASTCHECK(VIEWFS_CHECK_DEFAULT_HIDE))
	{
		errno = ENOENT;
		return DAR(-1);
	}

	return DAR(readlink(path, buf, bufsiz));
}

static int viewfs_access(char *path, int mode, void *umph)
{
	int umpid = um_mod_getumpid(umph);
	
	VIEWFS_CRITCHECK(path, -1, VIEWFS_DEEP);

	if (ISLASTCHECK(VIEWFS_CHECK_CURRENT_ADD))
		return DAR(access(currentpers->add, mode));

	if (ISLASTCHECK(VIEWFS_CHECK_CURRENT_HIDE))
	{
		errno = ENOENT;
		return DAR(-1);
	}
	
	if (ISLASTCHECK(VIEWFS_CHECK_DEFAULT_ADD))
		return DAR(access(defaultpers->add, mode));

	if (ISLASTCHECK(VIEWFS_CHECK_DEFAULT_HIDE))
	{
		errno = ENOENT;
		return DAR(-1);
	}

	return DAR(access(path, mode));
}

static int viewfs_mkdir(char *path, int mode, void *umph)
{
	int retval;
	int umpid = um_mod_getumpid(umph);
	
	
	VIEWFS_CRITCHECK(path, -1, VIEWFS_DEEP);

	if (ISLASTCHECK(VIEWFS_CHECK_PARENT_CURRENT_ADD))
	{
		//char *lastslash = strrchr(currentpers->add, '/');
		//assert(lastslash);
		//*lastslash = '\0';
		retval = DAR(mkdir(currentpers->add, mode));
		//*lastslash = '/';
		return retval;
	}
	if (ISLASTCHECK(VIEWFS_CHECK_PARENT_CURRENT_HIDE))
	{
		errno = ENOENT;
		return DAR(-1);
	}
	if (ISLASTCHECK(VIEWFS_CHECK_PARENT_DEFAULT_ADD))
	{
		//char *lastslash = strrchr(defaultpers->add, '/');
		//assert(lastslash);
		//*lastslash = '\0';
		retval = DAR(mkdir(defaultpers->add, mode));
		//*lastslash = '/';
		//return retval;
	}
	if (ISLASTCHECK(VIEWFS_CHECK_PARENT_CURRENT_ADD))
	{
		errno = ENOENT;
		return DAR(-1);
	}
	
	return DAR(mkdir(path,mode));
}

static int viewfs_rmdir(char *path, void *umph)
{
	int umpid = um_mod_getumpid(umph);

	
	VIEWFS_CRITCHECK(path, -1, VIEWFS_DEEP);

	if (ISLASTCHECK(VIEWFS_CHECK_CURRENT_ADD))
	{
		if (EXISTS(currentpers->hide))
			return DAR(rmdir(currentpers->add));
		else if (!is_directory_empty(currentpers->add))
			return DAR(rmdir(currentpers->add));
		else if (!EXISTS(defaultpers->add))
		{
			if (EXISTS(defaultpers->hide))
				return DAR(rmdir(currentpers->add));
			else
			{
				int retval = rmdir(path);
				if (!retval || (errno == ENOENT))
					return DAR(rmdir(currentpers->add));
				else
					return DAR(retval);
			}
		}
		else if (!is_directory_empty(defaultpers->add))
		{
			errno = ENOTEMPTY;
			return DAR(-1);
		}
		else
		{
			if (EXISTS(defaultpers->hide))
			{
				int retval = rmdir(currentpers->add);
				if (!retval) // Success
					return DAR(rmdir(defaultpers->add));
				else
					return retval;
			}
			else
			{
				int retval = rmdir(path);
				if (!retval || (errno == ENOENT)) // Success
					return DAR(rmdir(currentpers->add) && (rmdir(defaultpers->add)));
				else
					return retval;
			}
		}
	}
	else if (ISLASTCHECK(VIEWFS_CHECK_CURRENT_HIDE))
	{
		errno = ENOENT;
		return -1;
	}
	else if (!EXISTS(defaultpers->add))
	{
		if (EXISTS(defaultpers->hide))
		{
			errno = ENOENT;
			return -1;
		}
		else
			return DAR(rmdir(path));
	}
	else if (EXISTS(defaultpers->hide))
		return DAR(rmdir(defaultpers->add));
	else if (!is_directory_empty(defaultpers->add))
	{
		errno = ENOTEMPTY;
		return -1;
	}
	else
	{
		int retval = rmdir(path);
		if (!retval || (errno == ENOENT)) // Success
			return DAR(rmdir(defaultpers->add));
		else
			return retval;
	}
}

static int viewfs_chdir(char *path, void *umph)
{
	int umpid = um_mod_getumpid(umph);
	
	VIEWFS_CRITCHECK(path, -1, VIEWFS_DEEP);

	if (ISLASTCHECK(VIEWFS_CHECK_CURRENT_ADD))
		return DAR(chdir(currentpers->add));

	if (ISLASTCHECK(VIEWFS_CHECK_CURRENT_HIDE))
	{
		errno = ENOENT;
		return DAR(-1);
	}
	
	if (ISLASTCHECK(VIEWFS_CHECK_DEFAULT_ADD))
		return DAR(chdir(defaultpers->add));

	if (ISLASTCHECK(VIEWFS_CHECK_DEFAULT_HIDE))
	{
		errno = ENOENT;
		return DAR(-1);
	}

	return DAR(chdir(path));
}

static int viewfs_chmod(char *path, int mode, void *umph)
{
	int umpid = um_mod_getumpid(umph);
	
	VIEWFS_CRITCHECK(path, -1, VIEWFS_DEEP);

	if (ISLASTCHECK(VIEWFS_CHECK_CURRENT_ADD))
		return DAR(chmod(currentpers->add, mode));

	if (ISLASTCHECK(VIEWFS_CHECK_CURRENT_HIDE))
	{
		errno = ENOENT;
		return DAR(-1);
	}
	
	if (ISLASTCHECK(VIEWFS_CHECK_DEFAULT_ADD))
		return DAR(chmod(defaultpers->add, mode));

	if (ISLASTCHECK(VIEWFS_CHECK_DEFAULT_HIDE))
	{
		errno = ENOENT;
		return DAR(-1);
	}

	return DAR(chmod(path, mode));
}

static int viewfs_chown(char *path, uid_t owner, gid_t group, void *umph)
{
	int umpid = um_mod_getumpid(umph);
	
	VIEWFS_CRITCHECK(path, -1, VIEWFS_DEEP);

	if (ISLASTCHECK(VIEWFS_CHECK_CURRENT_ADD))
		return DAR(chown(currentpers->add, owner, group));

	if (ISLASTCHECK(VIEWFS_CHECK_CURRENT_HIDE))
	{
		errno = ENOENT;
		return DAR(-1);
	}
	
	if (ISLASTCHECK(VIEWFS_CHECK_DEFAULT_ADD))
		return DAR(chown(defaultpers->add, owner, group));

	if (ISLASTCHECK(VIEWFS_CHECK_DEFAULT_HIDE))
	{
		errno = ENOENT;
		return DAR(-1);
	}

	return DAR(chown(path, owner, group));
}

static int viewfs_lchown(char *path, uid_t owner, gid_t group, void *umph)
{
	int umpid = um_mod_getumpid(umph);
	
	VIEWFS_CRITCHECK(path, -1, VIEWFS_DEEP);

	if (ISLASTCHECK(VIEWFS_CHECK_CURRENT_ADD))
		return DAR(lchown(currentpers->add, owner, group));

	if (ISLASTCHECK(VIEWFS_CHECK_CURRENT_HIDE))
	{
		errno = ENOENT;
		return DAR(-1);
	}
	
	if (ISLASTCHECK(VIEWFS_CHECK_DEFAULT_ADD))
		return DAR(lchown(defaultpers->add, owner, group));

	if (ISLASTCHECK(VIEWFS_CHECK_DEFAULT_HIDE))
	{
		errno = ENOENT;
		return DAR(-1);
	}

	return DAR(lchown(path, owner, group));
}

/* Some of the conditions managed by this function should never happen. If
 * they happen, it is because someone directly modified one of the ~/.viewfs/
 * files. The behavior is not well defined and not consistent with the viewfs
 * semantic.
 * A really complete implementation should make some of the following unlinks
 * atomic, un-doing some of them if some of the following ones fail. However,
 * this should not happen during normal operations.
 */
static int viewfs_unlink(char *path, void *umph)
{
	int umpid = um_mod_getumpid(umph);

	VIEWFS_CRITCHECK(path, -1, VIEWFS_DEEP);


	if (ISLASTCHECK(VIEWFS_CHECK_CURRENT_ADD))
	{
		if (EXISTS(currentpers->hide))
			return DAR(unlink(currentpers->add));
		else if EXISTS(defaultpers->hide)
		{
			int retval = unlink(defaultpers->add);
			if (!retval || (errno == ENOENT))
				return DAR(unlink(currentpers->add));
			else
				return retval;
		}
		else
		{
			int retval = unlink(path);
			if (!retval || (errno == ENOENT)) // Success (real file existed)
			{
				int retval2 = unlink(defaultpers->add);
				if (!retval2 || (errno == ENOENT)) // Success (*+ file existed)
					return DAR(unlink(currentpers->add));
				else
					return retval2;
			}
			else
				return retval;
		}
	}
	else if (ISLASTCHECK(VIEWFS_CHECK_CURRENT_HIDE))
	{
		errno = ENOENT;
		return -1;
	}
	else if (EXISTS(defaultpers->hide))
		return DAR(unlink(defaultpers->add));
	else if (EXISTS(defaultpers->add))
	{
		int retval = unlink(path);
		if (!retval || errno == ENOENT)
			return DAR(unlink(defaultpers->add));
		else
			return retval;
	}
	else
		return DAR(unlink(path));
}

static int viewfs_link(char *oldpath, char *newpath, void *umph)
{
	
	VIEWFS_CRITCHECK(oldpath, -1, VIEWFS_DEEP);
	VIEWFS_CRITCHECK(newpath, -1, VIEWFS_DEEP);

	return -1;
}

static int viewfs_symlink(char *oldpath, char *newpath, void *umph)
{
	int umpid = um_mod_getumpid(umph);

	VIEWFS_CRITCHECK(oldpath, -1, VIEWFS_DEEP);
	VIEWFS_CRITCHECK(newpath, -1, VIEWFS_DEEP);

	if (ISLASTCHECK(VIEWFS_CHECK_CURRENT_ADD))
		return DAR(symlink(oldpath, currentpers->add));
	else if (ISLASTCHECK(VIEWFS_CHECK_CURRENT_HIDE))
		return DAR(symlink(oldpath, currentpers->add));
	else if (ISLASTCHECK(VIEWFS_CHECK_DEFAULT_ADD))
		return DAR(symlink(oldpath, defaultpers->add));
	else if (ISLASTCHECK(VIEWFS_CHECK_DEFAULT_HIDE))
		return DAR(symlink(oldpath, currentpers->add));
	else
		return DAR(symlink(oldpath, newpath));
}

static int viewfs_utime(char *filename, struct utimbuf *buf, void *umph)
{
	int umpid = um_mod_getumpid(umph);

	VIEWFS_CRITCHECK(filename, -1, VIEWFS_DEEP);

	if (ISLASTCHECK(VIEWFS_CHECK_CURRENT_ADD))
		return DAR(utime(currentpers->add, buf));

	if (ISLASTCHECK(VIEWFS_CHECK_CURRENT_HIDE))
	{
		errno = ENOENT;
		return DAR(-1);
	}
	
	if (ISLASTCHECK(VIEWFS_CHECK_DEFAULT_ADD))
		return DAR(utime(defaultpers->add, buf));

	if (ISLASTCHECK(VIEWFS_CHECK_DEFAULT_HIDE))
	{
		errno = ENOENT;
		return DAR(-1);
	}

	return DAR(utime(filename, buf));
}

static int viewfs_utimes(char *filename, struct timeval tv[2], void *umph)
{
	int umpid = um_mod_getumpid(umph);

	VIEWFS_CRITCHECK(filename, -1, VIEWFS_DEEP);

	if (ISLASTCHECK(VIEWFS_CHECK_CURRENT_ADD))
		return DAR(utimes(currentpers->add, tv));

	if (ISLASTCHECK(VIEWFS_CHECK_CURRENT_HIDE))
	{
		errno = ENOENT;
		return DAR(-1);
	}
	
	if (ISLASTCHECK(VIEWFS_CHECK_DEFAULT_ADD))
		return DAR(utimes(defaultpers->add, tv));

	if (ISLASTCHECK(VIEWFS_CHECK_DEFAULT_HIDE))
	{
		errno = ENOENT;
		return DAR(-1);
	}

	return DAR(utimes(filename, tv));
}

ssize_t viewfs_pread(int fd, void *buf, size_t count, long long offset)
{
	off_t off=offset;
	return DAR(pread(fd,buf,count,off));
}

ssize_t viewfs_pwrite(int fd, const void *buf, size_t count, long long offset)
{
	off_t off=offset;
	return DAR(pwrite(fd,buf,count,off));
}

static int viewfs_getdents(unsigned int fd, struct dirent *dirp, unsigned int count, void *umph)
{
	GDEBUG(1,"getdents!\n");
	int umpid = um_mod_getumpid(umph);
	
	if (FD_ISSET(fd, &procinfo[umpid].cur))
		GDEBUG(1, "fd %d is open in current personality\n", fd);
	if (FD_ISSET(fd, &procinfo[umpid].def))
		GDEBUG(1, "fd %d is open in default personality\n", fd);
	
	return 0;
}

static int getdents64_whole_dir(char *path, struct dirent64 **buf, int bufsize)
{
	struct dirent64 *alldents;
	int alldents_size;
	struct dirent64 *tmp;
	int gdretval;
	int fd = open(path, O_RDONLY);
	
	if (fd < 0)
		return -1;

	alldents = NULL;
	alldents_size = 0;
	gdretval = bufsize;
	
	do
	{
		alldents_size += gdretval;
		alldents = realloc(alldents, alldents_size);
		tmp = (struct dirent64*)(((char*)alldents) + alldents_size - bufsize);
		
		gdretval = getdents64(fd, tmp, bufsize);
	}
	while (gdretval > 0);

	close(fd);

	if (gdretval < 0)
	{
		if (errno == EINVAL)
			GDEBUG(1, "Buffer for getdents_whole_dir is too small. This is a bug.");
		free(alldents);
		return -1;
	}

	*buf = alldents;

	return (alldents_size - bufsize);
}

static struct d64array *dirent64_to_d64array(struct dirent64 *dirp, int count, int fd)
{
	struct dirent64 *tmp;
	struct d64array *retval;
	int curcount = 0;
	int elems = 0;
	int i = 0;
	
	if (count == 0)
		return NULL;

	retval = malloc(sizeof(struct d64array));

	// First pass: count the number of elements of dirp (sigh)
	tmp = dirp;
	
	do
	{
		elems++;
		curcount += tmp->d_reclen;
		tmp = (struct dirent64*)(((char*)tmp) + tmp->d_reclen);
	}
	while (curcount < count);

	GDEBUG(1, "there are %d elements in the struct dirent\n", elems);

	// Allocate a pointer array
	retval->array = malloc(elems * sizeof(struct dirent64*));

	// Second pass: populate the array
	tmp = dirp;
	curcount = 0;

	for (i = 0; i < elems; i++)
	{
		retval->array[i] = tmp;
		tmp = (struct dirent64*)(((char*)tmp) + tmp->d_reclen);
	}

	retval->fd = fd;
	retval->size = elems;

	return retval;
}

static int dirent64_compare(const void *d1, const void *d2)
{
	
	struct dirent64 **dirpp1 = (struct dirent64**) d1;
	struct dirent64 **dirpp2 = (struct dirent64**) d2;

	return strcoll((*dirpp1)->d_name, (*dirpp2)->d_name);
}

static void sort_array64(struct d64array *array)
{
	qsort(array->array, array->size, sizeof(struct dirent64*), dirent64_compare);
}

static int getdents64_cached(struct d64array *data, struct dirent64 *dirp, unsigned int count)
{
	int curcount = 0;
	char *curp;
	int dentsize;

	// We're already at the end of the directory -> getdents returns 0
	if (data->lastindex == data->size)
	{
		GDEBUG(1, "end of directory!\n");
		return 0;
	}

	if (!dirp)
	{
		errno = EFAULT;
		return -1;
	}

	curp = (char*) dirp;
	
	for (; data->lastindex < data->size; data->lastindex++)
	{
		dentsize = data->array[data->lastindex]->d_reclen;
		if ((curcount + dentsize) > count)
		{
			GDEBUG(1, "end of buffer!");
			break;
		}

		curcount += dentsize;
		memcpy(curp, data->array[data->lastindex], dentsize);
		GDEBUG(1, "added info for %s\n", ((struct dirent64 *)curp)->d_name);
		curp += dentsize;
	}

	GDEBUG(1, "curcount: %d, count: %d, lastindex: %d, size: %d\n", curcount, count, data->lastindex, data->size);

	// If no dirents have been copied in dirp, the buffer is too small
	if (curcount == 0)
	{
		errno = EINVAL;
		return -1;
	}

	return curcount;

}

static struct d64array *d64array_merge(struct d64array *a1, struct d64array *a2, int keep)
{
	struct d64array* retval;
	int i, c1, c2, d, compare;

	retval = malloc(sizeof(struct d64array));

	// Probably too much, overlapping files count as 1. But here no
	// assumptions can be made.
	retval->array = malloc((a1->size + a2->size) * sizeof(struct dirent64*));
	retval->fd = a1->fd;
	retval->lastindex = 0;
	retval->size = a1->size + a2->size;
	
	// One of them is always NULL, I'm interested in the union of the two sets
	// of pointers
	for (i = 0; i < 5; i++)
		retval->dirp_orig[i] = (struct dirent64*)((int)a1->dirp_orig[i] + (int)a2->dirp_orig[i]);

	c1 = 0;
	c2 = 0;
	d = 0;
	
	while (c1 < a1->size && c2 < a2->size)
	{
		compare = strcoll(a1->array[c1]->d_name, a2->array[c2]->d_name);
		
		if (compare < 0)
			retval->array[d++] = a1->array[c1++];
		else if (compare > 0)
			retval->array[d++] = a2->array[c2++];
		else if (keep == VIEWFS_KEEP_FIRST)
		{
			retval->array[d++] = a1->array[c1++];
			c2++;
			retval->size--;
		}
		else
		{
			retval->array[d++] = a2->array[c2++];
			c1++;
			retval->size--;
		}
	}

	while (c1 < a1->size)
		retval->array[d++] = a1->array[c1++];

	while (c2 < a2->size)
		retval->array[d++] = a2->array[c2++];
	
	return retval;
}

static struct d64array *d64array_subtract(struct d64array *a1, struct d64array *a2)
{
	struct d64array *retval;
	int i, c1, c2, d, compare;

	retval = malloc(sizeof(struct d64array));

	retval->array = malloc(a1->size * sizeof(struct dirent64*));
	retval->fd = a1->fd;
	retval->lastindex = 0;
	retval->size = a1->size;

	for (i = 0; i < 5; i++)
		retval->dirp_orig[i] = (struct dirent64*)((int)a1->dirp_orig[i] + (int)a2->dirp_orig[i]);

	c1 = 0;
	c2 = 0;
	d = 0;
	
	while (c1 < a1->size)
	{
		compare = strcoll(a1->array[c1]->d_name, a2->array[c2]->d_name);

		if (compare < 0)
			retval->array[d++] = a1->array[c1++];
		else if (compare > 0)
			c2++;
		else
		{
			c1++;
			c2++;
			retval->size--;
		}
	}

	return retval;

}

static int viewfs_getdents64(unsigned int fd, struct dirent64 *dirp, unsigned int count, void *umph)
{
	GDEBUG(1,"getdents64!\n");
	
	int umpid = um_mod_getumpid(umph);
	char *path = sfd_getpath(VIEWFS_SERVICE_CODE, fd);
	int pd_status = 0;
	int pd_total = 0;
	int found, firstempty;
	int i;

	struct dirent64 *gdtmp;
	int gdretval;

	struct d64array *cachedata;

	// Should have been blocked in open(), but who knows.
	VIEWFS_CRITCHECK(path, -1, VIEWFS_DEEP);

	if (FD_ISSET(fd, &procinfo[umpid].gd64))
	{
		for (i = 0; i < procinfo[umpid].gd64_size; i++)
		{
			GDEBUG(1, "parsing cache array: position %d (size %d), fd %d\n", i, procinfo[umpid].gd64_size, procinfo[umpid].gd64_data[i]->fd);
			if (procinfo[umpid].gd64_data[i]->fd == fd)
				return getdents64_cached(procinfo[umpid].gd64_data[i], dirp, count);
		}
		GDEBUG(1, "should have cached data for getdents64(%d) but none found. This is a bug.\n", fd);
		return -1;
	}

	prepare_names(path, VIEWFS_BOTH);
	
	if (EXISTS(currentpers->add))
	{
		pd_status |= VIEWFS_CURRENT_ADD;
		pd_total++;
	}
	if (EXISTS(currentpers->hide))
	{
		pd_status |= VIEWFS_CURRENT_HIDE;
		pd_total++;
	}
	if (EXISTS(defaultpers->add))
	{
		pd_total++;
		pd_status |= VIEWFS_DEFAULT_ADD;
	}
	if (EXISTS(defaultpers->hide))
	{
		pd_status |= VIEWFS_DEFAULT_HIDE;
		pd_total++;
	}
	if (EXISTS(path))
	{
		pd_status |= VIEWFS_REAL;
		pd_total++;
	}

	GDEBUG(1, "perspath is %s\n", path);
	
	if (FD_ISSET(fd, &procinfo[umpid].cur))
		GDEBUG(1, "fd %d is open in current personality\n", fd);
	if (FD_ISSET(fd, &procinfo[umpid].def))
		GDEBUG(1, "fd %d is open in default personality\n", fd);
	
	GDEBUG(1, "result =");

	if (pd_status & VIEWFS_REAL)
		GDEBUG(1, " R");
	else
		GDEBUG(1, " 0");

	if (pd_status & VIEWFS_DEFAULT_HIDE)
		GDEBUG(1, " \\ *-");
	if (pd_status & VIEWFS_DEFAULT_ADD)
		GDEBUG(1, " U *+");
	if (pd_status & VIEWFS_CURRENT_HIDE)
		GDEBUG(1, " \\ P-");
	if (pd_status & VIEWFS_CURRENT_ADD)
		GDEBUG(1, " U P+");
	
	GDEBUG(1, "\n");

	if (!pd_status)
		return DAR(syscall(__NR_getdents64, fd, dirp, count));

	/* If pd_total == 1, it means that only one of the various directories
	 * (real, current{add,hide}, default{add,hide} exists. So we don't have to
	 * sort and join the sets but we can directly call getdents and return it.
	 * The fd should already be associated to the correct directory, if the
	 * viewfs_open() implementation is correct. At least when the only
	 * existant directory is the real one (in this case the module should
	 * never be called, but just in case) or one of the "add" directories. */
	if (pd_total == 1)
	{
		if ((pd_status & VIEWFS_REAL) ||
				(pd_status & VIEWFS_CURRENT_ADD) ||
				(pd_status & VIEWFS_DEFAULT_ADD))
			return DAR(syscall(__NR_getdents64, fd, dirp, count));
		else
			GDEBUG(1, "this should never happen. please check: pd_status == %08x\n", pd_status);
	}
	else
	{
		/* What to do: for each of the potential 5 sets of files, obtain them
		 * and sort them; then, perform the correct operation (merge or
		 * difference).
		 */

		if (pd_status & VIEWFS_REAL)
		{
			gdretval = getdents64_whole_dir(path, &gdtmp, count);
			GDEBUG(1, "gwd on R returned %d\n", gdretval);
			if (gdretval < 0)
				return -1;

			GDEBUG(1, "converting to fixed-size array\n");
			cachedata = dirent64_to_d64array(gdtmp, gdretval, fd);
			cachedata->lastindex = 0;
			
			cachedata->dirp_orig[0] = gdtmp;
			for (i = 1; i < 5; i++)
				cachedata->dirp_orig[i] = NULL;
				
			GDEBUG(1, "sorting\n");
			sort_array64(cachedata);
			GDEBUG(1, "sorted\n");
		}
		else
		{
			cachedata = malloc(sizeof(struct d64array));
			cachedata->fd = fd;
			cachedata->array = NULL;
			cachedata->size = 0;
			cachedata->lastindex = 0;
			for (i = 0; i < 5; i++)
				cachedata->dirp_orig[i] = NULL;
		}
	
		/* TODO: Make the following a bit more efficient.
		 * At present, for each of the 4 possible changes to the original set
		 * (remove *-, add *+, remove P-, add P+) a d64array{merge,subtract}
		 * is called. These functions DO NOT work in place, but create a new
		 * array adding the elements from the original sets. So, if the 4
		 * personal directories are all non-empty, there is a total of 4
		 * passes and each of them allocates and copies the array.
		 * A better approach would take the 5 original sets once and perform
		 * the correct operations writing the result in a single new array.
		 * I think that in-place merging and subtraction is very difficult
		 * with the current array-based implementation. */
		
		if (pd_status & VIEWFS_DEFAULT_HIDE)
		{
			struct d64array *datmp, *old;
			gdretval = getdents64_whole_dir(defaultpers->hide, &gdtmp, count);
			GDEBUG(1, "gwd on *- returned %d\n", gdretval);
			if (gdretval < 0)
				return -1;

			datmp = dirent64_to_d64array(gdtmp, gdretval, fd);
			datmp->lastindex = 0;
			for (i = 0; i < 5; i++)
				datmp->dirp_orig[i] = NULL;
			datmp->dirp_orig[1] = gdtmp;
			sort_array64(datmp);

			old = cachedata;
			cachedata = d64array_subtract(old, datmp);
			clear_cachedata(old, VIEWFS_SHALLOW);
			clear_cachedata(datmp, VIEWFS_SHALLOW);
		}
		
		if (pd_status & VIEWFS_DEFAULT_ADD)
		{
			struct d64array *datmp, *old;
			gdretval = getdents64_whole_dir(defaultpers->add, &gdtmp, count);
			GDEBUG(1, "gwd on *+ returned %d\n", gdretval);
			if (gdretval < 0)
				return -1;
			
			datmp = dirent64_to_d64array(gdtmp, gdretval, fd);
			datmp->lastindex = 0;
			for (i = 0; i < 5; i++)
				datmp->dirp_orig[i] = NULL;
			datmp->dirp_orig[2] = gdtmp;
			sort_array64(datmp);

			old = cachedata;
			cachedata = d64array_merge(old, datmp, VIEWFS_KEEP_SECOND);
			clear_cachedata(old, VIEWFS_SHALLOW);
			clear_cachedata(datmp, VIEWFS_SHALLOW);
		}
		
		if (pd_status & VIEWFS_CURRENT_HIDE)
		{
			struct d64array *datmp, *old;
			gdretval = getdents64_whole_dir(currentpers->hide, &gdtmp, count);
			GDEBUG(1, "gwd on P- returned %d\n", gdretval);
			if (gdretval < 0)
				return -1;

			datmp = dirent64_to_d64array(gdtmp, gdretval, fd);
			datmp->lastindex = 0;
			for (i = 0; i < 5; i++)
				datmp->dirp_orig[i] = NULL;
			datmp->dirp_orig[3] = gdtmp;
			sort_array64(datmp);

			old = cachedata;
			cachedata = d64array_subtract(old, datmp);
			clear_cachedata(old, VIEWFS_SHALLOW);
			clear_cachedata(datmp, VIEWFS_SHALLOW);
		}
		
		if (pd_status & VIEWFS_CURRENT_ADD)
		{
			struct d64array *datmp, *old;
			gdretval = getdents64_whole_dir(currentpers->add, &gdtmp, count);
			GDEBUG(1, "gwd on P+ returned %d\n", gdretval);
			if (gdretval < 0)
				return -1;
			
			datmp = dirent64_to_d64array(gdtmp, gdretval, fd);
			datmp->lastindex = 0;
			for (i = 0; i < 5; i++)
				datmp->dirp_orig[i] = NULL;
			datmp->dirp_orig[4] = gdtmp;
			sort_array64(datmp);

			old = cachedata;
			cachedata = d64array_merge(old, datmp, VIEWFS_KEEP_SECOND);
			clear_cachedata(old, VIEWFS_SHALLOW);
			clear_cachedata(datmp, VIEWFS_SHALLOW);
		}

		// Add result to cache
		FD_SET(fd, &procinfo[umpid].gd64);
		found = 0;
		firstempty = -1;
		for (i = 0; i < procinfo[umpid].gd64_size && !found; i++)
			if (procinfo[umpid].gd64_data[i] && 
					(procinfo[umpid].gd64_data[i]->fd == fd))
			{
				GDEBUG(1, "cache already full for fd %d, flushing and creating new", fd);
				clear_cachedata(procinfo[umpid].gd64_data[i], VIEWFS_DEEP);
				procinfo[umpid].gd64_data[i] = cachedata;
				found = 1;
			}
			else if ((!procinfo[umpid].gd64_data[i]) && (firstempty < 0))
				firstempty = i;


		if (!found)
		{
			GDEBUG(1, "saving data to cache for fd %d\n", fd);
			if (firstempty < 0)
			{
				i = procinfo[umpid].gd64_size++;
				procinfo[umpid].gd64_data = realloc(procinfo[umpid].gd64_data,
						(i+1) * sizeof (struct d64array*));
				procinfo[umpid].gd64_data[i] = cachedata;
			}
			else
				procinfo[umpid].gd64_data[firstempty] = cachedata;
		}

		return getdents64_cached(cachedata, dirp, count);
	}
	return 0;
}

static struct service s;

/* Check if the given pathname must be managed by this module or not.
 * The choice takes into account the system call number and can look at its
 * parameters.
 * FIXME: check if the syscall parameters obtained via umph are the same that
 * are passed to the viewfs_* functions later.
 */
static int is_path_interesting(char *path, void *umph)
{
	int scno = um_mod_getsyscallno(umph);
	int umpid = um_mod_getumpid(umph);

	GDEBUG(2, "check for %s in syscall %s\n", path, SYSCALLNAME(scno));

	// TODO: convert this [slow?] switch into something faster, maybe
	// a pointer array
	switch(scno)
	{
		case __NR_open:
		case __NR_creat:
			return check_open(path, (int)(um_mod_getargs(umph)[1]), umpid);
		
		case __NR_stat:
		case __NR_stat64:
		case __NR_lstat:
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
		case __NR_chdir:
			return check_generic(path, umpid);

		case __NR_mkdir:
			return check_mkdir(path, umpid);

		case __NR_symlink:
			return check_generic((char*)(um_mod_getargs(umph)[1]), umpid);

		case __NR_fchdir:
			GDEBUG(1, "*CHECK* fchdir %d\n", (int)(um_mod_getargs(umph)[1]));
			break;

		default:
			GDEBUG(0, "[FIXME] viewfs support for %s has to be written\n", SYSCALLNAME(scno));
			prepare_names(path, VIEWFS_BOTH);
			break;
}
	
	return 0;
}

/* Choice function for viewfs */
static int viewfscheck(int type, void *arg, void *umph)
{
	char *path;
	
	if (type != CHECKPATH)
		return 0;

	path = (char*) arg;
	
	if (is_critical(path, VIEWFS_DEEP))
	{
		GDEBUG(1, "attempt to read inside the pers directory: %s\n", path);
		return 1;
	}

	if (is_path_interesting(path, umph))
	{
		GDEBUG(2, "found interesting file: %s\n", path);
		return 1;
	}
	else
		return 0;
}

static void
__attribute__ ((constructor))
init (void)
{
	GDEBUG(2, "viewfs init\n");
	
	prepare();
	
	s.name="viewfs Virtual FS";
	s.code = VIEWFS_SERVICE_CODE;
	s.checkfun=viewfscheck;
	s.addproc=addproc;
	s.delproc=delproc;
	s.syscall=(intfun *)malloc(scmap_scmapsize * sizeof(intfun));
	s.socket=(intfun *)malloc(scmap_sockmapsize * sizeof(intfun));
	s.syscall[uscno(__NR_open)]=viewfs_open;
	s.syscall[uscno(__NR_creat)]=viewfs_open; // creat must me mapped onto open
	s.syscall[uscno(__NR_read)]=read;
	s.syscall[uscno(__NR_write)]=write;
	s.syscall[uscno(__NR_readv)]=readv;
	s.syscall[uscno(__NR_writev)]=writev;
	s.syscall[uscno(__NR_close)]=viewfs_close;
	s.syscall[uscno(__NR_stat)]=viewfs_stat;
	s.syscall[uscno(__NR_lstat)]=viewfs_lstat;
	s.syscall[uscno(__NR_fstat)]=fstat;
	s.syscall[uscno(__NR_stat64)]=viewfs_stat64;
	s.syscall[uscno(__NR_lstat64)]=viewfs_lstat64;
	s.syscall[uscno(__NR_fstat64)]=fstat64;
	s.syscall[uscno(__NR_readlink)]=viewfs_readlink;
	s.syscall[uscno(__NR_getdents)]=viewfs_getdents;
	s.syscall[uscno(__NR_getdents64)]=viewfs_getdents64;
	s.syscall[uscno(__NR_access)]=viewfs_access;
	s.syscall[uscno(__NR_fcntl)]=fcntl32;
	s.syscall[uscno(__NR_fcntl64)]=fcntl64;
	s.syscall[uscno(__NR__llseek)]=_llseek;
	s.syscall[uscno(__NR_lseek)]= (intfun) lseek;
	s.syscall[uscno(__NR_mkdir)]=viewfs_mkdir;
	s.syscall[uscno(__NR_rmdir)]=viewfs_rmdir;
//	s.syscall[uscno(__NR_chdir)]=viewfs_chdir;
	s.syscall[uscno(__NR_chown)]=viewfs_chown;
	s.syscall[uscno(__NR_lchown)]=viewfs_lchown;
	s.syscall[uscno(__NR_fchown)]=fchown;
	s.syscall[uscno(__NR_chmod)]=viewfs_chmod;
	s.syscall[uscno(__NR_fchmod)]=fchmod;
	s.syscall[uscno(__NR_unlink)]=viewfs_unlink;
	s.syscall[uscno(__NR_fsync)]=fsync;
	s.syscall[uscno(__NR_fdatasync)]=fdatasync;
	s.syscall[uscno(__NR__newselect)]=select;
	s.syscall[uscno(__NR_link)]=viewfs_link;
	s.syscall[uscno(__NR_symlink)]=viewfs_symlink;
	s.syscall[uscno(__NR_pread64)]=viewfs_pread;
	s.syscall[uscno(__NR_pwrite64)]=viewfs_pwrite;
	s.syscall[uscno(__NR_utime)]=viewfs_utime;
	s.syscall[uscno(__NR_utimes)]=viewfs_utimes;
	add_service(&s);
}

static void
__attribute__ ((destructor))
fini (void)
{
	dispose();
	free(s.syscall);
	free(s.socket);
	GDEBUG(2, "viewfs fini\n");
}
