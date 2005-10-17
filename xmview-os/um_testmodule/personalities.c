/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   example of um-ViewOS module:
 *   personalities
 *   
 *   Copyright 2005 Renzo Davoli University of Bologna - Italy
 *   Modified 2005 Ludovico Gardenghi
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
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <utime.h>
#include "module.h"
#include "libummod.h"

#define UMPERS_PREFIX "/.umview/umpers"


/* Check if "path" can be accessed by the traced process. If yes, execute
 * "func" and return its return value. Else, set errno to "newerrno"
 * and return "rv". */
#if 0
#define UMPERS_VERIFY(func, path, rv, newerrno) \
	{ \
		/* fprintf(stderr,"%s: verifying %s...\n", __func__, (path)); */ \
		return (umpers_verify(path) ? (func) : (errno = newerrno, rv)); \
	}
#endif


/* Base directory of personalities mask (e.g. /home/ludovico/.umview/umpers)
 * It's stored in a global variable for better performances; this should not
 * be a problem for multithreading since the home directory of the umview
 * process is not supposed to change during execution (is it?). */
static char *umpers_fullprefix = NULL;
static int umpers_fullprefix_len = 0;

/* Build the name of the "ghost" file in the umview configuration directory.
 * For now, just append the first <depth> directories of <path> to UMVIEW_PREFIX.
 * If depth is < 0, add the full path. The result is put in the string pointed
 * to by <dest>, that must have enough space for it.
 * Return <depth> if the path is at least so deep, or the real path depth 
 * otherwise.
 * TODO: Add support for different trees (each umview instance, or each
 * traced process, should be able to use its set of permissions).
 */
static int umpers_maskfile(char* dest, char *path, int depth)
{
	char *fullpath;
	int pathlen; 
	int curdepth;
	
	/* Probably never needed, but this is safer. */
	if (!path)
		path = "";

	pathlen = strlen(path);

	fullpath = dest;
	
	/* Build fullpath */
	strncpy(fullpath, umpers_fullprefix, umpers_fullprefix_len + 1);

	if (depth < 0)
		strncat(fullpath, path, pathlen);
	else
	{
		int i = 0;
		for (curdepth = 0; (curdepth < depth) && (i < pathlen); curdepth++)
		{
			fullpath[umpers_fullprefix_len + i] = path[i];
			i++;
			
			while ((i < pathlen) && (path[i] != '/'))
			{
				fullpath[umpers_fullprefix_len + i] = path[i];
				i++;
			}
		}
		fullpath[umpers_fullprefix_len + i] = '\0';
	}

	return curdepth;

}

/* Do the real check. Return 1 if the file can be accessed, 0 if it can't.
 * TODO: write this function. */
static int umpers_verify(char *path)
{
	char *fullpath;
	struct stat path_info;
	int found;
	int prefix_length=strlen(UMPERS_PREFIX);
	int curdepth, lastdepth;
	
	/* First of all: the traced processes MUST NOT read, write or do
	 * anything else on the mask directory. */

	if (strncmp(path, umpers_fullprefix, umpers_fullprefix_len) == 0)
	{
		fprintf(stderr,"!!! WARNING - Attempt to access to config directory: %s\n", path);
		return 0; 
	}

	fullpath = malloc(strlen(path) + umpers_fullprefix_len + 1);

	found = 0;
	lastdepth = -1;
	curdepth = 1;
//	fprintf(stderr, "*** verify for %s\n", path);
	while (found == 0)
	{
		int retval;
		curdepth = umpers_maskfile(fullpath, path, curdepth);
//		fprintf(stderr, "maskfile is %s...", fullpath);
		if (curdepth == lastdepth) /* Search is over, not found */
		{
//			fprintf(stderr,"maxdepth %d and not found, allowing\n", curdepth);
			found = -1;
		}
		else
		{
			retval = stat(fullpath, &path_info);
			if (retval < 0) /* Not found */
			{
//				fprintf(stderr,"at depth %d, not found, allowing\n", curdepth);
				found = -1;
			}
			else if (S_ISDIR(path_info.st_mode));
//				fprintf(stderr,"at depth %d, found and is a directory, continuing\n", curdepth);
			else
			{
//				fprintf(stderr,"at depth %d, found and not a directory, DENYING\n", curdepth);
				found = 1;
			}
		}
		lastdepth = curdepth;
		curdepth++;
	}

	free(fullpath);
	return (found==1)?0:-1;
}

/* Tell if the given path has to be managed by this module or not. For now
 * we can't manage dynamic libraries, so we skip everything starting with
 * /lib or /usr/lib or /usr/X11R6/lib.
 * FIXME: Ugly. Very ugly. At least we should parse ld configuration. */
static int umpers_path(char *path)
{
	int retval;
	
	retval = ((strncmp(path, "/lib", 4) != 0) &&
			(strncmp(path, "/usr/lib", 8) != 0) &&
			(strncmp(path, "/usr/bin/X11", 12) != 0) &&
			(strncmp(path, "/usr/X11R6/lib", 14) != 0));

	retval &= ~umpers_verify(path);

	if (!retval)
	//	fprintf(stderr,"+++ personalities: allowing %s\n", path);
		;
	else
		fprintf(stderr,"--- personalities: denying %s\n", path);

	return retval;
}

static int umpers_choice(int type, void *arg)
{
	if (type == CHECKPATH)
		return umpers_path(arg);
	else
		return 0;
}


#if 0
/* Begin of system calls wrappers.
 * FIXME: Maybe some of them should do a weaker check. For instance, I don't
 * want ls to print "Permission denied" when I list a directory which contain
 * a forbidden file. */

static int umpers_open(char *pathname, int flags, mode_t mode)
{
	UMPERS_VERIFY(open(pathname, flags, mode), pathname, -1, EACCES);
}

static int umpers_stat(char *pathname, struct stat *buf)
{
	UMPERS_VERIFY(stat(pathname,buf), pathname, -1, EACCES);
}

static int umpers_lstat(char *pathname, struct stat *buf)
{
	UMPERS_VERIFY(lstat(pathname,buf), pathname, -1, EACCES);
}

static int umpers_stat64(char *pathname, struct stat64 *buf)
{
	UMPERS_VERIFY(stat64(pathname,buf), pathname, -1, EACCES)
}

static int umpers_lstat64(char *pathname, struct stat64 *buf)
{
	UMPERS_VERIFY(lstat64(pathname,buf), pathname, -1, EACCES);
}

static int umpers_readlink(char *path, char *buf, size_t bufsiz)
{
	UMPERS_VERIFY(readlink(path,buf,bufsiz), path, -1, EACCES);
}

static int umpers_access(char *path, int mode)
{
	UMPERS_VERIFY(access(path,mode), path, -1, EACCES);
}

static int umpers_mkdir(char *path, int mode)
{
	UMPERS_VERIFY(mkdir(path,mode), path, -1, EACCES);
}

static int umpers_rmdir(char *path)
{
	UMPERS_VERIFY(rmdir(path), path, -1, EACCES);
}

static int umpers_chmod(char *path, int mode)
{
	UMPERS_VERIFY(chmod(path,mode), path, -1, EACCES);
}

static int umpers_chown(char *path, uid_t owner, gid_t group)
{
	UMPERS_VERIFY(chown(path,owner,group), path, -1, EACCES);
}

static int umpers_lchown(char *path, uid_t owner, gid_t group)
{
	UMPERS_VERIFY(lchown(path,owner,group), path, -1, EACCES);
}

static int umpers_unlink(char *path)
{
	UMPERS_VERIFY(unlink(path), path, -1, EACCES);
}

static int umpers_link(char *oldpath, char *newpath)
{
	UMPERS_VERIFY(link(oldpath, newpath), newpath, -1, EACCES);
}

static int umpers_symlink(char *oldpath, char *newpath)
{
	UMPERS_VERIFY(symlink(oldpath, newpath), newpath, -1, EACCES);
}

static int umpers_utime(char *filename, struct utimbuf *buf)
{
	UMPERS_VERIFY(utime(filename,buf), filename, -1, EACCES);
}

static int umpers_utimes(char *filename, struct timeval tv[2])
{
	UMPERS_VERIFY(utimes(filename,tv), filename, -1, EACCES);
}

/* Copied from unreal. I still have to figure out why they are here. */

ssize_t umpers_pread(int fd, void *buf, size_t count, long long offset)
{
	off_t off=offset;
	return pread(fd,buf,count,off);
}

ssize_t umpers_pwrite(int fd, const void *buf, size_t count, long long offset)
{
	off_t off=offset;
	return pwrite(fd,buf,count,off);
}

#endif

static int umpers_deny(void)
{
	errno = EACCES;
	return -1;
}

static struct service s;

static void
__attribute__ ((constructor))
init (void)
{
	fprintf(stderr,"*** THIS CODE STILL DOES NOT WORK, PLEASE DO NOT USE IT ***\n");
	fprintf(stderr,"personalities init\n");

	char *home = getenv("HOME");
	
	/* Usually bash sets this to "/" if not found, but just to be sure. */
	if (!home)
		home = "";
	
	/* Fill the variable which contains the base directory for
	 * ghost files (e.g. "/home/user/.umview/umpers", and the one with
	 * its length (so we don't have to use strlen() over and over) */
	umpers_fullprefix_len = strlen(home) + strlen(UMPERS_PREFIX);
	umpers_fullprefix = malloc(umpers_fullprefix_len + 1);
	strncpy(umpers_fullprefix, home, strlen(home));
	strncat(umpers_fullprefix, UMPERS_PREFIX, strlen(UMPERS_PREFIX));

	fprintf(stderr,"Configuration directory is %s\n", umpers_fullprefix);
	s.name="Personalities management";
	s.code=0xfc;
	s.checkfun=umpers_choice;
	s.syscall=(intfun *)malloc(scmap_scmapsize * sizeof(intfun));
	s.socket=(intfun *)malloc(scmap_sockmapsize * sizeof(intfun));
#if 0
	s.syscall[uscno(__NR_open)]=umpers_open;
	/* creat must me mapped onto open */
	s.syscall[uscno(__NR_creat)]=umpers_open;
	s.syscall[uscno(__NR_read)]=read;
	s.syscall[uscno(__NR_write)]=write;
	s.syscall[uscno(__NR_readv)]=readv;
	s.syscall[uscno(__NR_writev)]=writev;
	s.syscall[uscno(__NR_close)]=close;
	s.syscall[uscno(__NR_stat)]=umpers_stat;
	s.syscall[uscno(__NR_lstat)]=umpers_lstat;
	s.syscall[uscno(__NR_fstat)]=fstat;
	s.syscall[uscno(__NR_stat64)]=umpers_stat64;
	s.syscall[uscno(__NR_lstat64)]=umpers_lstat64;
	s.syscall[uscno(__NR_fstat64)]=fstat64;
	s.syscall[uscno(__NR_readlink)]=umpers_readlink;
	s.syscall[uscno(__NR_getdents)]=getdents;
	s.syscall[uscno(__NR_getdents64)]=getdents64;
	s.syscall[uscno(__NR_access)]=umpers_access;
	s.syscall[uscno(__NR_fcntl)]=fcntl32;
	s.syscall[uscno(__NR_fcntl64)]=fcntl64;
	s.syscall[uscno(__NR__llseek)]=_llseek;
	s.syscall[uscno(__NR_lseek)]= (intfun) lseek;
	s.syscall[uscno(__NR_mkdir)]=umpers_mkdir;
	s.syscall[uscno(__NR_rmdir)]=umpers_rmdir;
	s.syscall[uscno(__NR_chown)]=umpers_chown;
	s.syscall[uscno(__NR_lchown)]=umpers_lchown;
	s.syscall[uscno(__NR_fchown)]=fchown;
	s.syscall[uscno(__NR_chmod)]=umpers_chmod;
	s.syscall[uscno(__NR_fchmod)]=fchmod;
	s.syscall[uscno(__NR_unlink)]=umpers_unlink;
	s.syscall[uscno(__NR_fsync)]=fsync;
	s.syscall[uscno(__NR_fdatasync)]=fdatasync;
	s.syscall[uscno(__NR__newselect)]=select;
	s.syscall[uscno(__NR_link)]=umpers_link;
	s.syscall[uscno(__NR_symlink)]=umpers_symlink;
	s.syscall[uscno(__NR_pread64)]=umpers_pread;
	s.syscall[uscno(__NR_pwrite64)]=umpers_pwrite;
	s.syscall[uscno(__NR_utime)]=umpers_utime;
	s.syscall[uscno(__NR_utimes)]=umpers_utimes;
#endif

	s.syscall[uscno(__NR_open)]=umpers_deny;
	/* creat must me mapped onto open */
	s.syscall[uscno(__NR_creat)]=umpers_deny;
	s.syscall[uscno(__NR_read)]=read;
	s.syscall[uscno(__NR_write)]=write;
	s.syscall[uscno(__NR_readv)]=readv;
	s.syscall[uscno(__NR_writev)]=writev;
	s.syscall[uscno(__NR_close)]=close;
	s.syscall[uscno(__NR_stat)]=umpers_deny;
	s.syscall[uscno(__NR_lstat)]=umpers_deny;
	s.syscall[uscno(__NR_fstat)]=fstat;
	s.syscall[uscno(__NR_stat64)]=umpers_deny;
	s.syscall[uscno(__NR_lstat64)]=umpers_deny;
	s.syscall[uscno(__NR_fstat64)]=fstat64;
	s.syscall[uscno(__NR_readlink)]=umpers_deny;
	s.syscall[uscno(__NR_getdents)]=getdents;
	s.syscall[uscno(__NR_getdents64)]=getdents64;
	s.syscall[uscno(__NR_access)]=umpers_deny;
	s.syscall[uscno(__NR_fcntl)]=fcntl32;
	s.syscall[uscno(__NR_fcntl64)]=fcntl64;
	s.syscall[uscno(__NR__llseek)]=_llseek;
	s.syscall[uscno(__NR_lseek)]= (intfun) lseek;
	s.syscall[uscno(__NR_mkdir)]=umpers_deny;
	s.syscall[uscno(__NR_rmdir)]=umpers_deny;
	s.syscall[uscno(__NR_chown)]=umpers_deny;
	s.syscall[uscno(__NR_lchown)]=umpers_deny;
	s.syscall[uscno(__NR_fchown)]=fchown;
	s.syscall[uscno(__NR_chmod)]=umpers_deny;
	s.syscall[uscno(__NR_fchmod)]=fchmod;
	s.syscall[uscno(__NR_unlink)]=umpers_deny;
	s.syscall[uscno(__NR_fsync)]=fsync;
	s.syscall[uscno(__NR_fdatasync)]=fdatasync;
	s.syscall[uscno(__NR__newselect)]=select;
	s.syscall[uscno(__NR_link)]=umpers_deny;
	s.syscall[uscno(__NR_symlink)]=umpers_deny;
	s.syscall[uscno(__NR_pread64)]=umpers_deny;
	s.syscall[uscno(__NR_pwrite64)]=umpers_deny;
	s.syscall[uscno(__NR_utime)]=umpers_deny;
	s.syscall[uscno(__NR_utimes)]=umpers_deny;
	add_service(&s);
	
}

static void
__attribute__ ((destructor))
fini (void)
{
	free(s.syscall);
	free(s.socket);
	fprintf(stderr,"personalities fini\n");
}
