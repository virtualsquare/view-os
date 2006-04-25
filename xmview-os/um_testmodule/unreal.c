/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   example of um-ViewOS module:
 *   remap of /unreal onto the real FS
 *   /unreal/XXXX is mapped to XXXX in th real FS
 *   
 *   Copyright 2005 Renzo Davoli University of Bologna - Italy
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
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <utime.h>
#include <sys/time.h>
#include "module.h"
#include "libummod.h"

int read(), write(), close();


static int alwaysfalse()
{
	return 0;
}

static int unrealpath(char *path)
{
	return(strncmp(path,"/unreal",7) == 0);
}

static char *unwrap(char *path)
{
	char *s;
	s=&(path[7]);
	if (*s == 0) s = "/";
	return (s);
}

static int unreal_open(char *pathname, int flags, mode_t mode)
{
	return open(unwrap(pathname),flags,mode);
}

static int unreal_stat(char *pathname, struct stat *buf)
{
	return stat(unwrap(pathname),buf);
}

static int unreal_lstat(char *pathname, struct stat *buf)
{
	return lstat(unwrap(pathname),buf);
}

static int unreal_stat64(char *pathname, struct stat64 *buf)
{
	return stat64(unwrap(pathname),buf);
}

static int unreal_lstat64(char *pathname, struct stat64 *buf)
{
	return lstat64(unwrap(pathname),buf);
}

static int unreal_readlink(char *path, char *buf, size_t bufsiz)
{
	return readlink(unwrap(path),buf,bufsiz);
}

static int unreal_access(char *path, int mode)
{
	return access(unwrap(path),mode);
}

static int unreal_mkdir(char *path, int mode)
{
	return mkdir(unwrap(path),mode);
}

static int unreal_rmdir(char *path)
{
	return rmdir(unwrap(path));
}

static int unreal_chmod(char *path, int mode)
{
	return chmod(unwrap(path),mode);
}

static int unreal_chown(char *path, uid_t owner, gid_t group)
{
	return chown(unwrap(path),owner,group);
}

static int unreal_lchown(char *path, uid_t owner, gid_t group)
{
	return lchown(unwrap(path),owner,group);
}

static int unreal_unlink(char *path)
{
	return unlink(unwrap(path));
}

static int unreal_link(char *oldpath, char *newpath)
{
	return link(unwrap(oldpath),unwrap(newpath));
}

static int unreal_symlink(char *oldpath, char *newpath)
{
	return symlink(oldpath,unwrap(newpath));
}

static int unreal_utime(char *filename, struct utimbuf *buf)
{
	return utime(unwrap(filename),buf);
}

static int unreal_utimes(char *filename, struct timeval tv[2])
{
	return utimes(unwrap(filename),tv);
}

ssize_t unreal_pread(int fd, void *buf, size_t count, long long offset)
{
	off_t off=offset;
	return pread(fd,buf,count,off);
}

ssize_t unreal_pwrite(int fd, const void *buf, size_t count, long long offset)
{
	off_t off=offset;
	return pwrite(fd,buf,count,off);
}

static struct service s;

static void
__attribute__ ((constructor))
init (void)
{
	printf("unreal init\n");
	s.name="/unreal Mapping to FS (server side)";
	s.code=0xfe;
	s.checkpath=unrealpath;
	s.checksocket=alwaysfalse;
	s.syscall=(intfun *)malloc(scmap_scmapsize * sizeof(intfun));
	s.socket=(intfun *)malloc(scmap_sockmapsize * sizeof(intfun));
	s.syscall[uscno(__NR_open)]=unreal_open;
	s.syscall[uscno(__NR_creat)]=unreal_open; /*creat must me mapped onto open*/
	s.syscall[uscno(__NR_read)]=read;
	s.syscall[uscno(__NR_write)]=write;
	s.syscall[uscno(__NR_readv)]=readv;
	s.syscall[uscno(__NR_writev)]=writev;
	s.syscall[uscno(__NR_close)]=close;
	s.syscall[uscno(__NR_stat)]=unreal_stat;
	s.syscall[uscno(__NR_lstat)]=unreal_lstat;
	s.syscall[uscno(__NR_fstat)]=fstat;
	s.syscall[uscno(__NR_stat64)]=unreal_stat64;
	s.syscall[uscno(__NR_lstat64)]=unreal_lstat64;
	s.syscall[uscno(__NR_fstat64)]=fstat64;
	s.syscall[uscno(__NR_readlink)]=unreal_readlink;
	s.syscall[uscno(__NR_getdents)]=getdents;
	s.syscall[uscno(__NR_getdents64)]=getdents64;
	s.syscall[uscno(__NR_access)]=unreal_access;
	s.syscall[uscno(__NR_fcntl)]=fcntl32;
	s.syscall[uscno(__NR_fcntl64)]=fcntl64;
	s.syscall[uscno(__NR__llseek)]=_llseek;
	s.syscall[uscno(__NR_lseek)]= (intfun) lseek;
	s.syscall[uscno(__NR_mkdir)]=unreal_mkdir;
	s.syscall[uscno(__NR_rmdir)]=unreal_rmdir;
	s.syscall[uscno(__NR_chown)]=unreal_chown;
	s.syscall[uscno(__NR_lchown)]=unreal_lchown;
	s.syscall[uscno(__NR_fchown)]=fchown;
	s.syscall[uscno(__NR_chmod)]=unreal_chmod;
	s.syscall[uscno(__NR_fchmod)]=fchmod;
	s.syscall[uscno(__NR_unlink)]=unreal_unlink;
	s.syscall[uscno(__NR_fsync)]=fsync;
	s.syscall[uscno(__NR_fdatasync)]=fdatasync;
	s.syscall[uscno(__NR__newselect)]=select;
	s.syscall[uscno(__NR_link)]=unreal_link;
	s.syscall[uscno(__NR_symlink)]=unreal_symlink;
	s.syscall[uscno(__NR_pread64)]=unreal_pread;
	s.syscall[uscno(__NR_pwrite64)]=unreal_pwrite;
	s.syscall[uscno(__NR_utime)]=unreal_utime;
	s.syscall[uscno(__NR_utimes)]=unreal_utimes;
	add_service(&s);
}

static void
__attribute__ ((destructor))
fini (void)
{
	free(s.syscall);
	free(s.socket);
	printf("unreal fini\n");
}
