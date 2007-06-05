/*   
 *   This is part of Remote System Call (RSC) Library.
 *
 *   fill_write_pointers.c: functions used during the tests 
 *   to fill write syscall buffers 
 *   
 *   Copyright (C) 2007 Andrea Forni
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

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <stdarg.h>
#include <string.h>

#include "rsc_client.h"
#include "fill_request.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/net.h>
#include <linux/types.h>
#include <linux/unistd.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/timex.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

int simple_fill() {
  errno = 0;
  return  0;
}

int _llseek_fill_write_pointers(unsigned int fd, unsigned long int offset_high, unsigned long int offset_low, loff_t *result, unsigned int whence)
{

  if(result != NULL)
    *result = 10;
  return 0;
}

int accept_fill_write_pointers(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
  struct sockaddr *a;
  
  if(addr != NULL) {
    a = fill_struct_sockaddr_in();
    memcpy(addr, a, sizeof(struct sockaddr_in));
    free(a);
    if(addrlen != NULL)
      *addrlen = sizeof(struct sockaddr_in);
  } else {
    if(addrlen != NULL)
      *addrlen = 0;
  }
  
  return 0;
}

int adjtimex_fill_write_pointers(struct timex *buf)
{

  if(buf != NULL)
    buf->offset = 20;
  return 0;
}

int clock_getres_fill_write_pointers(clockid_t clk_id, struct timespec *res)
{
  if(res != NULL) {
    res->tv_sec = 10;
    res->tv_nsec = 100;
  }
  return 0;
}

int clock_gettime_fill_write_pointers(clockid_t clk_id, struct timespec *tp)
{

  if(tp != NULL) {
    tp->tv_sec = 10;
    tp->tv_nsec = 100;
  }
  return 0;
}

int fgetxattr_fill_write_pointers(int filedes, char *name, void *value, size_t size)
{
  if(value != NULL)
    memset(value, 'b', size);
  return 0;
}

int fstat64_fill_write_pointers(int filedes, struct stat64 *buf)
{
  if(buf != NULL) {
		buf->st_dev = 10;
		buf->st_ino = 10 ;
		buf->st_mode = S_IRWXU;
		buf->st_nlink = 2;
		buf->st_uid = 1000;
		buf->st_gid = 1000;
		buf->st_rdev = 1;
		buf->st_size = 1024;
		buf->st_atime = 1000;
		buf->st_mtime = 2000;
		buf->st_ctime = 3000;
		buf->st_blksize = 512;
		buf->st_blocks = 2;
  }
  return 0;
}

int fstatfs64_fill_write_pointers(unsigned int fd, struct statfs64 *buf)
{
  if(buf != NULL) {
		buf->f_type = 1;
		buf->f_bsize = 512;
		buf->f_blocks = 2;
		buf->f_bfree = 3;
		buf->f_bavail = 3;
		buf->f_files = 10;
		buf->f_ffree = 2;
		buf->f_namelen = 200;
		buf->f_frsize = 1;
  }
  return 0;
}

int getdents64_fill_write_pointers(unsigned int fd, struct dirent64 *dirp, unsigned int count)
{
  if(dirp != NULL) {
    dirp->d_ino = 2;
    dirp->d_off = 10;
    dirp->d_reclen = 20;
    dirp->d_type = 30;
    dirp->d_name[0] = '/';
    dirp->d_name[1] = 't';
    dirp->d_name[2] = 'm';
    dirp->d_name[3] = 'p';
    dirp->d_name[4] = '/';
    dirp->d_name[5] = '\0';
  }
  return 0;
}

int getpeername_fill_write_pointers(int s, struct sockaddr *name, socklen_t *namelen)
{
  if(name != NULL) {
    struct sockaddr *a;
    a = fill_struct_sockaddr_in();
    memcpy(name, a, sizeof(struct sockaddr_in));
    if(namelen != NULL)
      *namelen = sizeof(struct sockaddr_in);
    free(a);
  } else if(namelen != NULL)
    *namelen = 0;
  return 0;
}

int getsockname_fill_write_pointers(int s, struct sockaddr *name, socklen_t *namelen)
{
  if(name != NULL) {
    struct sockaddr *a;
    a = fill_struct_sockaddr_in();
    memcpy(name, a, sizeof(struct sockaddr_in));
    if(namelen != NULL)
      *namelen = sizeof(struct sockaddr_in);
    free(a);
  } else if(namelen != NULL)
    *namelen = 0;
  return 0;
}

int getsockopt_fill_write_pointers(int s, int level, int optname, void *optval, socklen_t *optlen)
{
  if(optlen != NULL) {
    if(optval != NULL ) {
      *optlen = sizeof(int);
      memset(optval, 1, sizeof(int));
    } else {
      *optlen = 0;
    }
  }
  return 0;
}

int gettimeofday_fill_write_pointers(struct timeval *tv, struct timezone *tz)
{
  if(tv != NULL) {
    tv->tv_sec = 10;
    tv->tv_usec = 20;
  }
  if(tz != NULL) {
    tz->tz_minuteswest = 60;
    tz->tz_dsttime = 1;
  }
  return 0;
}

int getxattr_fill_write_pointers(char *path, char *name, void *value, size_t size)
{
  if(value != NULL)
    memset(value, 'b', size);
  return 0;
}

int lgetxattr_fill_write_pointers(char *path, char *name, void *value, size_t size)
{
  if(value != NULL)
    memset(value, 'b', size);
  return 0;
}

int lstat64_fill_write_pointers(char *path, struct stat64 *buf)
{
  if(buf != NULL) {
	  buf->st_dev = 10;
		buf->st_ino = 10 ;
		buf->st_mode = S_IRWXU;
		buf->st_nlink = 2;
		buf->st_uid = 1000;
		buf->st_gid = 1000;
		buf->st_rdev = 1;
		buf->st_size = 1024;
		buf->st_atime = 1000;
		buf->st_mtime = 2000;
		buf->st_ctime = 3000;
		buf->st_blksize = 512;
		buf->st_blocks = 2;
  }
  return 0;
}

int pread64_fill_write_pointers(int fd, void *buf, size_t count, off_t offset)
{

  if(buf != NULL)
    memset(buf, 'b', count);
  return 0;
}

int read_fill_write_pointers(int fd, void *buf, size_t count)
{
  if(buf != NULL)
    memset(buf, 'b', count);
  return count;
}

int readlink_fill_write_pointers(char *path, char *buf, size_t bufsiz)
{
  if(buf != NULL) {
    char *str;
    size_t  str_len;

    str = fill_string(NULL);
    str_len = strlen(str);
    memcpy(buf, str, str_len > bufsiz ? bufsiz : str_len );
    free(str);
  }
  return 0;
}

int recv_fill_write_pointers(int s, void *buf, size_t len, int flags)
{
  if(buf != NULL)
    memset(buf, 'b', len);
  return 0;
}

int recvfrom_fill_write_pointers(int s, void *buf, size_t len, int flags, struct sockaddr *from, socklen_t *fromlen)
{
  if(buf != NULL)
    memset(buf, 'b', len);
  if(fromlen != NULL)
    *fromlen = sizeof(struct sockaddr);
  return 0;
}

int stat64_fill_write_pointers(char *path, struct stat64 *buf)
{

  if(buf != NULL) {
	  buf->st_dev = 10;
		buf->st_ino = 10 ;
		buf->st_mode = S_IRWXU;
		buf->st_nlink = 2;
		buf->st_uid = 1000;
		buf->st_gid = 1000;
		buf->st_rdev = 1;
		buf->st_size = 1024;
		buf->st_atime = 1000;
		buf->st_mtime = 2000;
		buf->st_ctime = 3000;
		buf->st_blksize = 512;
		buf->st_blocks = 2;
  }
  return 0;
}

int statfs64_fill_write_pointers(char *path, struct statfs64 *buf)
{
  if(buf != NULL) {
		buf->f_type = 1;
		buf->f_bsize = 512;
		buf->f_blocks = 2;
		buf->f_bfree = 3;
		buf->f_bavail = 3;
		buf->f_files = 10;
		buf->f_ffree = 2;
		buf->f_namelen = 200;
		buf->f_frsize = 1;
  }  return 0;
}

int uname_fill_write_pointers(struct utsname *buf)
{
  if(buf != NULL) {
    strcpy(buf->sysname, "sysname");
    strcpy(buf->nodename, "nodename");
    strcpy(buf->release, "release");
    strcpy(buf->version, "1");
    strcpy(buf->machine, "x86");
  }
  return 0;
}

int ioctl_fill_write_pointers(int d, int request, void *arg)
{
  if(arg != NULL && (request == 20 || request == 30))
    memset(arg, 'b', 100);
  return 0;
}

int fcntl_fill_write_pointers(int16_t cmd_type, int fd, int cmd, struct flock *lock)
{
  if((cmd_type & FCNTL_3RD_FLOCK_W) && lock != NULL) {
    lock->l_type   = F_WRLCK;
    lock->l_whence = SEEK_END;
    lock->l_start  = 66;
    lock->l_len    = 80;
    lock->l_pid    = 246;
  }
  
  return 0;
}
