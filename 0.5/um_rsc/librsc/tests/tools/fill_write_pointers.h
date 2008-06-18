/*   
 *   This is part of Remote System Call (RSC) Library.
 *
 *   fill_write_pointers.h: header of the functions used during the tests 
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
#ifndef  __FILL_WRITE_POINTERS__
#define  __FILL_WRITE_POINTERS__
#include <stdlib.h>
#include <stdio.h>

#include "rsc_client.h"

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

int simple_fill();

int _llseek_fill_write_pointers(unsigned int fd, unsigned long int offset_high, unsigned long int offset_low, loff_t *result, unsigned int whence);
int accept_fill_write_pointers(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int adjtimex_fill_write_pointers(struct timex *buf);
int clock_getres_fill_write_pointers(clockid_t clk_id, struct timespec *res);
int clock_gettime_fill_write_pointers(clockid_t clk_id, struct timespec *tp);
int fgetxattr_fill_write_pointers(int filedes, char *name, void *value, size_t size);
int fstat64_fill_write_pointers(int filedes, struct stat64 *buf);
int fstatfs64_fill_write_pointers(unsigned int fd, struct statfs64 *buf);
int getdents64_fill_write_pointers(unsigned int fd, struct dirent64 *dirp, unsigned int count);
int getpeername_fill_write_pointers(int s, struct sockaddr *name, socklen_t *namelen);
int getsockname_fill_write_pointers(int s, struct sockaddr *name, socklen_t *namelen);
int getsockopt_fill_write_pointers(int s, int level, int optname, void *optval, socklen_t *optlen);
int gettimeofday_fill_write_pointers(struct timeval *tv, struct timezone *tz);
int getxattr_fill_write_pointers(char *path, char *name, void *value, size_t size);
int lgetxattr_fill_write_pointers(char *path, char *name, void *value, size_t size);
int lstat64_fill_write_pointers(char *path, struct stat64 *buf);
int pread64_fill_write_pointers(int fd, void *buf, size_t count, off_t offset);
int read_fill_write_pointers(int fd, void *buf, size_t count);
int readlink_fill_write_pointers(char *path, char *buf, size_t bufsiz);
int recv_fill_write_pointers(int s, void *buf, size_t len, int flags);
int recvfrom_fill_write_pointers(int s, void *buf, size_t len, int flags, struct sockaddr *from, socklen_t *fromlen);
int stat64_fill_write_pointers(char *path, struct stat64 *buf);
int statfs64_fill_write_pointers(char *path, struct statfs64 *buf);
int uname_fill_write_pointers(struct utsname *buf);
int ioctl_fill_write_pointers(int d, int request, void *arg);
int fcntl_fill_write_pointers(int16_t cmd_type, int fd, int cmd, struct flock *lock);

#endif /* __FILL_WRITE_POINTERS__ */
