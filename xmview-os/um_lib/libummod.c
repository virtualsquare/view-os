/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   
 *
 *   Copyright 2005 Renzo Davoli University of Bologna - Italy
 *   Modified 2005 Andrea Seraghiti
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
#include <unistd.h>
#include <linux/types.h>
#include <sys/types.h>
#define _DIRENT_H
#include <bits/dirent.h>
#undef _DIRENT_H
#include <linux/unistd.h>
#include <errno.h>
#include <config.h>


int getdents(unsigned int fd, struct dirent *dirp, unsigned int count)
{
	return syscall(__NR_getdents, fd, dirp, count);
}

int getdents64(unsigned int fd, struct dirent64 *dirp, unsigned int count)
{
	return syscall(__NR_getdents64, fd, dirp, count);
}

#if ! defined(__x86_64__)
int fcntl32(int fd, int cmd, long arg)
{
	return syscall(__NR_fcntl, fd, cmd, arg);
}
#endif

int fcntl64(int fd, int cmd, long arg)
{
#if defined(__x86_64__)
	return syscall(__NR_fcntl, fd, cmd, arg);
#else
	return syscall(__NR_fcntl64, fd, cmd, arg);
#endif
}

#if !defined(__x86_64__) // it doesn't appear in syscall table of amd64
int _llseek(unsigned int fd, unsigned long offset_high,  unsigned  long
		       offset_low, loff_t *result, unsigned int whence)
{
	return syscall(__NR__llseek, fd, offset_high, offset_low, result, whence);
}
#endif

