/*   
 *   This is part of Remote System Call (RSC) Library.
 *
 *   utils.h: utility functions header
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

#ifndef __UTILS_HEADER__
#define __UTILS_HEADER__
#include <sys/uio.h>

int write_n_bytes(int fd, void *buffer, int nbytes);
int read_n_bytes(int fd, void *buffer, int nbytes);

typedef int (*rwv_fun )(int filedes, const struct iovec *vector, size_t count);
int rwv_n_bytes(rwv_fun fun, int fd, struct iovec *vector, size_t count, int nbytes);

#define readv_n_bytes(fd, vector, count, nbytes)  rwv_n_bytes((rwv_fun)readv, fd, vector, count, nbytes)
#define writev_n_bytes(fd, vector, count, nbytes) rwv_n_bytes((rwv_fun)writev, fd, vector, count, nbytes)

#endif /* __UTILS_HEADER__ */
