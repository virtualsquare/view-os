/*   
 *   This is part of Remote System Call (RSC) Library.
 *
 *   type_equality.h: functions to test the equality of two variables
 *                    with same type 
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

/* This module contains functions that test the equality of two structures,
 * strings or void buffers. */
#ifndef __TEST_TYPE_EQUALITY__
#define __TEST_TYPE_EQUALITY__
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/timex.h>
#include <fcntl.h>
#include <sys/utsname.h>
#ifndef __USE_LARGEFILE64
#define __USE_LARGEFILE64
#endif
#include <sys/statfs.h>
#include <sys/stat.h>
#include <dirent.h>
#include <linux/utime.h>
/* "a" and "b" are pointers. 
 * Are equal if bot are NULL OR if both
 * are not NULL and have the same value. */ 
#define compare_simple_type(a,b)   ( (((a) == NULL) && ((b) == NULL)) || ( ((a) != NULL) && ((b) != NULL) && (*(a) == *(b)) ) )
#define compare_loff_t(a,b)       compare_simple_type(a,b)
#define compare_socklen_t(a,b)    compare_simple_type(a,b)
#define compare_time_t(a,b)       compare_simple_type(a,b)

#define compare_mem(a,b,n)      ( ((a) == NULL && (b) == NULL) || (((a) != NULL) && ((b) != NULL) && (memcmp(a,b,n) == 0)) )
#define compare_string(a,b)     ( ((a) == NULL && (b) == NULL) || (((a) != NULL) && ((b) != NULL) &&  (strcmp(a, b) == 0)) )

int compare_struct_sockaddr(struct sockaddr *a, struct sockaddr *b);
int compare_struct_timespec(struct timespec *a, struct timespec *b);
int compare_struct_timeval(struct timeval *a, struct timeval *b);
int compare_struct_timex(struct timex *a, struct timex *b);
int compare_struct_timezone(struct timezone *a, struct timezone *b);
int compare_struct_utimbuf(struct utimbuf *a, struct utimbuf *b);


int compare_struct_stat64(struct stat64 *a, struct stat64 *b);
int compare_struct_statfs64(struct statfs64 *a, struct statfs64 *b);
int compare_struct_dirent64(struct dirent64 *a, struct dirent64 *b);
int compare_struct_utsname(struct utsname *a, struct utsname *b);

int compare_struct_flock(struct flock *a, struct flock *b);
#endif /* __TEST_TYPE_EQUALITY__ */
