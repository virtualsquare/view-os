/*   
 *   This is part of Remote System Call (RSC) Library.
 *
 *   type_equality.c: functions to test the equality of two variables
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

#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#ifndef __USE_LARGEFILE64
#define __USE_LARGEFILE64
#endif
#include <sys/statfs.h>
#include <sys/stat.h>
#include <sys/timex.h>
#include <sys/utsname.h>
#include <dirent.h>
#include "type_equality.h"

int compare_struct_sockaddr(struct sockaddr *a, struct sockaddr *b) {
  if(a == NULL && b == NULL)
    return 1;
  if(a == NULL || b == NULL)
    return 0;
  return (
       (a->sa_family == b->sa_family) &&
       (memcmp(a->sa_data, b->sa_data, 14 * sizeof(char)) == 0)
      );
}

int compare_struct_statfs64(struct statfs64 *a, struct statfs64 *b) {
  if(a == NULL && b ==NULL)
    return 1;
  if(a == NULL || b == NULL)
    return 0;

  return (
			(b->f_type == a->f_type) &&
			(b->f_bsize == a->f_bsize) &&
			(b->f_blocks == a->f_blocks) &&
			(b->f_bfree == a->f_bfree) &&
			(b->f_bavail == a->f_bavail) &&
			(b->f_files == a->f_files) &&
			(b->f_ffree == a->f_ffree) &&
			/* (b->f_fsid == a->f_fsid) && */
			(b->f_namelen == a->f_namelen) &&
			(b->f_frsize == a->f_frsize)
      );
}

int compare_struct_timespec(struct timespec *a, struct timespec *b) {
  if(a == NULL && b ==NULL)
    return 1;
  if(a == NULL || b == NULL)
    return 0;
  return (
      (a->tv_sec == b->tv_sec) &&
      (a->tv_nsec == b->tv_nsec)
 );
}

int compare_struct_timeval(struct timeval *a, struct timeval *b) {
  if(a == NULL && b ==NULL)
    return 1;
  if(a == NULL || b == NULL)
    return 0;
  return (
      (a->tv_sec == b->tv_sec) &&
      (a->tv_usec == b->tv_usec)
      );
}

int compare_struct_timex(struct timex *a, struct timex *b) {
  if(a == NULL && b ==NULL)
    return 1;
  if(a == NULL || b == NULL)
    return 0;
  return (
		(b->modes == a->modes) &&
		(b->offset == a->offset) &&
		(b->freq == a->freq) &&
		(b->maxerror == a->maxerror) &&
		(b->esterror == a->esterror) &&
		(b->status == a->status) &&
		(b->constant == a->constant) &&
		(b->precision == a->precision) &&
		(b->tolerance == a->tolerance) &&
    compare_struct_timeval(&b->time, &a->time) &&
		(b->tick == a->tick)
    );
}

int compare_struct_timezone(struct timezone *a, struct timezone *b) {
  if(a == NULL && b ==NULL)
    return 1;
  if(a == NULL || b == NULL)
    return 0;
  return (
       (a->tz_minuteswest == b->tz_minuteswest) &&
       (a->tz_dsttime == b->tz_dsttime)
      );
}

int compare_struct_utimbuf(struct utimbuf *a, struct utimbuf *b) {
  if(a == NULL && b ==NULL)
    return 1;
  if(a == NULL || b == NULL)
    return 0;

  return (
    (a->actime == b->actime) &&
    (a->modtime == b->modtime));
}

int compare_struct_stat64(struct stat64 *a, struct stat64 *b) {
  if(a == NULL && b ==NULL)
    return 1;
  if(a == NULL || b == NULL)
    return 0;

  return(
		(a->st_dev == b->st_dev) &&
		(a->st_ino == b->st_ino) &&
		(a->st_mode == b->st_mode) &&
		(a->st_nlink == b->st_nlink) &&
		(a->st_uid == b->st_uid) &&
		(a->st_gid == b->st_gid) &&
		(a->st_rdev == b->st_rdev) &&
		(a->st_size == b->st_size) &&
		(a->st_atime == b->st_atime) &&
		(a->st_mtime == b->st_mtime) &&
		(a->st_ctime == b->st_ctime) &&
		(a->st_blksize == b->st_blksize) &&
		(a->st_blocks == b->st_blocks));
}

int compare_struct_dirent64(struct dirent64 *a, struct dirent64 *b) {
  if(a == NULL && b ==NULL)
    return 1;
  if(a == NULL || b == NULL)
    return 0;
  
  return (
    (a->d_ino == b->d_ino) &&
    (a->d_off == b->d_off) &&
    (a->d_reclen == b->d_reclen) &&
    (a->d_type == b->d_type) &&
    (strcmp(a->d_name, b->d_name) == 0));
}

int compare_struct_utsname(struct utsname *a, struct utsname *b) {
  if(a == NULL && b ==NULL)
    return 1;
  if(a == NULL || b == NULL)
    return 0;

  return (
    (strcmp(a->sysname, b->sysname) == 0) &&
    (strcmp(a->nodename, b->nodename) == 0) &&
    (strcmp(a->release, b->release) == 0) &&
    (strcmp(a->version, b->version) == 0) &&
    (strcmp(a->machine, b->machine) == 0));
}
int compare_struct_flock(struct flock *a, struct flock *b) {
  if(a == NULL && b ==NULL)
    return 1;
  if(a == NULL || b == NULL)
    return 0;

  return (
		(a->l_type == b->l_type) &&
		(a->l_whence == b->l_whence) &&
		(a->l_start == b->l_start) &&
		(a->l_len == b->l_len) &&
		(a->l_pid == b->l_pid));
}

