/*   
 *   This is part of Remote System Call (RSC) Library.
 *
 *   aconv.h: Architecture conversion header file
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

#ifndef __ACONV_HEADER__
#define __ACONV_HEADER__

#include <assert.h>
#include <sys/types.h>
#ifndef __USE_LARGEFILE64
#define __USE_LARGEFILE64
#endif
#include <dirent.h>
#include <time.h>
#include <sys/time.h>
#include <linux/utime.h>
#include <sys/utsname.h>
#include <sys/timex.h>
#include <sys/vfs.h>
#include <sys/stat.h>
#include <sys/socket.h>

#define ACONV_32BIT         0x20
#define ACONV_64BIT         0x40
#define ACONV_BITNUM_MASK  0xF0

#define ACONV_LITTLEE         0x01
#define ACONV_BIGE            0x02
#define ACONV_ENDIENESS_MASK  0x0F


enum arch {
  ACONV_ARCH_ERROR    = -1,
  ARCH_FIRST    = (ACONV_32BIT | ACONV_LITTLEE),
  ACONV_X86     = ARCH_FIRST,
  ACONV_X86_64  = (ACONV_64BIT | ACONV_LITTLEE),
  ACONV_PPC     = (ACONV_32BIT | ACONV_BIGE),
  ACONV_PPC_64  = (ACONV_64BIT | ACONV_BIGE),
  ARCH_LAST = ACONV_PPC_64
};

/* Return values */
#define   ACONV_OK           1
#define   ACONV_OK_SAMESIZE  2
#define   ACONV_UNNEC        3 
#define   ACONV_ERROR       -2
typedef int (* aconv_size_fun)(enum arch from, enum arch to);
/* typedef int (* aconv_fun)(void *d, enum arch from, enum arch to, void *p); */
typedef int (* aconv_fun)();

char *aconv_arch2str(enum arch arch);
enum arch aconv_get_host_arch();
/* Only long and pointers change from 32 to 64bit architectures */
int aconv_char_size(enum arch from, enum arch to);
int aconv_u_char_size(enum arch from, enum arch to);
int aconv_short_size(enum arch from, enum arch to);
int aconv_u_short_size(enum arch from, enum arch to);
int aconv_int_size(enum arch from, enum arch to);
int aconv_u_int_size(enum arch from, enum arch to);
int aconv_long_size(enum arch from, enum arch to);
int aconv_u_long_size(enum arch from, enum arch to);
int aconv_longlong_size(enum arch from, enum arch to);
int aconv_u_longlong_size(enum arch from, enum arch to);
int aconv_pointer_size(enum arch from, enum arch to);
int aconv_string_size(char *s, enum arch from, enum arch to);

int aconv_mode_t_size(enum arch from, enum arch to);
int aconv_loff_t_size(enum arch from, enum arch to);
int aconv_uid_t_size(enum arch from, enum arch to);
#define aconv___uid_t_size(from, to) aconv_uid_t_size((from), (to))
int aconv_gid_t_size(enum arch from, enum arch to);
#define aconv___gid_t_size(from, to) aconv_gid_t_size((from), (to))
int aconv_clockid_t_size(enum arch from, enum arch to);
int aconv___off64_t_size(enum arch from, enum arch to);
int aconv_socklen_t_size(enum arch from, enum arch to);
int aconv_size_t_size(enum arch from, enum arch to);
int aconv_off_t_size(enum arch from, enum arch to);
#define aconv___off_t_size(from, to) aconv_off_t_size((from), (to))
int aconv___ino64_t_size(enum arch from, enum arch to);
int aconv_sa_family_t_size(enum arch from, enum arch to);
int aconv_time_t_size(enum arch from, enum arch to);
#define aconv___time_t_size(from, to) aconv_time_t_size((from), (to))
int aconv_suseconds_t_size(enum arch from, enum arch to);
int aconv_array_size(enum arch from, enum arch to, int elnum, aconv_size_fun size_fun);
int aconv_struct_dirent64_size(enum arch from, enum arch to);
int aconv_struct_sockaddr_size(enum arch from, enum arch to);
int aconv_struct_timespec_size(enum arch from, enum arch to);
int aconv_struct_timeval_size(enum arch from, enum arch to);
int aconv_struct_timezone_size(enum arch from, enum arch to);
int aconv_struct_utimbuf_size(enum arch from, enum arch to);
int aconv_struct_utsname_size(enum arch from, enum arch to);
int aconv_struct_timex_size(enum arch from, enum arch to);
int aconv_struct_statfs64_size(enum arch from, enum arch to);
int aconv_struct_stat64_size(enum arch from, enum arch to);
#define aconv___dev_t_size(from, to)  aconv_u_longlong_size((from), (to))
#define aconv___ino_t_size(from, to)  aconv_u_long_size((from), (to))
#define aconv___mode_t_size(from, to) aconv_u_int_size((from), (to))
#define aconv___nlink_t_size(from, to) aconv_u_long_size((from), (to))
#define aconv___blksize_t_size(from, to) aconv_long_size((from), (to))
#define aconv___blkcnt64_t_size(from, to) aconv_longlong_size((from), (to))
int aconv_bytes_size(int bytenum, enum arch from, enum arch to);



/************************/
/* Conversion functions */
/************************/
int aconv_char(char *c, enum arch from, enum arch to, void *p);
int aconv_u_char(unsigned char *c, enum arch from, enum arch to, void *p);
int aconv_int(int *i, enum arch from, enum arch to, void *p);
int aconv_u_int(unsigned int *i, enum arch from, enum arch to, void *p);
int aconv_short(short *i, enum arch from, enum arch to, void *p);
int aconv_u_short(unsigned short *i, enum arch from, enum arch to, void *p);
int aconv_long(long *l, enum arch from, enum arch to, void *p);
int aconv_u_long(unsigned long *l, enum arch from, enum arch to, void *p);
int aconv_longlong(long long* l, enum arch from, enum arch to, void *p);
int aconv_u_longlong(unsigned long long *l, enum arch from, enum arch to, void *p);
int aconv_pointer(void *p, enum arch from, enum arch to, void *dest);
int aconv_string(char *s, enum arch from, enum arch to, void *p);

int aconv_mode_t(mode_t *n, enum arch from, enum arch to, void *p);
int aconv_loff_t(loff_t *n, enum arch from, enum arch to, void *p);
int aconv_uid_t(uid_t *n, enum arch from, enum arch to, void *p);
#define aconv___uid_t(n, from, to, p) aconv_uid_t((uid_t *)(n), (from), (to), (p))
int aconv_gid_t(gid_t *n, enum arch from, enum arch to, void *p);
#define aconv___gid_t(n, from, to, p) aconv_gid_t((gid_t *)(n), (from), (to), (p))
int aconv___ino64_t(__ino64_t *n, enum arch from, enum arch to, void *p);
int aconv_sa_family_t(sa_family_t *n, enum arch from, enum arch to, void *p);
int aconv_time_t(time_t *n, enum arch from, enum arch to, void *p);
#define aconv___time_t(n, from, to, p)  aconv_time_t((time_t *)(n), (from), (to), (p))
int aconv_suseconds_t(suseconds_t *n, enum arch from, enum arch to, void *p);
int aconv_clockid_t(clockid_t *n, enum arch from, enum arch to, void *p);
int aconv___off64_t(__off64_t *n, enum arch from, enum arch to, void *p);
int aconv_socklen_t(socklen_t *n, enum arch from, enum arch to, void *p);
int aconv_size_t(size_t *n, enum arch from, enum arch to, void *p);
int aconv_off_t(off_t *n, enum arch from, enum arch to, void *p);
#define aconv___off_t(n, from, to, p)  aconv_off_t((off_t)(n), (from), (to), (p))
int aconv_array(void *a, enum arch from, enum arch to, int elnum, void *p, 
    aconv_size_fun size_fun, aconv_fun aconv_fun);

#define aconv___dev_t(n, from, to, p)  aconv_u_longlong((n), (from), (to), (p))
#define aconv___ino_t(n, from, to, p)  aconv_u_long((n), (from), (to), (p))
#define aconv___mode_t(n, from, to, p) aconv_u_int((n), (from), (to), (p))
#define aconv___nlink_t(n, from, to, p) aconv_u_long((n), (from), (to), (p))
#define aconv___blksize_t(n, from, to, p) aconv_long((n), (from), (to), (p))
#define aconv___blkcnt64_t(n, from, to, p) aconv_longlong((n), (from), (to), (p))


int aconv_struct_dirent64(struct dirent64 *d, enum arch from, enum arch to, void *p);
int aconv_struct_sockaddr(struct sockaddr *s, enum arch from, enum arch to, void *p);
int aconv_struct_timespec(struct timespec *t, enum arch from, enum arch to, void *p);
int aconv_struct_timeval(struct timeval *t, enum arch from, enum arch to, void *p);
int aconv_struct_timezone(struct timezone *t, enum arch from, enum arch to, void *p);
int aconv_struct_utimbuf(struct utimbuf *t, enum arch from, enum arch to, void *p);
int aconv_struct_utsname(struct utsname *t, enum arch from, enum arch to, void *p);
int aconv_struct_timex(struct timex *t, enum arch from, enum arch to, void *p);
int aconv_struct_statfs64(struct statfs64 *s, enum arch from, enum arch to, void *p);
int aconv_struct_stat64(struct stat64 *s, enum arch from, enum arch to, void *p);
int aconv_bytes(void *b, enum arch from, enum arch to, void *p, int bytenum);

#endif /* __ACONV_HEADER__ */
