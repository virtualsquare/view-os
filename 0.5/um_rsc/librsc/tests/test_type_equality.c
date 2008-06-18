/*   
 *   This is part of Remote System Call (RSC) Library.
 *
 *   test_type_equality.c: tests of type equality functions
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
#include <string.h>
#include <assert.h>
#include <linux/types.h>
#include <sys/un.h>
#include <sys/statfs.h>
#include <netinet/in.h>

#include "type_equality.h"

static void test_compare_simple_types(void)
{
  int *av, *bv;
  int ai, bi;
  loff_t aloff, bloff;
  socklen_t aslen, bslen;
  time_t at, bt;

  av = bv = NULL;
  assert(compare_simple_type(av, bv));
  ai = bi = 10;
  assert(compare_simple_type(&ai, &bi));
  bi = 11;
  assert(!compare_simple_type(&ai, &bi));

  aloff = bloff = 10;
  assert(compare_simple_type(&aloff, &bloff));
  bloff = 2;
  assert(!compare_simple_type(&aloff, &bloff));

  aslen = bslen = 10;
  assert(compare_simple_type(&aslen, &bslen));
  bslen = 3;
  assert(!compare_simple_type(&aslen, &bslen));
  
  at = bt = 10;
  assert(compare_simple_type(&at, &bt));
  bt = 4;
  assert(!compare_simple_type(&at, &bt));
  

}


static void test_compare_mem(void)
{
  int a[5] = {1,2,3,4,5}; 
  int b[5] = {1,2,3,4,5};
  int c[5] = {1,2,3,4,10};

  assert(compare_mem(a,b,(sizeof(int) * 5)));
  assert(!compare_mem(a,c,(sizeof(int) * 5)));
}


static void test_compare_string(void)
{
  char *s1 = "Hello world!";
  char *s2 = "Hello world!";
  char *s3 = "Hello WORLD!";
  char *s4 = "Goodbye world!";
  assert(compare_string(s1,s2));
  assert(!compare_string(s1,s3));
  assert(!compare_string(s1,s4));
}


static void test_compare_struct_sockaddr(void)
{
  struct sockaddr_in a, b, c;
  struct sockaddr_un d;
  bzero(&a, sizeof(struct sockaddr));
  bzero(&b, sizeof(struct sockaddr));

  a.sin_family      = AF_INET;
  a.sin_addr.s_addr = htonl(INADDR_ANY);
  a.sin_port        = htons(9000);
  
  b.sin_family      = AF_INET;
  b.sin_addr.s_addr = htonl(INADDR_ANY);
  b.sin_port        = htons(9000);

  assert(compare_struct_sockaddr((struct sockaddr*)&a, (struct sockaddr*)&b));
  
  assert(compare_struct_sockaddr(NULL, NULL));
  assert(!compare_struct_sockaddr((struct sockaddr*)&a, NULL));
  assert(!compare_struct_sockaddr(NULL, (struct sockaddr*)&b));

  bzero(&c, sizeof(struct sockaddr));
  c.sin_family      = AF_INET;
  c.sin_addr.s_addr = htonl(INADDR_ANY);
  c.sin_port        = htons(6543);
  assert(!compare_struct_sockaddr((struct sockaddr*)&a, (struct sockaddr*)&c));
  
  bzero(&d, sizeof(struct sockaddr));
  d.sun_family      = AF_UNIX;
  strcpy(d.sun_path, "/tmp/");
  assert(!compare_struct_sockaddr((struct sockaddr*)&a, (struct sockaddr*)&d));
  
  c.sin_family      = AF_INET;
  c.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  c.sin_port        = htons(9000);
  assert(!compare_struct_sockaddr((struct sockaddr*)&a, (struct sockaddr*)&c));
}


static void test_compare_struct_timespec(void)
{
  struct timespec a, b, c;
  a.tv_sec  = b.tv_sec  = 10;
  a.tv_nsec = b.tv_nsec = 20;

  assert(compare_struct_timespec(&a, &b));
  
  assert(compare_struct_timespec(NULL, NULL));
  assert(!compare_struct_timespec(&a, NULL));
  assert(!compare_struct_timespec(NULL, &b));
  
  c.tv_sec  = 10;
  c.tv_nsec = 444;
  assert(!compare_struct_timespec(&a, &c));

  c.tv_sec  = 33;
  c.tv_nsec = 20;
  assert(!compare_struct_timespec(&a, &c));

  c.tv_sec  = 33;
  c.tv_nsec = 444;
  assert(!compare_struct_timespec(&a, &c));
}


static void test_compare_struct_timeval(void)
{
  struct timeval a, b, c;
  a.tv_sec  = b.tv_sec  = 10;
  a.tv_usec = b.tv_usec = 20;
  assert(compare_struct_timeval(&a, &b));
  
  assert(compare_struct_timeval(NULL, NULL));
  assert(!compare_struct_timeval(&a, NULL));
  assert(!compare_struct_timeval(NULL, &b));

  c.tv_sec  = 10;
  c.tv_usec = 44;
  assert(!compare_struct_timeval(&a, &c));

  c.tv_sec  = 33;
  c.tv_usec = 20;
  assert(!compare_struct_timeval(&a, &c));

  c.tv_sec  = 33;
  c.tv_usec = 44;
  assert(!compare_struct_timeval(&a, &c));
}


static void test_compare_struct_timex(void)
{
  struct timex a, b, c;

	a.modes		  =	b.modes		  = 0;
	a.offset		=	b.offset	  = 1;
	a.freq		  =	b.freq		  = 2;
	a.maxerror	=	b.maxerror	= 3;
	a.esterror	=	b.esterror	= 4;
	a.status		=	b.status		= 5;
	a.constant	=	b.constant	= 6;
	a.precision	=	b.precision	= 7;
	a.tolerance	=	b.tolerance	= 8;
	a.time.tv_sec   =	b.time.tv_sec = 50;
	a.time.tv_usec  =	b.time.tv_usec = 60;
	a.tick		  =	b.tick		  = 10;
  assert(compare_struct_timex(&a, &b));
  
  assert(compare_struct_timex(NULL, NULL));
  assert(!compare_struct_timex(&a, NULL));
  assert(!compare_struct_timex(NULL, &b));
	
  c.modes		  = 100;
	c.offset		= 1;
	c.freq		  = 2;
	c.maxerror	= 3;
	c.esterror	= 4;
	c.status		= 5;
	c.constant	= 6;
	c.precision	= 7;
	c.tolerance	= 8;
	c.time.tv_sec   =	50;
	c.time.tv_usec  =	60;
	c.tick		  = 10;
  assert(!compare_struct_timex(&a, &c));

  c.modes		  = 0;
	c.offset		= 100;
	c.freq		  = 2;
	c.maxerror	= 3;
	c.esterror	= 4;
	c.status		= 5;
	c.constant	= 6;
	c.precision	= 7;
	c.tolerance	= 8;
	c.time.tv_sec   =	50;
	c.time.tv_usec  =	60;
	c.tick		  = 10;
  assert(!compare_struct_timex(&a, &c));

  c.modes		  = 0;
	c.offset		= 1;
	c.freq		  = 200;
	c.maxerror	= 3;
	c.esterror	= 4;
	c.status		= 5;
	c.constant	= 6;
	c.precision	= 7;
	c.tolerance	= 8;
	c.time.tv_sec   =	50;
	c.time.tv_usec  =	60;
	c.tick		  = 10;
  assert(!compare_struct_timex(&a, &c));

  c.modes		  = 0;
	c.offset		= 1;
	c.freq		  = 2;
	c.maxerror	= 300;
	c.esterror	= 4;
	c.status		= 5;
	c.constant	= 6;
	c.precision	= 7;
	c.tolerance	= 8;
	c.time.tv_sec   =	50;
	c.time.tv_usec  =	60;
	c.tick		  = 10;
  assert(!compare_struct_timex(&a, &c));

  c.modes		  = 0;
	c.offset		= 1;
	c.freq		  = 2;
	c.maxerror	= 3;
	c.esterror	= 400;
	c.status		= 5;
	c.constant	= 6;
	c.precision	= 7;
	c.tolerance	= 8;
	c.time.tv_sec   =	50;
	c.time.tv_usec  =	60;
	c.tick		  = 10;
  assert(!compare_struct_timex(&a, &c));

  c.modes		  = 0;
	c.offset		= 1;
	c.freq		  = 2;
	c.maxerror	= 3;
	c.esterror	= 4;
	c.status		= 500;
	c.constant	= 6;
	c.precision	= 7;
	c.tolerance	= 8;
	c.time.tv_sec   =	50;
	c.time.tv_usec  =	60;
	c.tick		  = 10;
  assert(!compare_struct_timex(&a, &c));

  c.modes		  = 0;
	c.offset		= 1;
	c.freq		  = 2;
	c.maxerror	= 3;
	c.esterror	= 4;
	c.status		= 5;
	c.constant	= 600;
	c.precision	= 7;
	c.tolerance	= 8;
	c.time.tv_sec   =	50;
	c.time.tv_usec  =	60;
	c.tick		  = 10;
  assert(!compare_struct_timex(&a, &c));

  c.modes		  = 0;
	c.offset		= 1;
	c.freq		  = 2;
	c.maxerror	= 3;
	c.esterror	= 4;
	c.status		= 5;
	c.constant	= 6;
	c.precision	= 700;
	c.tolerance	= 8;
	c.time.tv_sec   =	50;
	c.time.tv_usec  =	60;
	c.tick		  = 10;
  assert(!compare_struct_timex(&a, &c));

  c.modes		  = 0;
	c.offset		= 1;
	c.freq		  = 2;
	c.maxerror	= 3;
	c.esterror	= 4;
	c.status		= 5;
	c.constant	= 6;
	c.precision	= 7;
	c.tolerance	= 800;
	c.time.tv_sec   =	50;
	c.time.tv_usec  =	60;
	c.tick		  = 10;
  assert(!compare_struct_timex(&a, &c));

  c.modes		  = 0;
	c.offset		= 1;
	c.freq		  = 2;
	c.maxerror	= 3;
	c.esterror	= 4;
	c.status		= 5;
	c.constant	= 6;
	c.precision	= 7;
	c.tolerance	= 8;
	c.time.tv_sec   =	999;
	c.time.tv_usec  =	60;
	c.tick		  = 10;
  assert(!compare_struct_timex(&a, &c));

  c.modes		  = 0;
	c.offset		= 1;
	c.freq		  = 2;
	c.maxerror	= 3;
	c.esterror	= 4;
	c.status		= 5;
	c.constant	= 6;
	c.precision	= 7;
	c.tolerance	= 8;
	c.time.tv_sec   =	50;
	c.time.tv_usec  =	60;
	c.tick		  = 999;
  assert(!compare_struct_timex(&a, &c));

}



static void test_compare_struct_timezone(void)
{
  struct timezone a, b, c;
  a.tz_minuteswest  = b.tz_minuteswest  = 2;
  a.tz_dsttime      = b.tz_dsttime      = 3;
  assert(compare_struct_timezone(&a, &b));
  
  assert(compare_struct_timezone(NULL, NULL));
  assert(!compare_struct_timezone(&a, NULL));
  assert(!compare_struct_timezone(NULL, &b));
  
  c.tz_minuteswest  = 2;
  c.tz_dsttime      = 55;
  assert(!compare_struct_timezone(&a, &c));

  c.tz_minuteswest  = 11;
  c.tz_dsttime      = 3;
  assert(!compare_struct_timezone(&a, &c));

  c.tz_minuteswest  = 11;
  c.tz_dsttime      = 55;
  assert(!compare_struct_timezone(&a, &c));

}



static void test_compare_struct_utimbuf(void)
{
  struct utimbuf a, b, c;
  a.actime  = b.actime  = 10;
  a.modtime = b.modtime = 20;
  assert(compare_struct_utimbuf(&a, &b));
  assert(compare_struct_utimbuf(NULL, NULL));
  assert(!compare_struct_utimbuf(&a, NULL));
  assert(!compare_struct_utimbuf(NULL, &b));
  

  c.actime  = 10;
  c.modtime = 33;
  assert(!compare_struct_utimbuf(&a, &c));

  c.actime  = 44;
  c.modtime = 20;
  assert(!compare_struct_utimbuf(&a, &c));

  c.actime  = 44;
  c.modtime = 33;
  assert(!compare_struct_utimbuf(&a, &c));
}


static void test_compare_struct_stat64(void)
{
  struct stat64 a, b;
	a.st_dev = b.st_dev = 1;
	a.st_ino = b.st_ino = 2;
	a.st_mode = b.st_mode = 3;
	a.st_nlink = b.st_nlink = 4;
	a.st_uid = b.st_uid = 5;
	a.st_gid = b.st_gid = 6;
	a.st_rdev = b.st_rdev = 7;
	a.st_size = b.st_size = 8;
	a.st_atime = b.st_atime = 9;
	a.st_mtime = b.st_mtime = 10;
	a.st_ctime = b.st_ctime = 11;
	a.st_blksize = b.st_blksize = 12;
	a.st_blocks = b.st_blocks = 13;


  assert(compare_struct_stat64(&a, &b));
  assert(compare_struct_stat64(NULL, NULL));
  assert(!compare_struct_stat64(&a, NULL));
  assert(!compare_struct_stat64(NULL, &b));
  
	b.st_dev = 100;
	b.st_ino = 2;
	b.st_mode = 3;
	b.st_nlink = 4;
	b.st_uid = 5;
	b.st_gid = 6;
	b.st_rdev = 7;
	b.st_size = 8;
	b.st_atime = 9;
	b.st_mtime = 10;
	b.st_ctime = 11;
	b.st_blksize = 12;
	b.st_blocks = 13;
  assert(!compare_struct_stat64(&a, &b));

	b.st_dev = 1;
	b.st_ino = 200;
	b.st_mode = 3;
	b.st_nlink = 4;
	b.st_uid = 5;
	b.st_gid = 6;
	b.st_rdev = 7;
	b.st_size = 8;
	b.st_atime = 9;
	b.st_mtime = 10;
	b.st_ctime = 11;
	b.st_blksize = 12;
	b.st_blocks = 13;
  assert(!compare_struct_stat64(&a, &b));

	b.st_dev = 1;
	b.st_ino = 2;
	b.st_mode = 300;
	b.st_nlink = 4;
	b.st_uid = 5;
	b.st_gid = 6;
	b.st_rdev = 7;
	b.st_size = 8;
	b.st_atime = 9;
	b.st_mtime = 10;
	b.st_ctime = 11;
	b.st_blksize = 12;
	b.st_blocks = 13;
  assert(!compare_struct_stat64(&a, &b));

	b.st_dev = 1;
	b.st_ino = 2;
	b.st_mode = 3;
	b.st_nlink = 400;
	b.st_uid = 5;
	b.st_gid = 6;
	b.st_rdev = 7;
	b.st_size = 8;
	b.st_atime = 9;
	b.st_mtime = 10;
	b.st_ctime = 11;
	b.st_blksize = 12;
	b.st_blocks = 13;
  assert(!compare_struct_stat64(&a, &b));

	b.st_dev = 1;
	b.st_ino = 2;
	b.st_mode = 3;
	b.st_nlink = 4;
	b.st_uid = 500;
	b.st_gid = 6;
	b.st_rdev = 7;
	b.st_size = 8;
	b.st_atime = 9;
	b.st_mtime = 10;
	b.st_ctime = 11;
	b.st_blksize = 12;
	b.st_blocks = 13;
  assert(!compare_struct_stat64(&a, &b));

	b.st_dev = 1;
	b.st_ino = 2;
	b.st_mode = 3;
	b.st_nlink = 4;
	b.st_uid = 5;
	b.st_gid = 600;
	b.st_rdev = 7;
	b.st_size = 8;
	b.st_atime = 9;
	b.st_mtime = 10;
	b.st_ctime = 11;
	b.st_blksize = 12;
	b.st_blocks = 13;
  assert(!compare_struct_stat64(&a, &b));

	b.st_dev = 1;
	b.st_ino = 2;
	b.st_mode = 3;
	b.st_nlink = 4;
	b.st_uid = 5;
	b.st_gid = 6;
	b.st_rdev = 700;
	b.st_size = 8;
	b.st_atime = 9;
	b.st_mtime = 10;
	b.st_ctime = 11;
	b.st_blksize = 12;
	b.st_blocks = 13;
  assert(!compare_struct_stat64(&a, &b));

	b.st_dev = 1;
	b.st_ino = 2;
	b.st_mode = 3;
	b.st_nlink = 4;
	b.st_uid = 5;
	b.st_gid = 6;
	b.st_rdev = 7;
	b.st_size = 800;
	b.st_atime = 9;
	b.st_mtime = 10;
	b.st_ctime = 11;
	b.st_blksize = 12;
	b.st_blocks = 13;
  assert(!compare_struct_stat64(&a, &b));

	b.st_dev = 1;
	b.st_ino = 2;
	b.st_mode = 3;
	b.st_nlink = 4;
	b.st_uid = 5;
	b.st_gid = 6;
	b.st_rdev = 7;
	b.st_size = 8;
	b.st_atime = 900;
	b.st_mtime = 10;
	b.st_ctime = 11;
	b.st_blksize = 12;
	b.st_blocks = 13;
  assert(!compare_struct_stat64(&a, &b));

	b.st_dev = 1;
	b.st_ino = 2;
	b.st_mode = 3;
	b.st_nlink = 4;
	b.st_uid = 5;
	b.st_gid = 6;
	b.st_rdev = 7;
	b.st_size = 8;
	b.st_atime = 9;
	b.st_mtime = 1000;
	b.st_ctime = 11;
	b.st_blksize = 12;
	b.st_blocks = 13;
  assert(!compare_struct_stat64(&a, &b));

	b.st_dev = 1;
	b.st_ino = 2;
	b.st_mode = 3;
	b.st_nlink = 4;
	b.st_uid = 5;
	b.st_gid = 6;
	b.st_rdev = 7;
	b.st_size = 8;
	b.st_atime = 9;
	b.st_mtime = 10;
	b.st_ctime = 1100;
	b.st_blksize = 12;
	b.st_blocks = 13;
  assert(!compare_struct_stat64(&a, &b));

	b.st_dev = 1;
	b.st_ino = 2;
	b.st_mode = 3;
	b.st_nlink = 4;
	b.st_uid = 5;
	b.st_gid = 6;
	b.st_rdev = 7;
	b.st_size = 8;
	b.st_atime = 9;
	b.st_mtime = 10;
	b.st_ctime = 11;
	b.st_blksize = 1200;
	b.st_blocks = 13;
  assert(!compare_struct_stat64(&a, &b));

	b.st_dev = 1;
	b.st_ino = 2;
	b.st_mode = 3;
	b.st_nlink = 4;
	b.st_uid = 5;
	b.st_gid = 6;
	b.st_rdev = 7;
	b.st_size = 8;
	b.st_atime = 9;
	b.st_mtime = 10;
	b.st_ctime = 11;
	b.st_blksize = 12;
	b.st_blocks = 1300;
  assert(!compare_struct_stat64(&a, &b));

}


static void test_compare_struct_dirent64(void)
{
  struct dirent64 a, b;
	a.d_ino = b.d_ino = 1;
	a.d_off = b.d_off = 2;
	a.d_reclen = b.d_reclen = 3;
	a.d_type = b.d_type = 4;
	a.d_name[0] = b.d_name[0] = '/';
	a.d_name[1] = b.d_name[1] = 't';
	a.d_name[2] = b.d_name[2] = 'm';
	a.d_name[3] = b.d_name[3] = 'p';
	a.d_name[4] = b.d_name[4] = '/';
	a.d_name[5] = b.d_name[5] = '\0';

  assert(compare_struct_dirent64(&a, &b)); 
  
  assert(compare_struct_dirent64(NULL, NULL));
  assert(!compare_struct_dirent64(&a, NULL));
  assert(!compare_struct_dirent64(NULL, &b));
  
  b.d_ino = 10;
  b.d_off = 2;
  b.d_reclen = 3;
  b.d_type = 4;
  b.d_name[0] = '/';
  b.d_name[1] = 't';
  b.d_name[2] = 'm';
  b.d_name[3] = 'p';
  b.d_name[4] = '/';
	b.d_name[5] = '\0';
  assert(!compare_struct_dirent64(&a, &b));

  b.d_ino = 1;
  b.d_off = 20;
  b.d_reclen = 3;
  b.d_type = 4;
  b.d_name[0] = '/';
  b.d_name[1] = 't';
  b.d_name[2] = 'm';
  b.d_name[3] = 'p';
  b.d_name[4] = '/';
	b.d_name[5] = '\0';
  assert(!compare_struct_dirent64(&a, &b));

  b.d_ino = 1;
  b.d_off = 2;
  b.d_reclen = 30;
  b.d_type = 4;
  b.d_name[0] = '/';
  b.d_name[1] = 't';
  b.d_name[2] = 'm';
  b.d_name[3] = 'p';
  b.d_name[4] = '/';
	b.d_name[5] = '\0';
  assert(!compare_struct_dirent64(&a, &b));

  b.d_ino = 1;
  b.d_off = 2;
  b.d_reclen = 3;
  b.d_type = 40;
  b.d_name[0] = '/';
  b.d_name[1] = 't';
  b.d_name[2] = 'm';
  b.d_name[3] = 'p';
  b.d_name[4] = '/';
	b.d_name[5] = '\0';
  assert(!compare_struct_dirent64(&a, &b));

  b.d_ino = 1;
  b.d_off = 2;
  b.d_reclen = 3;
  b.d_type = 4;
  b.d_name[0] = '/';
  b.d_name[1] = 's';
  b.d_name[2] = 'r';
  b.d_name[3] = 'c';
  b.d_name[4] = '/';
	b.d_name[5] = '\0';
  assert(!compare_struct_dirent64(&a, &b));

}


static void test_compare_struct_utsname(void)
{
  struct utsname a, b;

	strcpy(a.sysname, "sysname");
	strcpy(a.nodename, "nodename");
	strcpy(a.release, "release");
	strcpy(a.version, "1");
	strcpy(a.machine, "x86");

	strcpy(b.sysname, "sysname");
	strcpy(b.nodename, "nodename");
	strcpy(b.release, "release");
	strcpy(b.version, "1");
	strcpy(b.machine, "x86");

  assert(compare_struct_utsname(&a, &b)); 
  
  assert(compare_struct_utsname(NULL, NULL));
  assert(!compare_struct_utsname(&a, NULL));
  assert(!compare_struct_utsname(NULL, &b));
  
  {
    struct utsname c;

    strcpy(c.sysname, "different");
	  strcpy(c.nodename, "nodename");
	  strcpy(c.release, "release");
	  strcpy(c.version, "1");
	  strcpy(c.machine, "x86");
    assert(!compare_struct_utsname(&a, &c));
  }

  {
    struct utsname c;

    strcpy(c.sysname, "sysname");
	  strcpy(c.nodename, "different");
	  strcpy(c.release, "release");
	  strcpy(c.version, "1");
	  strcpy(c.machine, "x86");
    assert(!compare_struct_utsname(&a, &c));
  }

  {
    struct utsname c;

    strcpy(c.sysname, "sysname");
	  strcpy(c.nodename, "nodename");
	  strcpy(c.release, "different");
	  strcpy(c.version, "1");
	  strcpy(c.machine, "x86");
    assert(!compare_struct_utsname(&a, &c));
  }

  {
    struct utsname c;

    strcpy(c.sysname, "sysname");
	  strcpy(c.nodename, "nodename");
	  strcpy(c.release, "release");
	  strcpy(c.version, "100");
	  strcpy(c.machine, "x86");
    assert(!compare_struct_utsname(&a, &c));
  }

  {
    struct utsname c;

    strcpy(c.sysname, "sysname");
	  strcpy(c.nodename, "nodename");
	  strcpy(c.release, "release");
	  strcpy(c.version, "1");
	  strcpy(c.machine, "x86_64");
    assert(!compare_struct_utsname(&a, &c));
  }

}


static void test_compare_struct_flock(void)
{
  struct flock f1, f2;
	f1.l_type   = f2.l_type   = 1;
	f1.l_whence = f2.l_whence = 2;
	f1.l_start  = f2.l_start  = 3;
	f1.l_len    = f2.l_len    = 4;
	f1.l_pid    = f2.l_pid    = 5;
  
  assert(compare_struct_flock(NULL, NULL));
  assert(compare_struct_flock(&f1, &f2));

  assert(!compare_struct_flock(&f1, NULL));
  assert(!compare_struct_flock(NULL, &f2));
  
	f2.l_type   = 111;
	f2.l_whence = 2;
	f2.l_start  = 3;
	f2.l_len    = 4;
	f2.l_pid    = 5;
  assert(!compare_struct_flock(&f1, &f2));
  
	f2.l_type   = 1;
	f2.l_whence = 222;
	f2.l_start  = 3;
	f2.l_len    = 4;
	f2.l_pid    = 5;
  assert(!compare_struct_flock(&f1, &f2));

	f2.l_type   = 1;
	f2.l_whence = 2;
	f2.l_start  = 333;
	f2.l_len    = 4;
	f2.l_pid    = 5;
  assert(!compare_struct_flock(&f1, &f2));
  
	f2.l_type   = 1;
	f2.l_whence = 2;
	f2.l_start  = 3;
	f2.l_len    = 444;
	f2.l_pid    = 5;
  assert(!compare_struct_flock(&f1, &f2));
  
	f2.l_type   = 1;
	f2.l_whence = 2;
	f2.l_start  = 3;
	f2.l_len    = 4;
	f2.l_pid    = 555;
  assert(!compare_struct_flock(&f1, &f2));
  
}


/****************************************************************/
/* AUXILIARY FUNCTIONS                                          */
/****************************************************************/
void test_type_equality(void)
{
  test_compare_simple_types();
  test_compare_mem();
  test_compare_string();
  test_compare_struct_sockaddr();
  test_compare_struct_timespec();
  test_compare_struct_timeval();
  test_compare_struct_timex();
  test_compare_struct_timezone();
  test_compare_struct_utimbuf();
  test_compare_struct_stat64();
  test_compare_struct_dirent64();
  test_compare_struct_utsname();
  test_compare_struct_flock();
}
