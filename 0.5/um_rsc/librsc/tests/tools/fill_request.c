/*   
 *   This is part of Remote System Call (RSC) Library.
 *
 *   fill_request.c: fill RSC request functions used by tests
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

#include "aconv.h"
#include "rsc_client.h"

#include <unistd.h>

#include <arpa/inet.h>
#include <string.h>

#include <errno.h>
#include <fcntl.h>
#include <linux/net.h>
#include <linux/unistd.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/timex.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/vfs.h>
#include <syscall.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "fill_request.h"



/* Fills a struct sockaddr_in and return it type-casted
 * to "struct sockaddr" */
struct sockaddr_in *fill_struct_sockaddr_in(void) {
  struct sockaddr_in *addr_in;

  addr_in = calloc(1, sizeof(struct sockaddr_in));
  assert(!(addr_in == NULL));

  addr_in->sin_family      = AF_INET;
  addr_in->sin_addr.s_addr = htonl(INADDR_ANY);
  addr_in->sin_port        = htons(9000);

  return addr_in;
}
  
char *fill_string(char *str) {
  char *path;
  if(str == NULL)
    str = "/tmp/";
  
  path = calloc(1, strlen(str) + 1);
  assert(!(path == NULL));

  strncpy(path, str, strlen(str) + 1);

  return path;
}

struct _llseek_req *fill__llseek_request(void)
{
  struct _llseek_req *request;
  loff_t *result;

  request = calloc(1, sizeof(struct _llseek_req));
  assert(!(request == NULL));

  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC__llseek);
  request->req_size = htonl(sizeof(struct _llseek_req));

  request->fd = 10;
  request->offset_high = 100;
  request->offset_low = 50;
  result = calloc(1, sizeof(loff_t));
  assert(!(result == NULL));
  request->result = result;
  request->whence = SEEK_SET;  
  

  return request;
}


struct accept_req *fill_accept_request(int addrlen_null)
{
  struct accept_req *request;
  socklen_t *addrlen;
  int size_addrlen;

  request = calloc(1, sizeof(struct accept_req));
  assert(!(request == NULL));

  request->addr = (struct sockaddr *)fill_struct_sockaddr_in();

  if(addrlen_null) {
    addrlen = NULL;
    size_addrlen = 0;
  } else {
    size_addrlen = sizeof(socklen_t);
    addrlen = calloc(2, size_addrlen);
    assert(!(addrlen == NULL));
    /* Fill the buffer */
    *addrlen = sizeof(struct sockaddr_in);
  }

  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_accept);
  request->req_size = htonl(sizeof(struct accept_req) + size_addrlen);

  request->sockfd = 10;
  request->addrlen = addrlen;  
  

  return request;
}


struct access_req *fill_access_request(int pathname_null)
{
  struct access_req *request;
  char *pathname;
  int size_pathname;

  request = calloc(1, sizeof(struct access_req));
  assert(!(request == NULL));
  
  if(pathname_null) {
    pathname = NULL;
    size_pathname = 0;
  } else {
    pathname = fill_string(NULL);
    size_pathname = (strlen(pathname) + 1); 
  }
  
  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_access);
  request->req_size = htonl(sizeof(struct access_req) + size_pathname);

  request->pathname = pathname;
  request->mode = R_OK;  
  

  return request;
}


struct adjtimex_req *fill_adjtimex_request(int buf_null)
{
  struct adjtimex_req *request;
  struct timex *buf;
  int size_buf;

  request = calloc(1, sizeof(struct adjtimex_req));
  assert(!(request == NULL));

  if(buf_null) {
    size_buf = 0;
    buf = NULL;
  } else {
    size_buf = sizeof(struct timex);
    buf = calloc(1, size_buf);
    assert(!(buf == NULL));
    /* Fill the buffer */
    /* update only the time offset (request->offset). Only the root can do it, 
    * normal users have to set 'modes' to 0. */
	  buf->modes = ADJ_OFFSET; 
	  buf->offset = 10;
	  buf->freq = 1;
	  buf->maxerror = 2;
	  buf->esterror = 3;
	  buf->status = 4;
	  buf->constant = 5;
	  buf->precision = 6;
	  buf->tolerance = 7;
	  buf->time.tv_sec = 10;
	  buf->time.tv_usec = 20;
	  buf->tick = 8;
  }

  request->buf = buf;
  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_adjtimex);
  request->req_size = htonl(sizeof(struct adjtimex_req) + size_buf);


  return request;
}

struct bind_req *fill_bind_request(int my_addr_null)
{
  struct bind_req *request;
  socklen_t size_my_addr;


  request = calloc(1, sizeof(struct bind_req));
  assert(!(request == NULL));

  if(my_addr_null) {
    request->my_addr = NULL;
    size_my_addr = 0;
  } else {
    request->my_addr = (struct sockaddr *)fill_struct_sockaddr_in();
    size_my_addr = sizeof(struct sockaddr_in);
  }

  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_bind);
  request->req_size = htonl(sizeof(struct bind_req) + size_my_addr);

  request->sockfd = 10;
  request->addrlen = size_my_addr;  
  

  return request;
}


struct chdir_req *fill_chdir_request(int path_null)
{
  struct chdir_req *request;
  char *path;
  int size_path;

  request = calloc(1, sizeof(struct chdir_req));
  assert(!(request == NULL));
  if(path_null) {
    path = NULL;
    size_path = 0;
  } else {
    path = fill_string(NULL);
    size_path = (strlen(path) + 1); 
  }

  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_chdir);
  request->req_size = htonl(sizeof(struct chdir_req) + size_path);

  request->path = path;  
  

  return request;
}


struct chmod_req *fill_chmod_request(int path_null)
{
  struct chmod_req *request;
  char *path;
  int size_path;

  request = calloc(1, sizeof(struct chmod_req));
  assert(!(request == NULL));

  if(path_null) {
    path = NULL;
    size_path = 0;
  } else {
    path = fill_string(NULL);
    size_path = (strlen(path) + 1);
  }

  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_chmod);
  request->req_size = htonl(sizeof(struct chmod_req) + size_path);

  request->path = path;
  request->mode = S_IRUSR || S_IWUSR;


  return request;
}


struct chown_req *fill_chown_request(int path_null)
{
  struct chown_req *request;
  char *path;
  int size_path;

  request = calloc(1, sizeof(struct chown_req));
  assert(!(request == NULL));
  
  if(path_null) {
    path = NULL;
    size_path = 0;
  } else {
    path = fill_string(NULL);
    size_path = (strlen(path) + 1);
  }

  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_chown);
  request->req_size = htonl(sizeof(struct chown_req) + size_path);

  request->path = path;
  request->owner = 0;
  request->group = 0;  
  

  return request;
}


struct chown32_req *fill_chown32_request(int path_null)
{
  struct chown32_req *request;
  char *path;
  int size_path;

  request = calloc(1, sizeof(struct chown32_req));
  assert(!(request == NULL));
  
  if(path_null) {
    path = NULL;
    size_path = 0;
  } else {
    path = fill_string(NULL);
    size_path = (strlen(path) + 1);
  }

  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_chown32);
  request->req_size = htonl(sizeof(struct chown32_req) + size_path);

  request->path = path;
  request->owner = 0;
  request->group = 0;  
  

  return request;
}

struct clock_getres_req *fill_clock_getres_request(void)
{
  struct clock_getres_req *request;

  request = calloc(1, sizeof(struct clock_getres_req));
  assert(!(request == NULL));

  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_clock_getres);
  request->req_size = htonl(sizeof(struct clock_getres_req));

  request->clk_id = 1;
  request->res = calloc(1, sizeof(struct timespec));  
  assert(!(request->res == NULL));
  

  return request;
}


struct clock_gettime_req *fill_clock_gettime_request(void)
{
  struct clock_gettime_req *request;

  request = calloc(1, sizeof(struct clock_gettime_req));
  assert(!(request == NULL));
  
  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_clock_gettime);
  request->req_size = htonl(sizeof(struct clock_gettime_req));

  request->clk_id = 1;
  request->tp = calloc(1, sizeof(struct timespec));  
  assert(!(request->tp == NULL));
  

  return request;
}


struct clock_settime_req *fill_clock_settime_request(int tp_null)
{
  struct clock_settime_req *request;
  struct timespec *tp;
  int size_tp;

  request = calloc(1, sizeof(struct clock_settime_req));
  assert(!(request == NULL));
  
  if(tp_null) {
    size_tp = 0;
    tp = NULL;
  } else {
    size_tp = sizeof(struct timespec);
    tp = calloc(1, size_tp);
    assert(!(tp == NULL));
    /* Fill the buffer */
    tp->tv_sec = 10;
    tp->tv_nsec = 10;
  }

  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_clock_settime);
  request->req_size = htonl(sizeof(struct clock_settime_req) + size_tp);

  request->clk_id = 1;
  request->tp = tp;  
  

  return request;
}


struct close_req *fill_close_request(void)
{
  struct close_req *request;

  request = calloc(1, sizeof(struct close_req));
  assert(!(request == NULL));
  
  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_close);
  request->req_size = htonl(sizeof(struct close_req));

  request->fd = 10;  
  

  return request;
}


struct connect_req *fill_connect_request(int serv_addr_null)
{
  struct connect_req *request;
  struct sockaddr *serv_addr;
  socklen_t size_serv_addr;

  request = calloc(1, sizeof(struct connect_req));
  assert(!(request == NULL));
  
  if(serv_addr_null) {
    size_serv_addr = 0;
    serv_addr = NULL;
  } else {
    size_serv_addr = sizeof(struct sockaddr_in);
    serv_addr = (struct sockaddr *)fill_struct_sockaddr_in();
  }

  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_connect);
  request->req_size = htonl(sizeof(struct connect_req) + size_serv_addr);

  request->sockfd = 10;
  request->serv_addr = serv_addr;
  request->addrlen = size_serv_addr;  
  

  return request;
}

struct dup_req *fill_dup_request(void)
{
  struct dup_req *request;
  
  request = calloc(1, sizeof(struct dup_req));
  assert(!(request == NULL));
  
  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_dup);
  request->req_size = htonl(sizeof(struct dup_req));

  request->oldfd = 10;  
  

  return request;
}


struct dup2_req *fill_dup2_request(void)
{
  struct dup2_req *request;

  request = calloc(1, sizeof(struct dup2_req));
  assert(!(request == NULL));
  
  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_dup2);
  request->req_size = htonl(sizeof(struct dup2_req));

  request->oldfd = 10;
  request->newfd = 11;  
  

  return request;
}


struct fchdir_req *fill_fchdir_request(void)
{
  struct fchdir_req *request;

  request = calloc(1, sizeof(struct fchdir_req));
  assert(!(request == NULL));
  
  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_fchdir);
  request->req_size = htonl(sizeof(struct fchdir_req));

  request->fd = 10;  
  

  return request;
}


struct fchmod_req *fill_fchmod_request(void)
{
  struct fchmod_req *request;

  request = calloc(1, sizeof(struct fchmod_req));
  assert(!(request == NULL));
  
  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_fchmod);
  request->req_size = htonl(sizeof(struct fchmod_req));

  request->fildes = 10;
  request->mode = S_IRGRP || S_IWGRP;
  

  return request;
}


struct fchown_req *fill_fchown_request(void)
{
  struct fchown_req *request;

  request = calloc(1, sizeof(struct fchown_req));
  assert(!(request == NULL));
  
  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_fchown);
  request->req_size = htonl(sizeof(struct fchown_req));

  request->fd = 10;
  request->owner = 0;
  request->group = 0;  
  

  return request;
}


struct fchown32_req *fill_fchown32_request(void)
{
  struct fchown32_req *request;

  request = calloc(1, sizeof(struct fchown32_req));
  assert(!(request == NULL));
  
  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_fchown32);
  request->req_size = htonl(sizeof(struct fchown32_req));

  request->fd = 10;
  request->owner = 0;
  request->group = 0;  
  

  return request;
}


struct fcntl_req *fill_fcntl_request(u_int16_t cmd_type, int lock_null)
{
  struct fcntl_req *request;
  int buffer_size = 0;

  request = calloc(1, sizeof(struct fcntl_req));
  assert(!(request == NULL));

  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_fcntl);
  request->cmd_type = cmd_type;
  request->fd = 10;

  switch(cmd_type) {
    case FCNTL_NO_3RD_ARG:
      request->cmd = F_GETFD;
      break;
    case FCNTL_3RD_LONG:
      request->cmd = F_DUPFD;
      request->third.arg = 12345;
      break;
    case FCNTL_3RD_FLOCK_R:
      request->cmd = F_SETLK;
      break;
    case FCNTL_3RD_FLOCK_RW:
      request->cmd = F_GETLK;
      break;
    case FCNTL_3RD_FLOCK_W:
      fprintf(stderr, "A fcntl command that use the 'struct flock' only for writing doesn't exist");
      assert(0);
      break;
    default:
      fprintf(stderr, "wrong cmd_type: %lX", cmd_type);
      assert(0);
      break;
  }

  if(cmd_type & FCNTL_3RD_FLOCK) {
    if(!lock_null) {
      request->third.lock = calloc(1, sizeof(struct flock));
      assert(!(request->third.lock == NULL));
      request->third.lock->l_type   = F_RDLCK;
      request->third.lock->l_whence = SEEK_SET;
      request->third.lock->l_start  = 33;
      request->third.lock->l_len    = 40;
      request->third.lock->l_pid    = 123;

      if(cmd_type == FCNTL_3RD_FLOCK_R || cmd_type == FCNTL_3RD_FLOCK_RW)
        buffer_size = sizeof(struct flock);
    } else {
      request->third.lock = NULL;
    }
  }

  request->req_size = htonl(sizeof(struct fcntl_req) + buffer_size);
  

  return request;
}


struct fcntl64_req *fill_fcntl64_request(void)
{
#if 0
  struct fcntl64_req *request;

  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_fcntl64);
  request->req_size = htonl(sizeof(struct fcntl64_req));

  request->fd = /* FIXME */;
  request->cmd = /* FIXME */;  
  

  return request;
#endif
  return NULL;
}


struct fdatasync_req *fill_fdatasync_request(void)
{
  struct fdatasync_req *request;

  request = calloc(1, sizeof(struct fdatasync_req));
  assert(!(request == NULL));
  
  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_fdatasync);
  request->req_size = htonl(sizeof(struct fdatasync_req));

  request->fd = 10;  
  

  return request;
}

struct fgetxattr_req *fill_fgetxattr_request(int name_null)
{
  struct fgetxattr_req *request;
  char *name;
  int size_name;

  request = calloc(1, sizeof(struct fgetxattr_req));
  assert(!(request == NULL));
  
  if(name_null) {
    name = NULL;
    size_name = 0;
  } else {
    name = fill_string("user.mime_type");
    size_name = (strlen(name) + 1);
  }

  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_fgetxattr);
  request->req_size = htonl(sizeof(struct fgetxattr_req) + size_name);

  request->filedes = 10;
  request->name = name;
  request->value = calloc(20, sizeof(char));
  assert(!(request->value == NULL));
  request->size = sizeof(char) * 20;  
  

  return request;
}

struct fstat64_req *fill_fstat64_request(void)
{
  struct fstat64_req *request;

  request = calloc(1, sizeof(struct fstat64_req));
  assert(!(request == NULL));
  
  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_fstat64);
  request->req_size = htonl(sizeof(struct fstat64_req));

  request->filedes = 10;
  request->buf = calloc(1, sizeof(struct stat64));  
  assert(!(request->buf == NULL));
  

  return request;
}


struct fstatfs64_req *fill_fstatfs64_request(void)
{
  struct fstatfs64_req *request;

  request = calloc(1, sizeof(struct fstatfs64_req));
  assert(!(request == NULL));
  
  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_fstatfs64);
  request->req_size = htonl(sizeof(struct fstatfs64_req));

  request->fd = 10;
  request->buf = calloc(1, sizeof(struct statfs64));  
  assert(!(request->buf == NULL));
  

  return request;
}


struct fsync_req *fill_fsync_request(void)
{
  struct fsync_req *request;

  request = calloc(1, sizeof(struct fsync_req));
  assert(!(request == NULL));
  
  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_fsync);
  request->req_size = htonl(sizeof(struct fsync_req));

  request->fd = 10;  
  

  return request;
}

struct getpeername_req *fill_getpeername_request(int namelen_null)
{
  struct getpeername_req *request;
  socklen_t *namelen;
  int size_namelen;

  request = calloc(1, sizeof(struct getpeername_req));
  assert(!(request == NULL));
  
  if(namelen_null) {
    size_namelen = 0;
    namelen = NULL;
  } else {
    size_namelen = sizeof(socklen_t);
    namelen = calloc(1, size_namelen);
    assert(!(namelen == NULL));
    *namelen = sizeof(struct sockaddr_in);
  }

  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_getpeername);
  request->req_size = htonl(sizeof(struct getpeername_req) + size_namelen);

  request->s = 10;
  request->name = calloc(1, sizeof(struct sockaddr_in));
  assert(!(request->name == NULL));
  request->namelen = namelen;  
  

  return request;
}


struct getsockname_req *fill_getsockname_request(int namelen_null)
{
  struct getsockname_req *request;
  socklen_t *namelen;
  int size_namelen;

  request = calloc(1, sizeof(struct getsockname_req));
  assert(!(request == NULL));
  
  if(namelen_null) {
    size_namelen = 0;
    namelen = NULL;
  } else {
    size_namelen = sizeof(socklen_t);
    namelen = calloc(1, size_namelen);
    assert(!(namelen == NULL));
    *namelen = sizeof(struct sockaddr);
  }

  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_getsockname);
  request->req_size = htonl(sizeof(struct getsockname_req) + size_namelen);

  request->s = 10;
  request->name = calloc(1, sizeof(struct sockaddr));
  assert(!(request->name == NULL));
  request->namelen = namelen;  
  

  return request;
}


struct getsockopt_req *fill_getsockopt_request(int optlen_null)
{
  struct getsockopt_req *request;
  socklen_t *optlen;
  int size_optlen;

  request = calloc(1, sizeof(struct getsockopt_req));
  assert(!(request == NULL));
  
  if(optlen_null) {
    size_optlen = 0;
    optlen = NULL;
  } else {
    size_optlen = sizeof(socklen_t);
    optlen = calloc(1, size_optlen);
    assert(!(optlen == NULL));
    /* Fill the buffer */
    *optlen = sizeof(int);
  }

  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_getsockopt);
  request->req_size = htonl(sizeof(struct getsockopt_req) + size_optlen);

  request->s = 10;
  request->level = SOL_SOCKET;
  request->optname = SO_REUSEADDR;
  request->optval = calloc(1, sizeof(int));
  assert(!(request->optval == NULL));
  request->optlen = optlen;  
  

  return request;
}


struct gettimeofday_req *fill_gettimeofday_request(void)
{
  struct gettimeofday_req *request;

  request = calloc(1, sizeof(struct gettimeofday_req));
  assert(!(request == NULL));
  
  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_gettimeofday);
  request->req_size = htonl(sizeof(struct gettimeofday_req));

  request->tv = calloc(1, sizeof(struct timeval));
  assert(!(request->tv == NULL));
  request->tz = calloc(1, sizeof(struct timezone)); 
  assert(!(request->tz == NULL));
  

  return request;
}


struct getxattr_req *fill_getxattr_request(int path_null, int name_null)
{
  struct getxattr_req *request;
  char *path;
  int size_path;
  char *name;
  int size_name;

  request = calloc(1, sizeof(struct getxattr_req));
  assert(!(request == NULL));
  
  if(path_null) {
    path = NULL;
    size_path = 0;
  } else {
    path = fill_string(NULL);
    size_path = (strlen(path) + 1);
  }
  
  if(name_null) {
    name = NULL;
    size_name = 0;
  } else {
    name = fill_string("user.mime_type");
    size_name = (strlen(name) + 1);
  }

  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_getxattr);
  request->req_size = htonl(sizeof(struct getxattr_req) + size_path + size_name);

  request->path = path;
  request->name = name;
  request->value = calloc(20, sizeof(char));
  assert(!(request->value == NULL));
  request->size = 20 * sizeof(char);  
  

  return request;
}


struct lchown_req *fill_lchown_request(int path_null)
{
  struct lchown_req *request;
  char *path;
  int size_path;

  request = calloc(1, sizeof(struct lchown_req));
  assert(!(request == NULL));
  
  if(path_null) {
    path = NULL;
    size_path = 0;
  } else {
    path = fill_string(NULL);
    size_path = (strlen(path) + 1);
  }

  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_lchown);
  request->req_size = htonl(sizeof(struct lchown_req) + size_path);

  request->path = path;
  request->owner = 0;
  request->group = 0;  
  

  return request;
}


struct lchown32_req *fill_lchown32_request(int path_null)
{
  struct lchown32_req *request;
  char *path;
  int size_path;

  request = calloc(1, sizeof(struct lchown32_req));
  assert(!(request == NULL));
  
  if(path_null) {
    path = NULL;
    size_path = 0;
  } else {
    path = fill_string(NULL);
    size_path = (strlen(path) + 1);
  }

  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_lchown32);
  request->req_size = htonl(sizeof(struct lchown32_req) + size_path);

  request->path = path;
  request->owner = 0;
  request->group = 0;  
  

  return request;
}


struct lgetxattr_req *fill_lgetxattr_request(int path_null, int name_null)
{
  struct lgetxattr_req *request;
  char *path;
  int size_path;
  char *name;
  int size_name;

  request = calloc(1, sizeof(struct lgetxattr_req));
  assert(!(request == NULL));
  
  if(path_null) {
    path = NULL;
    size_path = 0;
  } else {
    path = fill_string(NULL);
    size_path = (strlen(path) + 1);
  }

  if(name_null) {
    name = NULL;
    size_name = 0;
  } else {
    name = fill_string("user.mime_type");
    size_name = (strlen(name) + 1);
  }

  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_lgetxattr);
  request->req_size = htonl(sizeof(struct lgetxattr_req) + size_path + size_name);

  request->path = path;
  request->name = name;
  request->value = calloc(20, sizeof(char));
  assert(!(request->value == NULL));
  request->size = 20 * sizeof(char);  
  

  return request;
}


struct link_req *fill_link_request(int oldpath_null, int newpath_null)
{
  struct link_req *request;
  char *oldpath;
  int size_oldpath;
  char *newpath;
  int size_newpath;

  request = calloc(1, sizeof(struct link_req));
  assert(!(request == NULL));
  
  if(oldpath_null) {
    oldpath = NULL;
    size_oldpath = 0;
  } else {
    oldpath = fill_string(NULL);
    size_oldpath = (strlen(oldpath) + 1);
  }
  
  if(newpath_null) {
    newpath = NULL;
    size_newpath = 0;
  } else {
    newpath = fill_string(NULL);
    size_newpath = (strlen(newpath) + 1);
  }

  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_link);
  request->req_size = htonl(sizeof(struct link_req) + size_oldpath + size_newpath);

  request->oldpath = oldpath;
  request->newpath = newpath;  
  

  return request;
}


struct listen_req *fill_listen_request(void)
{
  struct listen_req *request;

  request = calloc(1, sizeof(struct listen_req));
  assert(!(request == NULL));
  
  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_listen);
  request->req_size = htonl(sizeof(struct listen_req));

  request->sockfd = 10;
  request->backlog = 5;  
  

  return request;
}


struct lseek_req *fill_lseek_request(void)
{
  struct lseek_req *request;

  request = calloc(1, sizeof(struct lseek_req));
  assert(!(request == NULL));
  
  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_lseek);
  request->req_size = htonl(sizeof(struct lseek_req));

  request->fildes = 10;
  request->offset = 100;
  request->whence = SEEK_SET;


  return request;
}

struct lstat64_req *fill_lstat64_request(int path_null)
{
  struct lstat64_req *request;
  char *path;
  int size_path;

  request = calloc(1, sizeof(struct lstat64_req));
  assert(!(request == NULL));
  
  if(path_null) {
    path = NULL;
    size_path = 0;
  } else {
    path = fill_string(NULL);
    size_path = strlen(path) + 1;
    assert(!(path == NULL));
  }

  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_lstat64);
  request->req_size = htonl(sizeof(struct lstat64_req) + size_path);

  request->path = path;
  request->buf = calloc(1, sizeof(struct stat64));  
  assert(!(request->buf == NULL));
  

  return request;
}


struct mkdir_req *fill_mkdir_request(int pathname_null)
{
  struct mkdir_req *request;
  char *pathname;
  int size_pathname;

  request = calloc(1, sizeof(struct mkdir_req));
  assert(!(request == NULL));
  
  if(pathname_null) {
    pathname = NULL;
    size_pathname = 0;
  } else {
    pathname = fill_string(NULL);
    size_pathname = (strlen(pathname) + 1);
  }

  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_mkdir);
  request->req_size = htonl(sizeof(struct mkdir_req) + size_pathname);

  request->pathname = pathname;
  request->mode = 0700;
  

  return request;
}

struct mount_req *fill_mount_request(int source_null, int target_null, int filesystemtype_null, int data_null)
{
  struct mount_req *request;
  char *source;
  int size_source;
  char *target;
  int size_target;
  char *filesystemtype;
  int size_filesystemtype;
  void *data;
  int size_data;
    
  request = calloc(1, sizeof(struct mount_req));
  assert(!(request == NULL));

  if(source_null) {
    size_source = 0;
    source = NULL;
  } else {
    source = fill_string("/dev/hda1");
    size_source = (strlen(source) + 1);
  }
  if(target_null) {
    size_target = 0;
    target = NULL;
  } else {
    target = fill_string(NULL);
    size_target = (strlen(target) + 1);
  }
  if(filesystemtype_null) {
    size_filesystemtype = 0;
    filesystemtype = NULL;
  } else {
    filesystemtype = fill_string("ext3");
    size_filesystemtype = (strlen(filesystemtype) + 1);
  }
  if(data_null) {
    size_data = 0;
    data = NULL;
  } else {
    data = fill_string("defaults,user,umask=077");
    size_data = (strlen(data) + 1);
  }
  
  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_mount);
  request->req_size = htonl(sizeof(struct mount_req) + size_source + size_target + size_filesystemtype + size_data);

  request->source = source;
  request->target = target;
  request->filesystemtype = filesystemtype;
  request->mountflags = MS_NOEXEC;
  request->data = data;  
  

  return request;
}


#if 0
struct mmap_req *fill_mmap_request(void)
{
  struct mmap_req *request;

  request = calloc(1, sizeof(struct mmap_req));
  assert(!(request == NULL));
  
  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_mmap);
  request->req_size = htonl(sizeof(struct mmap_req));

  request->start = 0;
  request->length = 100;
  request->prot = PROT_NONE;
  request->flags = MAP_SHARED;
  request->fd = 10;
  request->offset = 20;  
  

  return request;
}


struct mmap2_req *fill_mmap2_request(void)
{
  struct mmap2_req *request;


  request = calloc(1, sizeof(struct mmap2_req));
  assert(!(request == NULL));
  
  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_mmap2);
  request->req_size = htonl(sizeof(struct mmap2_req));
  
  request->start = 0;
  request->length = 100;
  request->prot = PROT_NONE;
  request->flags = MAP_SHARED;
  request->fd = 10;
  request->pgoffset = 20;  
  

  return request;
}
#endif


struct open_req *fill_open_request(int pathname_null)
{
  struct open_req *request;
  char *pathname;
  int size_pathname;

  request = calloc(1, sizeof(struct open_req));
  assert(!(request == NULL));
  
  if(pathname_null) {
    pathname = NULL;
    size_pathname = 0;
  } else {
    pathname = fill_string(NULL);
    size_pathname = (strlen(pathname) + 1);
  }

  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_open);
  request->req_size = htonl(sizeof(struct open_req) + size_pathname);

  request->pathname = pathname;
  request->flags = O_RDONLY;  
  

  return request;
}


struct pread64_req *fill_pread64_request(void)
{
  struct pread64_req *request;

  request = calloc(1, sizeof(struct pread64_req));
  assert(!(request == NULL));
  
  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_pread64);
  request->req_size = htonl(sizeof(struct pread64_req));

  request->fd = 10;
  request->buf = calloc(200, sizeof(char));
  assert(!(request->buf == NULL));
  request->count = 100;
  request->offset = 20;  
  

  return request;
}


struct pwrite64_req *fill_pwrite64_request(int buf_null)
{
  struct pwrite64_req *request;
  void *buf;
  size_t size_buf;

  request = calloc(1, sizeof(struct pwrite64_req));
  assert(!(request == NULL));
  
  if(buf_null) {
    size_buf = 0;
    buf = NULL;
  } else {
    size_buf = sizeof(char) * 30;
    buf = calloc(1, size_buf);
    assert(!(buf == NULL));
    /* Fill the buffer */
    memset(buf, 'a', size_buf);
  }

  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_pwrite64);
  request->req_size = htonl(sizeof(struct pwrite64_req) + size_buf);

  request->fd = 10;
  request->buf = buf;
  request->count = size_buf;
  request->offset = 20;  
  

  return request;
}


struct read_req *fill_read_request(void)
{
  struct read_req *request;

  request = calloc(1, sizeof(struct read_req));
  assert(!(request == NULL));
  
  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_read);
  request->req_size = htonl(sizeof(struct read_req));

  request->fd = 10;
  request->buf = calloc(20, sizeof(char));
  assert(!(request->buf == NULL));
  request->count = sizeof(char) * 20;  
  

  return request;
}


struct readlink_req *fill_readlink_request(int path_null)
{
  struct readlink_req *request;
  char *path;
  int size_path;

  request = calloc(1, sizeof(struct readlink_req));
  assert(!(request == NULL));
 
  if(path_null) {
    path = NULL;
    size_path = 0;
  } else {
    path = fill_string(NULL);
    size_path = (strlen(path) + 1);
  }

  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_readlink);
  request->req_size = htonl(sizeof(struct readlink_req) + size_path);

  request->path = path;
  request->buf = calloc(20, sizeof(char));
  assert(!(request->buf == NULL));
  request->bufsiz = sizeof(char) * 20;  
  

  return request;
}


struct recv_req *fill_recv_request(void)
{
  struct recv_req *request;

  request = calloc(1, sizeof(struct recv_req));
  assert(!(request == NULL));
  
  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_recv);
  request->req_size = htonl(sizeof(struct recv_req));

  request->s = 10;
  request->buf = calloc(20, sizeof(char));
  assert(!(request->buf == NULL));
  request->len = sizeof(char) * 20;
  request->flags = MSG_WAITALL;  
  

  return request;
}


struct recvfrom_req *fill_recvfrom_request(int fromlen_null, int from_null)
{
  struct recvfrom_req *request;
  struct sockaddr *from;
  socklen_t size_from;
  socklen_t *fromlen;
  int size_fromlen;

  request = calloc(1, sizeof(struct recvfrom_req));
  assert(!(request == NULL));
  
  if(from_null) {
    from = NULL;
    size_from = 0;
  } else {
    from = (struct sockaddr *)fill_struct_sockaddr_in();
    size_from = sizeof(struct sockaddr_in);
  }
  
  if(fromlen_null) {
    size_fromlen = 0;
    fromlen = NULL;
  } else {
    size_fromlen = sizeof(socklen_t);
    fromlen = calloc(1, size_fromlen);
    assert(!(fromlen == NULL));
    *fromlen = sizeof(struct sockaddr_in);
  }
    
  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_recvfrom);
  request->req_size = htonl(sizeof(struct recvfrom_req) + size_from + size_fromlen);

  request->s = 10;
  request->buf = calloc(20, sizeof(char));
  assert(!(request->buf == NULL));
  request->len = sizeof(char) * 20;
  request->flags = MSG_WAITALL;
  request->from = from;
  request->fromlen = fromlen;  
  

  return request;
}


struct rename_req *fill_rename_request(int oldpath_null, int newpath_null)
{
  struct rename_req *request;
  char *oldpath;
  int size_oldpath;
  char *newpath;
  int size_newpath;

  request = calloc(1, sizeof(struct rename_req));
  assert(!(request == NULL));
  
  if(oldpath_null) {
    oldpath = NULL;
    size_oldpath = 0;
  } else {
    oldpath = fill_string(NULL);
    size_oldpath = (strlen(oldpath) + 1);
  }
  
  if(newpath_null) {
    newpath = NULL;
    size_newpath = 0;
  } else {
    newpath = fill_string(NULL);
    size_newpath = (strlen(newpath) + 1);
  }

  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_rename);
  request->req_size = htonl(sizeof(struct rename_req) + size_oldpath + size_newpath);

  request->oldpath = oldpath;
  request->newpath = newpath;  
  

  return request;
}


struct rmdir_req *fill_rmdir_request(int pathname_null)
{
  struct rmdir_req *request;
  char *pathname;
  int size_pathname;

  request = calloc(1, sizeof(struct rmdir_req));
  assert(!(request == NULL));
  
  if(pathname_null) {
    pathname = NULL;
    size_pathname = 0;
  } else {
    pathname = fill_string(NULL);
    size_pathname = (strlen(pathname) + 1);
  }

  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_rmdir);
  request->req_size = htonl(sizeof(struct rmdir_req) + size_pathname);

  request->pathname = pathname;  
  

  return request;
}


struct send_req *fill_send_request(int buf_null)
{
  struct send_req *request;
  void *buf;
  size_t size_buf;

  request = calloc(1, sizeof(struct send_req));
  assert(!(request == NULL));
  
  if(buf_null) {
    size_buf = 0;
    buf = NULL;
  } else {
    size_buf = sizeof(char) * 20;
    buf = calloc(1, size_buf);
    assert(!(buf == NULL));
    /* Fill the buffer */
    memset(buf, 'a', size_buf);
  }

  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_send);
  request->req_size = htonl(sizeof(struct send_req) + size_buf);

  request->s = 10;
  request->buf = buf;
  request->len = size_buf;
  request->flags = 0;  
  

  return request;
}


struct sendto_req *fill_sendto_request(int buf_null, int to_null)
{
  struct sendto_req *request;
  void *buf;
  size_t size_buf;
  struct sockaddr *to;
  socklen_t size_to;

  request = calloc(1, sizeof(struct sendto_req));
  assert(!(request == NULL));
  
  if(buf_null) {
    size_buf = 0;
    buf = NULL;
  } else {
    size_buf = sizeof(char) * 20;
    buf = calloc(1, size_buf);
    assert(!(buf == NULL));
    /* Fill the buffer */
    memset(buf, 'a', size_buf);
  }
  
  if(to_null) {
    to = NULL;
    size_to = 0;
  } else {
    to = (struct sockaddr *)fill_struct_sockaddr_in();
    size_to = sizeof(struct sockaddr_in);
  }

  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_sendto);
  request->req_size = htonl(sizeof(struct sendto_req) + size_buf + size_to);

  request->s = 10;
  request->buf = buf;
  request->len = size_buf;
  request->flags = 0;
  request->to = to;
  request->tolen = size_to;  
  

  return request;
}


struct setdomainname_req *fill_setdomainname_request(int name_null)
{
  struct setdomainname_req *request;
  char *name;
  int size_name;

  request = calloc(1, sizeof(struct setdomainname_req));
  assert(!(request == NULL));
  
  if(name_null) {
    name = NULL;
    size_name = 0;
  } else {
    name = fill_string("domainname");
    size_name = (strlen(name) + 1);
  }

  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_setdomainname);
  request->req_size = htonl(sizeof(struct setdomainname_req) + size_name);

  request->name = name;
  request->len = size_name;  
  

  return request;
}


struct sethostname_req *fill_sethostname_request(int name_null)
{
  struct sethostname_req *request;
  int size_name;
  char *name;

  request = calloc(1, sizeof(struct sethostname_req));
  assert(!(request == NULL));
  
  if(name_null) {
    name = NULL;
    size_name = 0;
  } else {
    name = fill_string("hostname"); 
    size_name = strlen(name) + 1;
  }

  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_sethostname);
  request->req_size = htonl(sizeof(struct sethostname_req));

  request->name = name;
  request->len = size_name;  
  

  return request;
}


struct setsockopt_req *fill_setsockopt_request(int optval_null)
{
  struct setsockopt_req *request;
  int *optval;
  socklen_t size_optval;

  request = calloc(1, sizeof(struct setsockopt_req));
  assert(!(request == NULL));
  
  if(optval_null) {
    size_optval = 0;
    optval = NULL;
  } else {
    size_optval = sizeof(int);
    optval = calloc(1, size_optval);
    assert(!(optval == NULL));
    /* Fill the buffer */
    *optval = htonl(1);
  }

  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_setsockopt);
  request->req_size = htonl(sizeof(struct setsockopt_req) + size_optval);

  request->s = 10;
  request->level = SOL_SOCKET;
  request->optname = SO_REUSEADDR;
  request->optval = optval;
  request->optlen = size_optval;  
  

  return request;
}


struct settimeofday_req *fill_settimeofday_request(int tv_null, int tz_null)
{
  struct settimeofday_req *request;
  struct timeval *tv;
  struct timezone *tz;
  int size_tv, size_tz;

  request = calloc(1, sizeof(struct settimeofday_req));
  assert(!(request == NULL));
  
  if(tv_null) {
    size_tv = 0;
    tv = NULL;
  } else {
    size_tv = sizeof(struct timeval);
    tv = calloc(1, size_tv);
    assert(!(tv == NULL));
    /* Fill the buffer */
    tv->tv_sec = 10;
    tv->tv_usec = 30;
  }

  if(tz_null) {
    size_tz = 0;
    tz = NULL;
  } else {
    size_tz = sizeof(struct timezone);
    tz = calloc(1, size_tz);
    assert(!(tz == NULL));
    /* Fill the buffer */
    tz->tz_minuteswest  = 20;
    tz->tz_dsttime      = 40;
  }

  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_settimeofday);
  request->req_size = htonl(sizeof(struct settimeofday_req) + size_tv + size_tz);

  request->tv = tv;
  request->tz = tz;
  

  return request;
}


struct shutdown_req *fill_shutdown_request(void)
{
  struct shutdown_req *request;

  request = calloc(1, sizeof(struct shutdown_req));
  assert(!(request == NULL));
  
  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_shutdown);
  request->req_size = htonl(sizeof(struct shutdown_req));

  request->s = 10;
  request->how = SHUT_RDWR;  
  

  return request;
}


struct socket_req *fill_socket_request(void)
{
  struct socket_req *request;

  request = calloc(1, sizeof(struct socket_req));
  assert(!(request == NULL));
  
  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_socket);
  request->req_size = htonl(sizeof(struct socket_req));

  request->domain = AF_INET;
  request->type = SOCK_STREAM;
  request->protocol = 0;  
  

  return request;
}

struct stat64_req *fill_stat64_request(int path_null)
{
  struct stat64_req *request;
  char *path;
  int size_path;

  request = calloc(1, sizeof(struct stat64_req));
  assert(!(request == NULL));
  
  if(path_null) {
    path = NULL;
    size_path = 0;
  } else {
    path = fill_string(NULL);
    size_path = (strlen(path) + 1);
  }

  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_stat64);
  request->req_size = htonl(sizeof(struct stat64_req) + size_path);

  request->path = path;
  request->buf = calloc(1, sizeof(struct stat64)); 
  assert(!(request->buf == NULL));
  

  return request;
}


struct statfs64_req *fill_statfs64_request(int path_null)
{
  struct statfs64_req *request;
  char *path;
  int size_path;

  request = calloc(1, sizeof(struct statfs64_req));
  assert(!(request == NULL));
  
  if(path_null) {
    path = NULL;
    size_path = 0;
  } else {
    path = fill_string(NULL);
    size_path = (strlen(path) + 1);
  }

  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_statfs64);
  request->req_size = htonl(sizeof(struct statfs64_req) + size_path);

  request->path = path;
  request->buf = calloc(1, sizeof(struct statfs64));
  assert(!(request->buf == NULL));
  

  return request;
}


struct symlink_req *fill_symlink_request(int oldpath_null, int newpath_null)
{
  struct symlink_req *request;
  char *oldpath;
  int size_oldpath;
  char *newpath;
  int size_newpath;

  request = calloc(1, sizeof(struct symlink_req));
  assert(!(request == NULL));
  
  if(oldpath_null) {
    oldpath = NULL;
    size_oldpath = 0;
  } else {
    oldpath = fill_string(NULL);
    size_oldpath = (strlen(oldpath) + 1);
  }
  
  if(newpath_null) {
    newpath = NULL;
    size_newpath = 0;
  } else {
    newpath = fill_string(NULL);
    size_newpath = (strlen(newpath) + 1);
  }

  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_symlink);
  request->req_size = htonl(sizeof(struct symlink_req) + size_oldpath + size_newpath);

  request->oldpath = oldpath;
  request->newpath = newpath;  
  

  return request;
}

struct umount2_req *fill_umount2_request(int target_null)
{
  struct umount2_req *request;
  char *target;
  int size_target;

  request = calloc(1, sizeof(struct umount2_req));
  assert(!(request == NULL));
  
  if(target_null) {
    target = NULL;
    size_target = 0;
  } else {
    target = fill_string(NULL);
    size_target = (strlen(target) + 1);
  }

  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_umount2);
  request->req_size = htonl(sizeof(struct umount2_req) + size_target);

  request->target = target;
  /* request->flags = MNT_DETACH; */
  request->flags = 0;
  

  return request;
}


struct uname_req *fill_uname_request(void)
{
  struct uname_req *request;

  request = calloc(1, sizeof(struct uname_req));
  assert(!(request == NULL));
  
  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_uname);
  request->req_size = htonl(sizeof(struct uname_req));

  request->buf = calloc(1, sizeof(struct utsname));  
  assert(!(request->buf == NULL));
  

  return request;
}


struct unlink_req *fill_unlink_request(int pathname_null)
{
  struct unlink_req *request;
  char *pathname;
  int size_pathname;

  request = calloc(1, sizeof(struct unlink_req));
  assert(!(request == NULL));
  
  if(pathname_null) {
    pathname = NULL;
    size_pathname = 0;
  } else {
    pathname = fill_string(NULL);
    size_pathname = (strlen(pathname) + 1);
  }

  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_unlink);
  request->req_size = htonl(sizeof(struct unlink_req) + size_pathname);

  request->pathname = pathname;  
  

  return request;
}


struct utime_req *fill_utime_request(int filename_null, int buf_null)
{
  struct utime_req *request;
  char *filename;
  int size_filename;
  struct utimbuf *buf;
  int size_buf;

  request = calloc(1, sizeof(struct utime_req));
  assert(!(request == NULL));
  
  if(filename_null) {
    filename = NULL;
    size_filename = 0;
  } else {
    filename = fill_string(NULL);
    size_filename = (strlen(filename) + 1);
  }
  
  if(buf_null) {
    size_buf = 0;
    buf = NULL;
  } else {
    size_buf = sizeof(struct utimbuf);
    buf = calloc(1, size_buf);
    assert(!(buf == NULL));
    /* Fill the buffer */
    buf->actime = 200;
    buf->modtime = 100;
  }

  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_utime);
  request->req_size = htonl(sizeof(struct utime_req) + size_filename + size_buf);

  request->filename = filename;
  request->buf = buf;  
  

  return request;
}


struct utimes_req *fill_utimes_request(int filename_null)
{
  struct utimes_req *request;
  char *filename;
  int size_filename;

  request = calloc(1, sizeof(struct utimes_req));
  assert(!(request == NULL));
  
  if(filename_null) {
    filename = NULL;
    size_filename = 0;
  } else {
    filename = fill_string(NULL);
    size_filename = (strlen(filename) + 1);
  }

  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_utimes);
  request->req_size = htonl(sizeof(struct utimes_req) + size_filename);

  request->filename = filename;

  request->tv[0].tv_sec = 100;
  request->tv[0].tv_usec = 100;
  
  request->tv[1].tv_sec = 100;
  request->tv[1].tv_usec = 100;
  

  return request;
}


struct write_req *fill_write_request(int buf_null)
{
  struct write_req *request;
  void *buf;
  size_t size_buf;
  
  request = calloc(1, sizeof(struct write_req));
  assert(!(request == NULL));

  if(buf_null) {
    size_buf = 0;
    buf = NULL;
  } else {
    size_buf = 10 * sizeof(char);
    buf = calloc(1, size_buf);
    assert(!(buf == NULL));
    /* Fill the buffer */
    memset(buf, 'a', size_buf);
  }

  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_write);
  request->req_size = htonl(sizeof(struct write_req) + size_buf);

  request->fd = 10;
  request->buf = buf;
  request->count = size_buf;  
  

  return request;
}
struct ftruncate64_req *fill_ftruncate64_request(void)
{
  struct ftruncate64_req *request;
  
  request = calloc(1, sizeof(struct ftruncate64_req));
  assert(!(request == NULL));

  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_ftruncate64);
  request->req_size = htonl(sizeof(struct ftruncate64_req));

  request->fd = 10;
  request->length = 200;  
  

  return request;
}

struct getdents64_req *fill_getdents64_request(void)
{
  struct getdents64_req *request;
  
  request = calloc(1, sizeof(struct getdents64_req));
  assert(!(request == NULL));

  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_getdents64);
  request->req_size = htonl(sizeof(struct getdents64_req));

  request->fd = 10;
  request->dirp = calloc(1, sizeof(struct dirent64));
  assert(!(request->dirp == NULL));
  request->count = sizeof(struct dirent64);  
  

  return request;
}

struct truncate64_req *fill_truncate64_request(int path_null)
{
  struct truncate64_req *request;
  char *path;
  int size_path;

  request = calloc(1, sizeof(struct truncate64_req));
  assert(!(request == NULL));

  if(path_null) {
    path = NULL;
    size_path = 0;
  } else {
    path = fill_string(NULL);
    size_path = (strlen(path) + 1);
  }
  
  request->req_type = RSC_SYS_REQ;
  request->req_rsc_const =  htons(__RSC_truncate64);
  request->req_size = htonl(sizeof(struct truncate64_req) + size_path);

  request->path = path;
  request->length = 200;  
  

  return request;
}

/**********************************************************/
/* Free filled request                                    */
/**********************************************************/
void free_filled__llseek_request(struct _llseek_req *req, int only_pointed_memory) 
{
  if(req->result != NULL)
    free(req->result);
  if(! only_pointed_memory)
    free(req);
}
void free_filled_accept_request(struct accept_req *req, int only_pointed_memory) 
{
  if(req->addr != NULL) 
    free(req->addr);
  if(req->addrlen != NULL)
    free(req->addrlen);
  if(! only_pointed_memory)
    free(req);
}
void free_filled_access_request(struct access_req *req, int only_pointed_memory) 
{
  if(req->pathname != NULL)
    free(req->pathname);
  if(! only_pointed_memory)
    free(req);
}
void free_filled_adjtimex_request(struct adjtimex_req *req, int only_pointed_memory) 
{
  if(req->buf != NULL)
    free(req->buf);
  if(! only_pointed_memory)
    free(req);
}
void free_filled_bind_request(struct bind_req *req, int only_pointed_memory) 
{
  if(req->my_addr != NULL)
    free(req->my_addr);
  if(! only_pointed_memory)
    free(req);
}
void free_filled_chdir_request(struct chdir_req *req, int only_pointed_memory) 
{
  if(req->path != NULL)
    free(req->path);
  if(! only_pointed_memory)
    free(req);
}
void free_filled_chmod_request(struct chmod_req *req, int only_pointed_memory) 
{
  if(req->path != NULL)
    free(req->path);
  if(! only_pointed_memory)
    free(req);
}
void free_filled_chown_request(struct chown_req *req, int only_pointed_memory) 
{
  if(req->path != NULL)
    free(req->path);
  if(! only_pointed_memory)
    free(req);
}
void free_filled_chown32_request(struct chown32_req *req, int only_pointed_memory) 
{
  if(req->path != NULL)
    free(req->path);
  if(! only_pointed_memory)
    free(req);
}
void free_filled_clock_getres_request(struct clock_getres_req *req, int only_pointed_memory) 
{
  if(req->res != NULL)
    free(req->res);
  if(! only_pointed_memory)
    free(req);
}
void free_filled_clock_gettime_request(struct clock_gettime_req *req, int only_pointed_memory) 
{
  if(req->tp != NULL)
    free(req->tp);
  if(! only_pointed_memory)
    free(req);
}
void free_filled_clock_settime_request(struct clock_settime_req *req, int only_pointed_memory) 
{
  if(req->tp != NULL)
    free(req->tp);
  if(! only_pointed_memory)
    free(req);
}
void free_filled_close_request(struct close_req *req, int only_pointed_memory) 
{
  if(! only_pointed_memory)
    free(req);
}
void free_filled_connect_request(struct connect_req *req, int only_pointed_memory) 
{
  if(req->serv_addr != NULL)
    free(req->serv_addr);
  if(! only_pointed_memory)
    free(req);
}
void free_filled_dup_request(struct dup_req *req, int only_pointed_memory) 
{
  if(! only_pointed_memory)
    free(req);
}
void free_filled_dup2_request(struct dup2_req *req, int only_pointed_memory) 
{
  if(! only_pointed_memory)
    free(req);
}
void free_filled_fchdir_request(struct fchdir_req *req, int only_pointed_memory) 
{
  if(! only_pointed_memory)
    free(req);
}
void free_filled_fchmod_request(struct fchmod_req *req, int only_pointed_memory) 
{
  if(! only_pointed_memory)
    free(req);
}
void free_filled_fchown_request(struct fchown_req *req, int only_pointed_memory) 
{
  if(! only_pointed_memory)
    free(req);
}
void free_filled_fchown32_request(struct fchown32_req *req, int only_pointed_memory) 
{
  if(! only_pointed_memory)
    free(req);
}
void free_filled_fdatasync_request(struct fdatasync_req *req, int only_pointed_memory) 
{
  if(! only_pointed_memory)
    free(req);
}
void free_filled_fgetxattr_request(struct fgetxattr_req *req, int only_pointed_memory) 
{
  if(req->name != NULL)
    free(req->name);
  if(req->value != NULL)
    free(req->value);
  if(! only_pointed_memory)
    free(req);
}
void free_filled_fstat64_request(struct fstat64_req *req, int only_pointed_memory) 
{
  if(req->buf != NULL)
    free(req->buf);
  if(! only_pointed_memory)
    free(req);
}
void free_filled_fstatfs64_request(struct fstatfs64_req *req, int only_pointed_memory) 
{
  if(req->buf != NULL)
    free(req->buf);
  if(! only_pointed_memory)
    free(req);
}
void free_filled_fsync_request(struct fsync_req *req, int only_pointed_memory) 
{
  if(! only_pointed_memory)
    free(req);
}
void free_filled_ftruncate64_request(struct ftruncate64_req *req, int only_pointed_memory) 
{
  if(! only_pointed_memory)
    free(req);
}
void free_filled_getdents64_request(struct getdents64_req *req, int only_pointed_memory) 
{
  if(req->dirp != NULL)
    free(req->dirp);
  if(! only_pointed_memory)
    free(req);
}
void free_filled_getpeername_request(struct getpeername_req *req, int only_pointed_memory) 
{
  if(req->name != NULL)
    free(req->name);
  if(req->namelen != NULL)
    free(req->namelen);
  if(! only_pointed_memory)
    free(req);
}
void free_filled_getsockname_request(struct getsockname_req *req, int only_pointed_memory) 
{
  if(req->name != NULL)
    free(req->name);
  if(req->namelen != NULL)
    free(req->namelen);
  if(! only_pointed_memory)
    free(req);
}
void free_filled_getsockopt_request(struct getsockopt_req *req, int only_pointed_memory) 
{
  if(req->optval != NULL)
    free(req->optval);
  if(req->optlen != NULL)
    free(req->optlen);
  if(! only_pointed_memory)
    free(req);
}
void free_filled_gettimeofday_request(struct gettimeofday_req *req, int only_pointed_memory) 
{
  if(req->tv != NULL)
    free(req->tv);
  if(req->tz != NULL)
    free(req->tz);
  if(! only_pointed_memory)
    free(req);
}
void free_filled_getxattr_request(struct getxattr_req *req, int only_pointed_memory) 
{
  if(req->path != NULL)
    free(req->path);
  if(req->name != NULL)
    free(req->name);
  if(req->value != NULL)
    free(req->value);
  if(! only_pointed_memory)
    free(req);
}
void free_filled_lchown_request(struct lchown_req *req, int only_pointed_memory) 
{
  if(req->path != NULL)
    free(req->path);
  if(! only_pointed_memory)
    free(req);
}
void free_filled_lchown32_request(struct lchown32_req *req, int only_pointed_memory) 
{
  if(req->path != NULL)
    free(req->path);
  if(! only_pointed_memory)
    free(req);
}
void free_filled_lgetxattr_request(struct lgetxattr_req *req, int only_pointed_memory) 
{
  if(req->path != NULL)
    free(req->path);
  if(req->name != NULL)
    free(req->name);
  if(req->value != NULL)
    free(req->value);
  if(! only_pointed_memory)
    free(req);
}
void free_filled_link_request(struct link_req *req, int only_pointed_memory) 
{
  if(req->oldpath != NULL)
    free(req->oldpath);
  if(req->newpath != NULL)
    free(req->newpath);
  if(! only_pointed_memory)
    free(req);
}
void free_filled_listen_request(struct listen_req *req, int only_pointed_memory) 
{
  if(! only_pointed_memory)
    free(req);
}
void free_filled_lseek_request(struct lseek_req *req, int only_pointed_memory) 
{
  if(! only_pointed_memory)
    free(req);
}
void free_filled_lstat64_request(struct lstat64_req *req, int only_pointed_memory) 
{
  if(req->path != NULL)
    free(req->path);
  if(req->buf != NULL)
    free(req->buf);
  if(! only_pointed_memory)
    free(req);
}
void free_filled_mkdir_request(struct mkdir_req *req, int only_pointed_memory) 
{
  if(req->pathname != NULL)
    free(req->pathname);
  if(! only_pointed_memory)
    free(req);
}
void free_filled_mount_request(struct mount_req *req, int only_pointed_memory) 
{
  if(req->source != NULL)
    free(req->source);
  if(req->target != NULL)
    free(req->target);
  if(req->filesystemtype != NULL)
    free(req->filesystemtype);
  if(req->data != NULL)
    free(req->data);
  if(! only_pointed_memory)
    free(req);
}
void free_filled_open_request(struct open_req *req, int only_pointed_memory) 
{
  if(req->pathname != NULL)
    free(req->pathname);
  if(! only_pointed_memory)
    free(req);
}
void free_filled_pread64_request(struct pread64_req *req, int only_pointed_memory) 
{
  if(req->buf != NULL)
    free(req->buf);
  if(! only_pointed_memory)
    free(req);
}
void free_filled_pwrite64_request(struct pwrite64_req *req, int only_pointed_memory) 
{
  if(req->buf != NULL)
    free(req->buf);
  if(! only_pointed_memory)
    free(req);
}
void free_filled_read_request(struct read_req *req, int only_pointed_memory) 
{
  if(req->buf != NULL)
    free(req->buf);
  if(! only_pointed_memory)
    free(req);
}
void free_filled_readlink_request(struct readlink_req *req, int only_pointed_memory) 
{
  if(req->path != NULL)
    free(req->path);
  if(req->buf != NULL)
    free(req->buf);
  if(! only_pointed_memory)
    free(req);
}
void free_filled_recv_request(struct recv_req *req, int only_pointed_memory) 
{
  if(req->buf != NULL)
    free(req->buf);
  if(! only_pointed_memory)
    free(req);
}
void free_filled_recvfrom_request(struct recvfrom_req *req, int only_pointed_memory) 
{
  if(req->buf != NULL)
    free(req->buf);
  if(req->from != NULL)
    free(req->from);
  if(req->fromlen != NULL)
    free(req->fromlen);
  if(! only_pointed_memory)
    free(req);
}
void free_filled_rename_request(struct rename_req *req, int only_pointed_memory) 
{
  if(req->oldpath != NULL)
    free(req->oldpath);
  if(req->newpath != NULL)
    free(req->newpath);
  if(! only_pointed_memory)
    free(req);
}
void free_filled_rmdir_request(struct rmdir_req *req, int only_pointed_memory) 
{
  if(req->pathname != NULL)
    free(req->pathname);
  if(! only_pointed_memory)
    free(req);
}
void free_filled_send_request(struct send_req *req, int only_pointed_memory) 
{
  if(req->buf != NULL)
    free(req->buf);
  if(! only_pointed_memory)
    free(req);
}
void free_filled_sendto_request(struct sendto_req *req, int only_pointed_memory) 
{
  if(req->buf != NULL)
    free(req->buf);
  if(req->to != NULL)
    free(req->to);
  if(! only_pointed_memory)
    free(req);
}
void free_filled_setdomainname_request(struct setdomainname_req *req, int only_pointed_memory) 
{
  if(req->name != NULL)
    free(req->name);
  if(! only_pointed_memory)
    free(req);
}
void free_filled_sethostname_request(struct sethostname_req *req, int only_pointed_memory) 
{
  if(req->name != NULL)
    free(req->name);
  if(! only_pointed_memory)
    free(req);
}
void free_filled_setsockopt_request(struct setsockopt_req *req, int only_pointed_memory) 
{
  if(req->optval != NULL)
    free(req->optval);
  if(! only_pointed_memory)
    free(req);
}
void free_filled_settimeofday_request(struct settimeofday_req *req, int only_pointed_memory) 
{
  if(req->tv != NULL)
    free(req->tv);
  if(req->tz != NULL)
    free(req->tz);
  if(! only_pointed_memory)
    free(req);
}
void free_filled_shutdown_request(struct shutdown_req *req, int only_pointed_memory) 
{
  if(! only_pointed_memory)
    free(req);
}
void free_filled_socket_request(struct socket_req *req, int only_pointed_memory) 
{
  if(! only_pointed_memory)
    free(req);
}
void free_filled_stat64_request(struct stat64_req *req, int only_pointed_memory) 
{
  if(req->path != NULL)
    free(req->path);
  if(req->buf != NULL)
    free(req->buf);
  if(! only_pointed_memory)
    free(req);
}
void free_filled_statfs64_request(struct statfs64_req *req, int only_pointed_memory) 
{
  if(req->path != NULL)
    free(req->path);
  if(req->buf != NULL)
    free(req->buf);
  if(! only_pointed_memory)
    free(req);
}
void free_filled_symlink_request(struct symlink_req *req, int only_pointed_memory) 
{
  if(req->oldpath != NULL)
    free(req->oldpath);
  if(req->newpath != NULL)
    free(req->newpath);
  if(! only_pointed_memory)
    free(req);
}
void free_filled_truncate64_request(struct truncate64_req *req, int only_pointed_memory) 
{
  if(req->path != NULL)
    free(req->path);
  if(! only_pointed_memory)
    free(req);
}
void free_filled_umount2_request(struct umount2_req *req, int only_pointed_memory) 
{
  if(req->target != NULL)
    free(req->target);
  if(! only_pointed_memory)
    free(req);
}
void free_filled_uname_request(struct uname_req *req, int only_pointed_memory) 
{
  if(req->buf != NULL)
    free(req->buf);
  if(! only_pointed_memory)
    free(req);
}
void free_filled_unlink_request(struct unlink_req *req, int only_pointed_memory) 
{
  if(req->pathname != NULL)
    free(req->pathname);
  if(! only_pointed_memory)
    free(req);
}
void free_filled_utime_request(struct utime_req *req, int only_pointed_memory) 
{
  if(req->filename != NULL)
    free(req->filename);
  if(req->buf != NULL)
    free(req->buf);
  if(! only_pointed_memory)
    free(req);
}
void free_filled_utimes_request(struct utimes_req *req, int only_pointed_memory) 
{
  if(req->filename != NULL)
    free(req->filename);
  if(! only_pointed_memory)
    free(req);
}
void free_filled_write_request(struct write_req *req, int only_pointed_memory) 
{
  if(req->buf != NULL)
    free(req->buf);
  if(! only_pointed_memory)
    free(req);
}

void free_filled_fcntl_request(struct fcntl_req *req, int only_pointed_memory) 
{
  if(req->cmd_type & FCNTL_3RD_FLOCK)
    free(req->third.lock);
  if(! only_pointed_memory)
    free(req);
}


void free_filled_ioctl_request(struct ioctl_req *req, int only_pointed_memory) 
{
  if(req->arg != NULL)
    free(req->arg);
  if(! only_pointed_memory)
    free(req);
}

struct ioctl_req *fill_ioctl_request(int arg_null, int how)
{
  struct ioctl_req *request;
  char *arg;
  int size_arg;
    
  request = calloc(1, sizeof(struct ioctl_req));
  assert(!(request == NULL));

  if(arg_null) {
    size_arg = 0;
    arg = NULL;
  } else {
    size_arg = 100;
    arg = calloc(1, size_arg);
    assert(!(arg == NULL));
    /* Fill the buffer */
    memset(arg, 'a', size_arg);
  }
  
  request->arg = arg;
  request->req_type = htonl(__RSC_ioctl);
  request->req_size = htonl(sizeof(struct ioctl_req) + size_arg);

  request->d = 10;
  switch(how) {
    case FILL_IOCTL_R:
      request->request = 10;
      break;
    case FILL_IOCTL_W:
      request->request = 20;
      break;
    default:
      request->request = 30;
      break;
  }
  

  return request;
}
