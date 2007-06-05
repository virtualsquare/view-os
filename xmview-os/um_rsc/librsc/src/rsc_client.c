/*   
 *   This is part of Remote System Call (RSC) Library.
 *
 *   rsc_client.c: client side functions 
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
#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>

#include "registered_callbacks.h"
#include "debug.h"
#include "utils.h"
#include "rsc_client.h"
#include "rsc_consts.h"

#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/uio.h>
#include <stdarg.h>


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
#ifndef RSCDEBUG
struct ioctl_cache_el {
  int request;
  u_int32_t size_type;
  struct ioctl_cache_el *prev;
  struct ioctl_cache_el *next;
};

struct ioctl_cache {
  struct ioctl_cache_el *first;
  struct ioctl_cache_el *last;
  int size;
  int nentry;
};
#else
#include "test_rsc_client.h"
#endif

#ifndef RSCDEBUG
static 
#endif
struct ioctl_cache *ioctl_cache_init(int size);


static enum arch my_arch;
static enum arch server_arch;
static int rsc_sockfd;
static int rsc_event_sub_fd;
#ifndef RSCDEBUG
static 
#endif
struct ioctl_cache *ioctl_cache;

int rscc_init(int client_fd, int event_sub_fd, struct reg_cbs **rc, enum arch c_arch, enum arch s_arch) {
  if(c_arch < ARCH_FIRST || c_arch > ARCH_LAST) 
    return -1;
  if(s_arch < ARCH_FIRST || s_arch > ARCH_LAST) 
    return -1;

  rsc_sockfd = client_fd;
  my_arch = c_arch;
  server_arch = s_arch;
  rsc_event_sub_fd = event_sub_fd;
  /* I init the event subscribe sub-module if there is a valid fd */
  if(event_sub_fd >= 0 && rc != NULL)  {
    if((*rc = rscc_es_init(event_sub_fd)) == NULL)
      return -1;
  }

  /* I init the ioctl cache */
  ioctl_cache = ioctl_cache_init(20);
  if(ioctl_cache == NULL)
    return -1;
  return 0;
}

/*########################################################################*/
/*##                                                                    ##*/
/*##  Remote System Call FUNCTIONS - Client side                        ##*/
/*##                                                                    ##*/
/*########################################################################*/


/*##########################################################*/
/*##                                                      ##*/
/*##  REQUEST CREATION FUNCTIONS                          ##*/
/*##                                                      ##*/
/*##########################################################*/

/* This function build the request for the system call '_llseek' */
struct iovec *rscc_create__llseek_request(int *total_size, int *iovec_count, unsigned int fd, unsigned long int offset_high, unsigned long int offset_low, loff_t *result, unsigned int whence) {
  struct _llseek_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  struct iovec *v;
  size_t vcount;

  /* If the destination architecture doesn't support this syscall, I return immediately */
  if(server_arch == ACONV_X86_64)
    return NULL;


  

  req_size = sizeof(struct _llseek_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_u_int_size(my_arch, server_arch);
    req_size += aconv_u_long_size(my_arch, server_arch);
    req_size += aconv_u_long_size(my_arch, server_arch);
    req_size += aconv_pointer_size(my_arch, server_arch);
    req_size += aconv_u_int_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
#ifdef __x86_64__ 
  return NULL;
#else
 
	if( (rsc_const = nr2rsc(__NR__llseek, NO_VALUE, my_arch)) == __RSC_ERROR ) {
    free(req);
	  return NULL;
  }
#endif
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->fd = fd; 
    req->offset_high = offset_high; 
    req->offset_low = offset_low; 
    req->result = result; 
    req->whence = whence; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_u_int(&fd, my_arch, server_arch, mem); mem += aconv_u_int_size(my_arch, server_arch);
    
    aconv_u_long(&offset_high, my_arch, server_arch, mem); mem += aconv_u_long_size(my_arch, server_arch);
    
    aconv_u_long(&offset_low, my_arch, server_arch, mem); mem += aconv_u_long_size(my_arch, server_arch);
    
    aconv_pointer(result, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
    aconv_u_int(&whence, my_arch, server_arch, mem); mem += aconv_u_int_size(my_arch, server_arch);
    
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 1;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct _llseek_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: fd = %u (0x%lX); offset_high = %lu (0x%lX); offset_low = %lu (0x%lX); result = %p (0x%lX); whence = %u (0x%lX)", req->fd, req->fd, req->offset_high, req->offset_high, req->offset_low, req->offset_low, req->result, req->result, req->whence, req->whence);

  return v;
}

/* This function build the request for the system call 'accept' */
struct iovec *rscc_create_accept_request(int *total_size, int *iovec_count, int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
  struct accept_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  int i;
  struct iovec *v;
  size_t vcount;


  int addrlen_size_value;
  /* The size of 'addr' is contained in the memory pointed by 'addrlen',
   * but if the latter is NULL I cannot know the size of 'addr'. */
  if(addr != NULL && addrlen == NULL)
    return NULL;
  

  req_size = sizeof(struct accept_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_int_size(my_arch, server_arch);
    req_size += aconv_pointer_size(my_arch, server_arch);
    req_size += aconv_pointer_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
#ifdef __x86_64__
	if( (rsc_const = nr2rsc(__NR_accept, SYS_ACCEPT, my_arch)) == __RSC_ERROR ) {
#else
	if( (rsc_const = nr2rsc(__NR_socketcall, SYS_ACCEPT, my_arch)) == __RSC_ERROR ) {
#endif
    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  if(addrlen == NULL)
    addrlen_size_value = 0;
  else
    addrlen_size_value = aconv_socklen_t_size(my_arch, server_arch);
  req->req_size += addrlen_size_value;
  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->sockfd = sockfd; 
    req->addr = addr; 
    req->addrlen = addrlen; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_int(&sockfd, my_arch, server_arch, mem); mem += aconv_int_size(my_arch, server_arch);
    
    aconv_pointer(addr, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
    aconv_pointer(addrlen, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 2;
  if(addrlen == NULL)
    vcount--;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
  i = 1;
 
  if(addrlen != NULL) {
    v[i].iov_len =  addrlen_size_value;
    if(my_arch == server_arch) {
      v[i].iov_base = addrlen;
    } else {
      socklen_t  addrlen_new = *addrlen;

      v[i].iov_base = malloc(v[i].iov_len);
      if(v[i].iov_base == NULL)
        return NULL;
      if(*addrlen < aconv_struct_sockaddr_size(my_arch, server_arch))
        addrlen_new = aconv_struct_sockaddr_size(my_arch, server_arch);
      aconv_socklen_t(&addrlen_new, my_arch, server_arch, v[i].iov_base);
    }
    *total_size += v[i].iov_len;
     
  }
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct accept_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: sockfd = %ld (0x%lX); addr = %p (0x%lX); addrlen = %p (0x%lX)", req->sockfd, req->sockfd, req->addr, req->addr, req->addrlen, req->addrlen);

  return v;
}

/* This function build the request for the system call 'access' */
struct iovec *rscc_create_access_request(int *total_size, int *iovec_count, char *pathname, int mode) {
  struct access_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  int i;
  struct iovec *v;
  size_t vcount;


  int pathname_size_value;
  

  req_size = sizeof(struct access_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_pointer_size(my_arch, server_arch);
    req_size += aconv_int_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
	if( (rsc_const = nr2rsc(__NR_access, NO_VALUE, my_arch)) == __RSC_ERROR ) {
    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  if(pathname == NULL)
    pathname_size_value = 0;
  else
    pathname_size_value = aconv_string_size(pathname, my_arch, server_arch);
  req->req_size += pathname_size_value;
  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->pathname = pathname; 
    req->mode = mode; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_pointer(pathname, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
    aconv_int(&mode, my_arch, server_arch, mem); mem += aconv_int_size(my_arch, server_arch);
    
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 2;
  if(pathname == NULL)
    vcount--;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
  i = 1;
 
  if(pathname != NULL) {
    v[i].iov_len =  pathname_size_value;
    if(my_arch == server_arch) {
      v[i].iov_base = pathname;
    } else {

      v[i].iov_base = malloc(v[i].iov_len);
      if(v[i].iov_base == NULL)
        return NULL;
      aconv_string(pathname, my_arch, server_arch, v[i].iov_base);
    }
    *total_size += v[i].iov_len;
     
  }
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct access_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: pathname = %p (0x%lX); mode = %ld (0x%lX)", req->pathname, req->pathname, req->mode, req->mode);

  return v;
}

/* This function build the request for the system call 'adjtimex' */
struct iovec *rscc_create_adjtimex_request(int *total_size, int *iovec_count, struct timex *buf) {
  struct adjtimex_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  int i;
  struct iovec *v;
  size_t vcount;


  int buf_size_value;
  

  req_size = sizeof(struct adjtimex_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_pointer_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
	if( (rsc_const = nr2rsc(__NR_adjtimex, NO_VALUE, my_arch)) == __RSC_ERROR ) {
    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  if(buf == NULL)
    buf_size_value = 0;
  else
    buf_size_value = aconv_struct_timex_size(my_arch, server_arch);
  req->req_size += buf_size_value;
  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->buf = buf; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_pointer(buf, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 2;
  if(buf == NULL)
    vcount--;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
  i = 1;
 
  if(buf != NULL) {
    v[i].iov_len =  buf_size_value;
    if(my_arch == server_arch) {
      v[i].iov_base = buf;
    } else {

      v[i].iov_base = malloc(v[i].iov_len);
      if(v[i].iov_base == NULL)
        return NULL;
      aconv_struct_timex(buf, my_arch, server_arch, v[i].iov_base);
    }
    *total_size += v[i].iov_len;
     
  }
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct adjtimex_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: buf = %p (0x%lX)", req->buf, req->buf);

  return v;
}

/* This function build the request for the system call 'bind' */
struct iovec *rscc_create_bind_request(int *total_size, int *iovec_count, int sockfd, struct sockaddr *my_addr, socklen_t addrlen) {
  struct bind_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  int i;
  struct iovec *v;
  size_t vcount;


  socklen_t addrlen_value;
  

  req_size = sizeof(struct bind_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_int_size(my_arch, server_arch);
    req_size += aconv_pointer_size(my_arch, server_arch);
    req_size += aconv_socklen_t_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
#ifdef __x86_64__
	if( (rsc_const = nr2rsc(__NR_bind, SYS_BIND, my_arch)) == __RSC_ERROR ) {
#else
	if( (rsc_const = nr2rsc(__NR_socketcall, SYS_BIND, my_arch)) == __RSC_ERROR ) {
#endif
    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  if(my_addr == NULL)
    addrlen_value = 0;
  else
    addrlen_value = aconv_struct_sockaddr_size(my_arch, server_arch);
  req->req_size += addrlen_value;
  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->sockfd = sockfd; 
    req->my_addr = my_addr; 
    req->addrlen = addrlen; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    socklen_t addrlen_new = addrlen;
    aconv_int(&sockfd, my_arch, server_arch, mem); mem += aconv_int_size(my_arch, server_arch);
    
    aconv_pointer(my_addr, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
    if(addrlen < aconv_struct_sockaddr_size(my_arch, server_arch))
      addrlen_new = aconv_struct_sockaddr_size(my_arch, server_arch);
    aconv_socklen_t(&addrlen_new, my_arch, server_arch, mem); mem += aconv_socklen_t_size(my_arch, server_arch);
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 2;
  if(my_addr == NULL)
    vcount--;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
  i = 1;
 
  if(my_addr != NULL) {
    v[i].iov_len =  addrlen_value;
    if(my_arch == server_arch) {
      v[i].iov_base = my_addr;
    } else {

      v[i].iov_base = malloc(v[i].iov_len);
      if(v[i].iov_base == NULL)
        return NULL;
      aconv_struct_sockaddr(my_addr, my_arch, server_arch, v[i].iov_base);
    }
    *total_size += v[i].iov_len;
     
  }
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct bind_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: sockfd = %ld (0x%lX); my_addr = %p (0x%lX); addrlen = %ld (0x%lX)", req->sockfd, req->sockfd, req->my_addr, req->my_addr, req->addrlen, req->addrlen);

  return v;
}

/* This function build the request for the system call 'chdir' */
struct iovec *rscc_create_chdir_request(int *total_size, int *iovec_count, char *path) {
  struct chdir_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  int i;
  struct iovec *v;
  size_t vcount;


  int path_size_value;
  

  req_size = sizeof(struct chdir_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_pointer_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
	if( (rsc_const = nr2rsc(__NR_chdir, NO_VALUE, my_arch)) == __RSC_ERROR ) {
    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  if(path == NULL)
    path_size_value = 0;
  else
    path_size_value = aconv_string_size(path, my_arch, server_arch);
  req->req_size += path_size_value;
  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->path = path; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_pointer(path, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 2;
  if(path == NULL)
    vcount--;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
  i = 1;
 
  if(path != NULL) {
    v[i].iov_len =  path_size_value;
    if(my_arch == server_arch) {
      v[i].iov_base = path;
    } else {

      v[i].iov_base = malloc(v[i].iov_len);
      if(v[i].iov_base == NULL)
        return NULL;
      aconv_string(path, my_arch, server_arch, v[i].iov_base);
    }
    *total_size += v[i].iov_len;
     
  }
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct chdir_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: path = %p (0x%lX)", req->path, req->path);

  return v;
}

/* This function build the request for the system call 'chmod' */
struct iovec *rscc_create_chmod_request(int *total_size, int *iovec_count, char *path, mode_t mode) {
  struct chmod_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  int i;
  struct iovec *v;
  size_t vcount;


  int path_size_value;
  

  req_size = sizeof(struct chmod_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_pointer_size(my_arch, server_arch);
    req_size += aconv_mode_t_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
	if( (rsc_const = nr2rsc(__NR_chmod, NO_VALUE, my_arch)) == __RSC_ERROR ) {
    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  if(path == NULL)
    path_size_value = 0;
  else
    path_size_value = aconv_string_size(path, my_arch, server_arch);
  req->req_size += path_size_value;
  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->path = path; 
    req->mode = mode; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_pointer(path, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
    aconv_mode_t(&mode, my_arch, server_arch, mem); mem += aconv_mode_t_size(my_arch, server_arch);
    
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 2;
  if(path == NULL)
    vcount--;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
  i = 1;
 
  if(path != NULL) {
    v[i].iov_len =  path_size_value;
    if(my_arch == server_arch) {
      v[i].iov_base = path;
    } else {

      v[i].iov_base = malloc(v[i].iov_len);
      if(v[i].iov_base == NULL)
        return NULL;
      aconv_string(path, my_arch, server_arch, v[i].iov_base);
    }
    *total_size += v[i].iov_len;
     
  }
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct chmod_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: path = %p (0x%lX); mode = %ld (0x%lX)", req->path, req->path, req->mode, req->mode);

  return v;
}

/* This function build the request for the system call 'chown' */
struct iovec *rscc_create_chown_request(int *total_size, int *iovec_count, char *path, uid_t owner, gid_t group) {
  struct chown_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  int i;
  struct iovec *v;
  size_t vcount;


  int path_size_value;
  

  req_size = sizeof(struct chown_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_pointer_size(my_arch, server_arch);
    req_size += aconv_uid_t_size(my_arch, server_arch);
    req_size += aconv_gid_t_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
	if( (rsc_const = nr2rsc(__NR_chown, NO_VALUE, my_arch)) == __RSC_ERROR ) {
    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  if(path == NULL)
    path_size_value = 0;
  else
    path_size_value = aconv_string_size(path, my_arch, server_arch);
  req->req_size += path_size_value;
  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->path = path; 
    req->owner = owner; 
    req->group = group; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_pointer(path, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
    aconv_uid_t(&owner, my_arch, server_arch, mem); mem += aconv_uid_t_size(my_arch, server_arch);
    
    aconv_gid_t(&group, my_arch, server_arch, mem); mem += aconv_gid_t_size(my_arch, server_arch);
    
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 2;
  if(path == NULL)
    vcount--;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
  i = 1;
 
  if(path != NULL) {
    v[i].iov_len =  path_size_value;
    if(my_arch == server_arch) {
      v[i].iov_base = path;
    } else {

      v[i].iov_base = malloc(v[i].iov_len);
      if(v[i].iov_base == NULL)
        return NULL;
      aconv_string(path, my_arch, server_arch, v[i].iov_base);
    }
    *total_size += v[i].iov_len;
     
  }
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct chown_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: path = %p (0x%lX); owner = %ld (0x%lX); group = %ld (0x%lX)", req->path, req->path, req->owner, req->owner, req->group, req->group);

  return v;
}

/* This function build the request for the system call 'chown32' */
struct iovec *rscc_create_chown32_request(int *total_size, int *iovec_count, char *path, uid_t owner, gid_t group) {
  struct chown32_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  int i;
  struct iovec *v;
  size_t vcount;

  /* If the destination architecture doesn't support this syscall, I return immediately */
  if(server_arch == ACONV_PPC || server_arch == ACONV_X86_64)
    return NULL;


  int path_size_value;
  

  req_size = sizeof(struct chown32_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_pointer_size(my_arch, server_arch);
    req_size += aconv_uid_t_size(my_arch, server_arch);
    req_size += aconv_gid_t_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
#ifdef __powerpc__ 
  return NULL;
#elif defined __x86_64__ 
  return NULL;
#else
 
	if( (rsc_const = nr2rsc(__NR_chown32, NO_VALUE, my_arch)) == __RSC_ERROR ) {
    free(req);
	  return NULL;
  }
#endif
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  if(path == NULL)
    path_size_value = 0;
  else
    path_size_value = aconv_string_size(path, my_arch, server_arch);
  req->req_size += path_size_value;
  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->path = path; 
    req->owner = owner; 
    req->group = group; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_pointer(path, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
    aconv_uid_t(&owner, my_arch, server_arch, mem); mem += aconv_uid_t_size(my_arch, server_arch);
    
    aconv_gid_t(&group, my_arch, server_arch, mem); mem += aconv_gid_t_size(my_arch, server_arch);
    
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 2;
  if(path == NULL)
    vcount--;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
  i = 1;
 
  if(path != NULL) {
    v[i].iov_len =  path_size_value;
    if(my_arch == server_arch) {
      v[i].iov_base = path;
    } else {

      v[i].iov_base = malloc(v[i].iov_len);
      if(v[i].iov_base == NULL)
        return NULL;
      aconv_string(path, my_arch, server_arch, v[i].iov_base);
    }
    *total_size += v[i].iov_len;
     
  }
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct chown32_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: path = %p (0x%lX); owner = %ld (0x%lX); group = %ld (0x%lX)", req->path, req->path, req->owner, req->owner, req->group, req->group);

  return v;
}

/* This function build the request for the system call 'clock_getres' */
struct iovec *rscc_create_clock_getres_request(int *total_size, int *iovec_count, clockid_t clk_id, struct timespec *res) {
  struct clock_getres_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  struct iovec *v;
  size_t vcount;


  

  req_size = sizeof(struct clock_getres_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_clockid_t_size(my_arch, server_arch);
    req_size += aconv_pointer_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
	if( (rsc_const = nr2rsc(__NR_clock_getres, NO_VALUE, my_arch)) == __RSC_ERROR ) {
    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->clk_id = clk_id; 
    req->res = res; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_clockid_t(&clk_id, my_arch, server_arch, mem); mem += aconv_clockid_t_size(my_arch, server_arch);
    
    aconv_pointer(res, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 1;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct clock_getres_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: clk_id = %ld (0x%lX); res = %p (0x%lX)", req->clk_id, req->clk_id, req->res, req->res);

  return v;
}

/* This function build the request for the system call 'clock_gettime' */
struct iovec *rscc_create_clock_gettime_request(int *total_size, int *iovec_count, clockid_t clk_id, struct timespec *tp) {
  struct clock_gettime_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  struct iovec *v;
  size_t vcount;


  

  req_size = sizeof(struct clock_gettime_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_clockid_t_size(my_arch, server_arch);
    req_size += aconv_pointer_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
	if( (rsc_const = nr2rsc(__NR_clock_gettime, NO_VALUE, my_arch)) == __RSC_ERROR ) {
    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->clk_id = clk_id; 
    req->tp = tp; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_clockid_t(&clk_id, my_arch, server_arch, mem); mem += aconv_clockid_t_size(my_arch, server_arch);
    
    aconv_pointer(tp, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 1;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct clock_gettime_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: clk_id = %ld (0x%lX); tp = %p (0x%lX)", req->clk_id, req->clk_id, req->tp, req->tp);

  return v;
}

/* This function build the request for the system call 'clock_settime' */
struct iovec *rscc_create_clock_settime_request(int *total_size, int *iovec_count, clockid_t clk_id, struct timespec *tp) {
  struct clock_settime_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  int i;
  struct iovec *v;
  size_t vcount;


  int tp_size_value;
  

  req_size = sizeof(struct clock_settime_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_clockid_t_size(my_arch, server_arch);
    req_size += aconv_pointer_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
	if( (rsc_const = nr2rsc(__NR_clock_settime, NO_VALUE, my_arch)) == __RSC_ERROR ) {
    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  if(tp == NULL)
    tp_size_value = 0;
  else
    tp_size_value = aconv_struct_timespec_size(my_arch, server_arch);
  req->req_size += tp_size_value;
  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->clk_id = clk_id; 
    req->tp = tp; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_clockid_t(&clk_id, my_arch, server_arch, mem); mem += aconv_clockid_t_size(my_arch, server_arch);
    
    aconv_pointer(tp, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 2;
  if(tp == NULL)
    vcount--;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
  i = 1;
 
  if(tp != NULL) {
    v[i].iov_len =  tp_size_value;
    if(my_arch == server_arch) {
      v[i].iov_base = tp;
    } else {

      v[i].iov_base = malloc(v[i].iov_len);
      if(v[i].iov_base == NULL)
        return NULL;
      aconv_struct_timespec(tp, my_arch, server_arch, v[i].iov_base);
    }
    *total_size += v[i].iov_len;
     
  }
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct clock_settime_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: clk_id = %ld (0x%lX); tp = %p (0x%lX)", req->clk_id, req->clk_id, req->tp, req->tp);

  return v;
}

/* This function build the request for the system call 'close' */
struct iovec *rscc_create_close_request(int *total_size, int *iovec_count, int fd) {
  struct close_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  struct iovec *v;
  size_t vcount;


  

  req_size = sizeof(struct close_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_int_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
	if( (rsc_const = nr2rsc(__NR_close, NO_VALUE, my_arch)) == __RSC_ERROR ) {
    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->fd = fd; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_int(&fd, my_arch, server_arch, mem); mem += aconv_int_size(my_arch, server_arch);
    
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 1;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct close_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: fd = %ld (0x%lX)", req->fd, req->fd);

  return v;
}

/* This function build the request for the system call 'connect' */
struct iovec *rscc_create_connect_request(int *total_size, int *iovec_count, int sockfd, struct sockaddr *serv_addr, socklen_t addrlen) {
  struct connect_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  int i;
  struct iovec *v;
  size_t vcount;


  socklen_t addrlen_value;
  

  req_size = sizeof(struct connect_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_int_size(my_arch, server_arch);
    req_size += aconv_pointer_size(my_arch, server_arch);
    req_size += aconv_socklen_t_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
#ifdef __x86_64__
	if( (rsc_const = nr2rsc(__NR_connect, SYS_CONNECT, my_arch)) == __RSC_ERROR ) {
#else
	if( (rsc_const = nr2rsc(__NR_socketcall, SYS_CONNECT, my_arch)) == __RSC_ERROR ) {
#endif
    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  if(serv_addr == NULL)
    addrlen_value = 0;
  else
    addrlen_value = aconv_struct_sockaddr_size(my_arch, server_arch);
  req->req_size += addrlen_value;
  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->sockfd = sockfd; 
    req->serv_addr = serv_addr; 
    req->addrlen = addrlen; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    socklen_t addrlen_new = addrlen;
    aconv_int(&sockfd, my_arch, server_arch, mem); mem += aconv_int_size(my_arch, server_arch);
    
    aconv_pointer(serv_addr, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
    if(addrlen < aconv_struct_sockaddr_size(my_arch, server_arch))
      addrlen_new = aconv_struct_sockaddr_size(my_arch, server_arch);
    aconv_socklen_t(&addrlen_new, my_arch, server_arch, mem); mem += aconv_socklen_t_size(my_arch, server_arch);
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 2;
  if(serv_addr == NULL)
    vcount--;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
  i = 1;
 
  if(serv_addr != NULL) {
    v[i].iov_len =  addrlen_value;
    if(my_arch == server_arch) {
      v[i].iov_base = serv_addr;
    } else {

      v[i].iov_base = malloc(v[i].iov_len);
      if(v[i].iov_base == NULL)
        return NULL;
      aconv_struct_sockaddr(serv_addr, my_arch, server_arch, v[i].iov_base);
    }
    *total_size += v[i].iov_len;
     
  }
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct connect_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: sockfd = %ld (0x%lX); serv_addr = %p (0x%lX); addrlen = %ld (0x%lX)", req->sockfd, req->sockfd, req->serv_addr, req->serv_addr, req->addrlen, req->addrlen);

  return v;
}

/* This function build the request for the system call 'dup' */
struct iovec *rscc_create_dup_request(int *total_size, int *iovec_count, int oldfd) {
  struct dup_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  struct iovec *v;
  size_t vcount;


  

  req_size = sizeof(struct dup_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_int_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
	if( (rsc_const = nr2rsc(__NR_dup, NO_VALUE, my_arch)) == __RSC_ERROR ) {
    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->oldfd = oldfd; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_int(&oldfd, my_arch, server_arch, mem); mem += aconv_int_size(my_arch, server_arch);
    
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 1;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct dup_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: oldfd = %ld (0x%lX)", req->oldfd, req->oldfd);

  return v;
}

/* This function build the request for the system call 'dup2' */
struct iovec *rscc_create_dup2_request(int *total_size, int *iovec_count, int oldfd, int newfd) {
  struct dup2_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  struct iovec *v;
  size_t vcount;


  

  req_size = sizeof(struct dup2_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_int_size(my_arch, server_arch);
    req_size += aconv_int_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
	if( (rsc_const = nr2rsc(__NR_dup2, NO_VALUE, my_arch)) == __RSC_ERROR ) {
    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->oldfd = oldfd; 
    req->newfd = newfd; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_int(&oldfd, my_arch, server_arch, mem); mem += aconv_int_size(my_arch, server_arch);
    
    aconv_int(&newfd, my_arch, server_arch, mem); mem += aconv_int_size(my_arch, server_arch);
    
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 1;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct dup2_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: oldfd = %ld (0x%lX); newfd = %ld (0x%lX)", req->oldfd, req->oldfd, req->newfd, req->newfd);

  return v;
}

/* This function build the request for the system call 'fchdir' */
struct iovec *rscc_create_fchdir_request(int *total_size, int *iovec_count, int fd) {
  struct fchdir_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  struct iovec *v;
  size_t vcount;


  

  req_size = sizeof(struct fchdir_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_int_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
	if( (rsc_const = nr2rsc(__NR_fchdir, NO_VALUE, my_arch)) == __RSC_ERROR ) {
    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->fd = fd; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_int(&fd, my_arch, server_arch, mem); mem += aconv_int_size(my_arch, server_arch);
    
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 1;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct fchdir_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: fd = %ld (0x%lX)", req->fd, req->fd);

  return v;
}

/* This function build the request for the system call 'fchmod' */
struct iovec *rscc_create_fchmod_request(int *total_size, int *iovec_count, int fildes, mode_t mode) {
  struct fchmod_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  struct iovec *v;
  size_t vcount;


  

  req_size = sizeof(struct fchmod_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_int_size(my_arch, server_arch);
    req_size += aconv_mode_t_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
	if( (rsc_const = nr2rsc(__NR_fchmod, NO_VALUE, my_arch)) == __RSC_ERROR ) {
    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->fildes = fildes; 
    req->mode = mode; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_int(&fildes, my_arch, server_arch, mem); mem += aconv_int_size(my_arch, server_arch);
    
    aconv_mode_t(&mode, my_arch, server_arch, mem); mem += aconv_mode_t_size(my_arch, server_arch);
    
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 1;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct fchmod_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: fildes = %ld (0x%lX); mode = %ld (0x%lX)", req->fildes, req->fildes, req->mode, req->mode);

  return v;
}

/* This function build the request for the system call 'fchown' */
struct iovec *rscc_create_fchown_request(int *total_size, int *iovec_count, int fd, uid_t owner, gid_t group) {
  struct fchown_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  struct iovec *v;
  size_t vcount;


  

  req_size = sizeof(struct fchown_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_int_size(my_arch, server_arch);
    req_size += aconv_uid_t_size(my_arch, server_arch);
    req_size += aconv_gid_t_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
	if( (rsc_const = nr2rsc(__NR_fchown, NO_VALUE, my_arch)) == __RSC_ERROR ) {
    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->fd = fd; 
    req->owner = owner; 
    req->group = group; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_int(&fd, my_arch, server_arch, mem); mem += aconv_int_size(my_arch, server_arch);
    
    aconv_uid_t(&owner, my_arch, server_arch, mem); mem += aconv_uid_t_size(my_arch, server_arch);
    
    aconv_gid_t(&group, my_arch, server_arch, mem); mem += aconv_gid_t_size(my_arch, server_arch);
    
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 1;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct fchown_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: fd = %ld (0x%lX); owner = %ld (0x%lX); group = %ld (0x%lX)", req->fd, req->fd, req->owner, req->owner, req->group, req->group);

  return v;
}

/* This function build the request for the system call 'fchown32' */
struct iovec *rscc_create_fchown32_request(int *total_size, int *iovec_count, int fd, uid_t owner, gid_t group) {
  struct fchown32_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  struct iovec *v;
  size_t vcount;

  /* If the destination architecture doesn't support this syscall, I return immediately */
  if(server_arch == ACONV_PPC || server_arch == ACONV_X86_64)
    return NULL;


  

  req_size = sizeof(struct fchown32_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_int_size(my_arch, server_arch);
    req_size += aconv_uid_t_size(my_arch, server_arch);
    req_size += aconv_gid_t_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
#ifdef __powerpc__ 
  return NULL;
#elif defined __x86_64__ 
  return NULL;
#else
 
	if( (rsc_const = nr2rsc(__NR_fchown32, NO_VALUE, my_arch)) == __RSC_ERROR ) {
    free(req);
	  return NULL;
  }
#endif
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->fd = fd; 
    req->owner = owner; 
    req->group = group; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_int(&fd, my_arch, server_arch, mem); mem += aconv_int_size(my_arch, server_arch);
    
    aconv_uid_t(&owner, my_arch, server_arch, mem); mem += aconv_uid_t_size(my_arch, server_arch);
    
    aconv_gid_t(&group, my_arch, server_arch, mem); mem += aconv_gid_t_size(my_arch, server_arch);
    
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 1;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct fchown32_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: fd = %ld (0x%lX); owner = %ld (0x%lX); group = %ld (0x%lX)", req->fd, req->fd, req->owner, req->owner, req->group, req->group);

  return v;
}

/* This function build the request for the system call 'fdatasync' */
struct iovec *rscc_create_fdatasync_request(int *total_size, int *iovec_count, int fd) {
  struct fdatasync_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  struct iovec *v;
  size_t vcount;


  

  req_size = sizeof(struct fdatasync_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_int_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
	if( (rsc_const = nr2rsc(__NR_fdatasync, NO_VALUE, my_arch)) == __RSC_ERROR ) {
    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->fd = fd; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_int(&fd, my_arch, server_arch, mem); mem += aconv_int_size(my_arch, server_arch);
    
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 1;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct fdatasync_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: fd = %ld (0x%lX)", req->fd, req->fd);

  return v;
}

/* This function build the request for the system call 'fgetxattr' */
struct iovec *rscc_create_fgetxattr_request(int *total_size, int *iovec_count, int filedes, char *name, void *value, size_t size) {
  struct fgetxattr_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  int i;
  struct iovec *v;
  size_t vcount;


  int name_size_value;
  

  req_size = sizeof(struct fgetxattr_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_int_size(my_arch, server_arch);
    req_size += aconv_pointer_size(my_arch, server_arch);
    req_size += aconv_pointer_size(my_arch, server_arch);
    req_size += aconv_size_t_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
	if( (rsc_const = nr2rsc(__NR_fgetxattr, NO_VALUE, my_arch)) == __RSC_ERROR ) {
    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  if(name == NULL)
    name_size_value = 0;
  else
    name_size_value = aconv_string_size(name, my_arch, server_arch);
  req->req_size += name_size_value;
  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->filedes = filedes; 
    req->name = name; 
    req->value = value; 
    req->size = size; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_int(&filedes, my_arch, server_arch, mem); mem += aconv_int_size(my_arch, server_arch);
    
    aconv_pointer(name, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
    aconv_pointer(value, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
    aconv_size_t(&size, my_arch, server_arch, mem); mem += aconv_size_t_size(my_arch, server_arch);
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 2;
  if(name == NULL)
    vcount--;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
  i = 1;
 
  if(name != NULL) {
    v[i].iov_len =  name_size_value;
    if(my_arch == server_arch) {
      v[i].iov_base = name;
    } else {

      v[i].iov_base = malloc(v[i].iov_len);
      if(v[i].iov_base == NULL)
        return NULL;
      aconv_string(name, my_arch, server_arch, v[i].iov_base);
    }
    *total_size += v[i].iov_len;
     
  }
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct fgetxattr_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: filedes = %ld (0x%lX); name = %p (0x%lX); value = %p (0x%lX); size = %ld (0x%lX)", req->filedes, req->filedes, req->name, req->name, req->value, req->value, req->size, req->size);

  return v;
}

/* This function build the request for the system call 'fstat64' */
struct iovec *rscc_create_fstat64_request(int *total_size, int *iovec_count, int filedes, struct stat64 *buf) {
  struct fstat64_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  struct iovec *v;
  size_t vcount;


  

  req_size = sizeof(struct fstat64_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_int_size(my_arch, server_arch);
    req_size += aconv_pointer_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
#ifdef __x86_64__
	if( (rsc_const = nr2rsc(__NR_fstat, NO_VALUE, my_arch)) == __RSC_ERROR ) {
#else
	if( (rsc_const = nr2rsc(__NR_fstat64, NO_VALUE, my_arch)) == __RSC_ERROR ) {
#endif

    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->filedes = filedes; 
    req->buf = buf; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_int(&filedes, my_arch, server_arch, mem); mem += aconv_int_size(my_arch, server_arch);
    
    aconv_pointer(buf, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 1;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct fstat64_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: filedes = %ld (0x%lX); buf = %p (0x%lX)", req->filedes, req->filedes, req->buf, req->buf);

  return v;
}

/* This function build the request for the system call 'fstatfs64' */
struct iovec *rscc_create_fstatfs64_request(int *total_size, int *iovec_count, unsigned int fd, struct statfs64 *buf) {
  struct fstatfs64_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  struct iovec *v;
  size_t vcount;


  

  req_size = sizeof(struct fstatfs64_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_u_int_size(my_arch, server_arch);
    req_size += aconv_pointer_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
#ifdef __x86_64__
	if( (rsc_const = nr2rsc(__NR_fstatfs, NO_VALUE, my_arch)) == __RSC_ERROR ) {
#else
	if( (rsc_const = nr2rsc(__NR_fstatfs64, NO_VALUE, my_arch)) == __RSC_ERROR ) {
#endif

    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->fd = fd; 
    req->buf = buf; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_u_int(&fd, my_arch, server_arch, mem); mem += aconv_u_int_size(my_arch, server_arch);
    
    aconv_pointer(buf, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 1;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct fstatfs64_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: fd = %u (0x%lX); buf = %p (0x%lX)", req->fd, req->fd, req->buf, req->buf);

  return v;
}

/* This function build the request for the system call 'fsync' */
struct iovec *rscc_create_fsync_request(int *total_size, int *iovec_count, int fd) {
  struct fsync_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  struct iovec *v;
  size_t vcount;


  

  req_size = sizeof(struct fsync_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_int_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
	if( (rsc_const = nr2rsc(__NR_fsync, NO_VALUE, my_arch)) == __RSC_ERROR ) {
    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->fd = fd; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_int(&fd, my_arch, server_arch, mem); mem += aconv_int_size(my_arch, server_arch);
    
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 1;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct fsync_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: fd = %ld (0x%lX)", req->fd, req->fd);

  return v;
}

/* This function build the request for the system call 'ftruncate64' */
struct iovec *rscc_create_ftruncate64_request(int *total_size, int *iovec_count, int fd, __off64_t length) {
  struct ftruncate64_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  struct iovec *v;
  size_t vcount;


  

  req_size = sizeof(struct ftruncate64_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_int_size(my_arch, server_arch);
    req_size += aconv___off64_t_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
#ifdef __x86_64__
	if( (rsc_const = nr2rsc(__NR_ftruncate, NO_VALUE, my_arch)) == __RSC_ERROR ) {
#else
	if( (rsc_const = nr2rsc(__NR_ftruncate64, NO_VALUE, my_arch)) == __RSC_ERROR ) {
#endif

    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->fd = fd; 
    req->length = length; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_int(&fd, my_arch, server_arch, mem); mem += aconv_int_size(my_arch, server_arch);
    
    aconv___off64_t(&length, my_arch, server_arch, mem); mem += aconv___off64_t_size(my_arch, server_arch);
    
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 1;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct ftruncate64_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: fd = %ld (0x%lX); length = %ld (0x%lX)", req->fd, req->fd, req->length, req->length);

  return v;
}

/* This function build the request for the system call 'getdents64' */
struct iovec *rscc_create_getdents64_request(int *total_size, int *iovec_count, unsigned int fd, struct dirent64 *dirp, unsigned int count) {
  struct getdents64_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  struct iovec *v;
  size_t vcount;


  

  req_size = sizeof(struct getdents64_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_u_int_size(my_arch, server_arch);
    req_size += aconv_pointer_size(my_arch, server_arch);
    req_size += aconv_u_int_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
	if( (rsc_const = nr2rsc(__NR_getdents64, NO_VALUE, my_arch)) == __RSC_ERROR ) {
    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->fd = fd; 
    req->dirp = dirp; 
    req->count = count; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    unsigned int count_new = count;
    aconv_u_int(&fd, my_arch, server_arch, mem); mem += aconv_u_int_size(my_arch, server_arch);
    
    aconv_pointer(dirp, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
    if(count < aconv_struct_dirent64_size(my_arch, server_arch))
      count_new = aconv_struct_dirent64_size(my_arch, server_arch);
    aconv_u_int(&count_new, my_arch, server_arch, mem); mem += aconv_u_int_size(my_arch, server_arch);
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 1;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct getdents64_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: fd = %u (0x%lX); dirp = %p (0x%lX); count = %u (0x%lX)", req->fd, req->fd, req->dirp, req->dirp, req->count, req->count);

  return v;
}

/* This function build the request for the system call 'getpeername' */
struct iovec *rscc_create_getpeername_request(int *total_size, int *iovec_count, int s, struct sockaddr *name, socklen_t *namelen) {
  struct getpeername_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  int i;
  struct iovec *v;
  size_t vcount;


  int namelen_size_value;
  /* The size of 'name' is contained in the memory pointed by 'namelen',
   * but if the latter is NULL I cannot know the size of 'name'. */
  if(name != NULL && namelen == NULL)
    return NULL;
  

  req_size = sizeof(struct getpeername_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_int_size(my_arch, server_arch);
    req_size += aconv_pointer_size(my_arch, server_arch);
    req_size += aconv_pointer_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
#ifdef __x86_64__
	if( (rsc_const = nr2rsc(__NR_getpeername, SYS_GETPEERNAME, my_arch)) == __RSC_ERROR ) {
#else
	if( (rsc_const = nr2rsc(__NR_socketcall, SYS_GETPEERNAME, my_arch)) == __RSC_ERROR ) {
#endif
    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  if(namelen == NULL)
    namelen_size_value = 0;
  else
    namelen_size_value = aconv_socklen_t_size(my_arch, server_arch);
  req->req_size += namelen_size_value;
  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->s = s; 
    req->name = name; 
    req->namelen = namelen; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_int(&s, my_arch, server_arch, mem); mem += aconv_int_size(my_arch, server_arch);
    
    aconv_pointer(name, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
    aconv_pointer(namelen, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 2;
  if(namelen == NULL)
    vcount--;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
  i = 1;
 
  if(namelen != NULL) {
    v[i].iov_len =  namelen_size_value;
    if(my_arch == server_arch) {
      v[i].iov_base = namelen;
    } else {
      socklen_t  namelen_new = *namelen;

      v[i].iov_base = malloc(v[i].iov_len);
      if(v[i].iov_base == NULL)
        return NULL;
      if(*namelen < aconv_struct_sockaddr_size(my_arch, server_arch))
        namelen_new = aconv_struct_sockaddr_size(my_arch, server_arch);
      aconv_socklen_t(&namelen_new, my_arch, server_arch, v[i].iov_base);
    }
    *total_size += v[i].iov_len;
     
  }
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct getpeername_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: s = %ld (0x%lX); name = %p (0x%lX); namelen = %p (0x%lX)", req->s, req->s, req->name, req->name, req->namelen, req->namelen);

  return v;
}

/* This function build the request for the system call 'getsockname' */
struct iovec *rscc_create_getsockname_request(int *total_size, int *iovec_count, int s, struct sockaddr *name, socklen_t *namelen) {
  struct getsockname_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  int i;
  struct iovec *v;
  size_t vcount;


  int namelen_size_value;
  /* The size of 'name' is contained in the memory pointed by 'namelen',
   * but if the latter is NULL I cannot know the size of 'name'. */
  if(name != NULL && namelen == NULL)
    return NULL;
  

  req_size = sizeof(struct getsockname_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_int_size(my_arch, server_arch);
    req_size += aconv_pointer_size(my_arch, server_arch);
    req_size += aconv_pointer_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
#ifdef __x86_64__
	if( (rsc_const = nr2rsc(__NR_getsockname, SYS_GETSOCKNAME, my_arch)) == __RSC_ERROR ) {
#else
	if( (rsc_const = nr2rsc(__NR_socketcall, SYS_GETSOCKNAME, my_arch)) == __RSC_ERROR ) {
#endif
    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  if(namelen == NULL)
    namelen_size_value = 0;
  else
    namelen_size_value = aconv_socklen_t_size(my_arch, server_arch);
  req->req_size += namelen_size_value;
  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->s = s; 
    req->name = name; 
    req->namelen = namelen; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_int(&s, my_arch, server_arch, mem); mem += aconv_int_size(my_arch, server_arch);
    
    aconv_pointer(name, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
    aconv_pointer(namelen, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 2;
  if(namelen == NULL)
    vcount--;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
  i = 1;
 
  if(namelen != NULL) {
    v[i].iov_len =  namelen_size_value;
    if(my_arch == server_arch) {
      v[i].iov_base = namelen;
    } else {
      socklen_t  namelen_new = *namelen;

      v[i].iov_base = malloc(v[i].iov_len);
      if(v[i].iov_base == NULL)
        return NULL;
      if(*namelen < aconv_struct_sockaddr_size(my_arch, server_arch))
        namelen_new = aconv_struct_sockaddr_size(my_arch, server_arch);
      aconv_socklen_t(&namelen_new, my_arch, server_arch, v[i].iov_base);
    }
    *total_size += v[i].iov_len;
     
  }
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct getsockname_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: s = %ld (0x%lX); name = %p (0x%lX); namelen = %p (0x%lX)", req->s, req->s, req->name, req->name, req->namelen, req->namelen);

  return v;
}

/* This function build the request for the system call 'getsockopt' */
struct iovec *rscc_create_getsockopt_request(int *total_size, int *iovec_count, int s, int level, int optname, void *optval, socklen_t *optlen) {
  struct getsockopt_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  int i;
  struct iovec *v;
  size_t vcount;


  int optlen_size_value;
  /* The size of 'optval' is contained in the memory pointed by 'optlen',
   * but if the latter is NULL I cannot know the size of 'optval'. */
  if(optval != NULL && optlen == NULL)
    return NULL;
  

  req_size = sizeof(struct getsockopt_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_int_size(my_arch, server_arch);
    req_size += aconv_int_size(my_arch, server_arch);
    req_size += aconv_int_size(my_arch, server_arch);
    req_size += aconv_pointer_size(my_arch, server_arch);
    req_size += aconv_pointer_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
#ifdef __x86_64__
	if( (rsc_const = nr2rsc(__NR_getsockopt, SYS_GETSOCKOPT, my_arch)) == __RSC_ERROR ) {
#else
	if( (rsc_const = nr2rsc(__NR_socketcall, SYS_GETSOCKOPT, my_arch)) == __RSC_ERROR ) {
#endif
    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  if(optlen == NULL)
    optlen_size_value = 0;
  else
    optlen_size_value = aconv_socklen_t_size(my_arch, server_arch);
  req->req_size += optlen_size_value;
  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->s = s; 
    req->level = level; 
    req->optname = optname; 
    req->optval = optval; 
    req->optlen = optlen; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_int(&s, my_arch, server_arch, mem); mem += aconv_int_size(my_arch, server_arch);
    
    aconv_int(&level, my_arch, server_arch, mem); mem += aconv_int_size(my_arch, server_arch);
    
    aconv_int(&optname, my_arch, server_arch, mem); mem += aconv_int_size(my_arch, server_arch);
    
    aconv_pointer(optval, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
    aconv_pointer(optlen, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 2;
  if(optlen == NULL)
    vcount--;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
  i = 1;
 
  if(optlen != NULL) {
    v[i].iov_len =  optlen_size_value;
    if(my_arch == server_arch) {
      v[i].iov_base = optlen;
    } else {

      v[i].iov_base = malloc(v[i].iov_len);
      if(v[i].iov_base == NULL)
        return NULL;
      aconv_socklen_t(optlen, my_arch, server_arch, v[i].iov_base);
    }
    *total_size += v[i].iov_len;
     
  }
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct getsockopt_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: s = %ld (0x%lX); level = %ld (0x%lX); optname = %ld (0x%lX); optval = %p (0x%lX); optlen = %p (0x%lX)", req->s, req->s, req->level, req->level, req->optname, req->optname, req->optval, req->optval, req->optlen, req->optlen);

  return v;
}

/* This function build the request for the system call 'gettimeofday' */
struct iovec *rscc_create_gettimeofday_request(int *total_size, int *iovec_count, struct timeval *tv, struct timezone *tz) {
  struct gettimeofday_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  struct iovec *v;
  size_t vcount;


  

  req_size = sizeof(struct gettimeofday_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_pointer_size(my_arch, server_arch);
    req_size += aconv_pointer_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
	if( (rsc_const = nr2rsc(__NR_gettimeofday, NO_VALUE, my_arch)) == __RSC_ERROR ) {
    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->tv = tv; 
    req->tz = tz; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_pointer(tv, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
    aconv_pointer(tz, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 1;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct gettimeofday_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: tv = %p (0x%lX); tz = %p (0x%lX)", req->tv, req->tv, req->tz, req->tz);

  return v;
}

/* This function build the request for the system call 'getxattr' */
struct iovec *rscc_create_getxattr_request(int *total_size, int *iovec_count, char *path, char *name, void *value, size_t size) {
  struct getxattr_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  int i;
  struct iovec *v;
  size_t vcount;


  int path_size_value;
  int name_size_value;
  

  req_size = sizeof(struct getxattr_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_pointer_size(my_arch, server_arch);
    req_size += aconv_pointer_size(my_arch, server_arch);
    req_size += aconv_pointer_size(my_arch, server_arch);
    req_size += aconv_size_t_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
	if( (rsc_const = nr2rsc(__NR_getxattr, NO_VALUE, my_arch)) == __RSC_ERROR ) {
    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  if(path == NULL)
    path_size_value = 0;
  else
    path_size_value = aconv_string_size(path, my_arch, server_arch);
  if(name == NULL)
    name_size_value = 0;
  else
    name_size_value = aconv_string_size(name, my_arch, server_arch);
  req->req_size += path_size_value + name_size_value;
  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->path = path; 
    req->name = name; 
    req->value = value; 
    req->size = size; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_pointer(path, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
    aconv_pointer(name, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
    aconv_pointer(value, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
    aconv_size_t(&size, my_arch, server_arch, mem); mem += aconv_size_t_size(my_arch, server_arch);
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 3;
  if(path == NULL)
    vcount--;
  if(name == NULL)
    vcount--;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
  i = 1;
 
  if(path != NULL) {
    v[i].iov_len =  path_size_value;
    if(my_arch == server_arch) {
      v[i].iov_base = path;
    } else {

      v[i].iov_base = malloc(v[i].iov_len);
      if(v[i].iov_base == NULL)
        return NULL;
      aconv_string(path, my_arch, server_arch, v[i].iov_base);
    }
    *total_size += v[i].iov_len;
    i++; 
  }
 
  if(name != NULL) {
    v[i].iov_len =  name_size_value;
    if(my_arch == server_arch) {
      v[i].iov_base = name;
    } else {

      v[i].iov_base = malloc(v[i].iov_len);
      if(v[i].iov_base == NULL)
        return NULL;
      aconv_string(name, my_arch, server_arch, v[i].iov_base);
    }
    *total_size += v[i].iov_len;
     
  }
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct getxattr_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: path = %p (0x%lX); name = %p (0x%lX); value = %p (0x%lX); size = %ld (0x%lX)", req->path, req->path, req->name, req->name, req->value, req->value, req->size, req->size);

  return v;
}

/* This function build the request for the system call 'lchown' */
struct iovec *rscc_create_lchown_request(int *total_size, int *iovec_count, char *path, uid_t owner, gid_t group) {
  struct lchown_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  int i;
  struct iovec *v;
  size_t vcount;


  int path_size_value;
  

  req_size = sizeof(struct lchown_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_pointer_size(my_arch, server_arch);
    req_size += aconv_uid_t_size(my_arch, server_arch);
    req_size += aconv_gid_t_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
	if( (rsc_const = nr2rsc(__NR_lchown, NO_VALUE, my_arch)) == __RSC_ERROR ) {
    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  if(path == NULL)
    path_size_value = 0;
  else
    path_size_value = aconv_string_size(path, my_arch, server_arch);
  req->req_size += path_size_value;
  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->path = path; 
    req->owner = owner; 
    req->group = group; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_pointer(path, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
    aconv_uid_t(&owner, my_arch, server_arch, mem); mem += aconv_uid_t_size(my_arch, server_arch);
    
    aconv_gid_t(&group, my_arch, server_arch, mem); mem += aconv_gid_t_size(my_arch, server_arch);
    
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 2;
  if(path == NULL)
    vcount--;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
  i = 1;
 
  if(path != NULL) {
    v[i].iov_len =  path_size_value;
    if(my_arch == server_arch) {
      v[i].iov_base = path;
    } else {

      v[i].iov_base = malloc(v[i].iov_len);
      if(v[i].iov_base == NULL)
        return NULL;
      aconv_string(path, my_arch, server_arch, v[i].iov_base);
    }
    *total_size += v[i].iov_len;
     
  }
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct lchown_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: path = %p (0x%lX); owner = %ld (0x%lX); group = %ld (0x%lX)", req->path, req->path, req->owner, req->owner, req->group, req->group);

  return v;
}

/* This function build the request for the system call 'lchown32' */
struct iovec *rscc_create_lchown32_request(int *total_size, int *iovec_count, char *path, uid_t owner, gid_t group) {
  struct lchown32_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  int i;
  struct iovec *v;
  size_t vcount;

  /* If the destination architecture doesn't support this syscall, I return immediately */
  if(server_arch == ACONV_PPC || server_arch == ACONV_X86_64)
    return NULL;


  int path_size_value;
  

  req_size = sizeof(struct lchown32_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_pointer_size(my_arch, server_arch);
    req_size += aconv_uid_t_size(my_arch, server_arch);
    req_size += aconv_gid_t_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
#ifdef __powerpc__ 
  return NULL;
#elif defined __x86_64__ 
  return NULL;
#else
 
#ifdef __x86_64__
	if( (rsc_const = nr2rsc(__NR_lchown32, NO_VALUE, my_arch)) == __RSC_ERROR ) {
#else
	if( (rsc_const = nr2rsc(__NR_lchown32, NO_VALUE, my_arch)) == __RSC_ERROR ) {
#endif

    free(req);
	  return NULL;
  }
#endif
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  if(path == NULL)
    path_size_value = 0;
  else
    path_size_value = aconv_string_size(path, my_arch, server_arch);
  req->req_size += path_size_value;
  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->path = path; 
    req->owner = owner; 
    req->group = group; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_pointer(path, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
    aconv_uid_t(&owner, my_arch, server_arch, mem); mem += aconv_uid_t_size(my_arch, server_arch);
    
    aconv_gid_t(&group, my_arch, server_arch, mem); mem += aconv_gid_t_size(my_arch, server_arch);
    
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 2;
  if(path == NULL)
    vcount--;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
  i = 1;
 
  if(path != NULL) {
    v[i].iov_len =  path_size_value;
    if(my_arch == server_arch) {
      v[i].iov_base = path;
    } else {

      v[i].iov_base = malloc(v[i].iov_len);
      if(v[i].iov_base == NULL)
        return NULL;
      aconv_string(path, my_arch, server_arch, v[i].iov_base);
    }
    *total_size += v[i].iov_len;
     
  }
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct lchown32_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: path = %p (0x%lX); owner = %ld (0x%lX); group = %ld (0x%lX)", req->path, req->path, req->owner, req->owner, req->group, req->group);

  return v;
}

/* This function build the request for the system call 'lgetxattr' */
struct iovec *rscc_create_lgetxattr_request(int *total_size, int *iovec_count, char *path, char *name, void *value, size_t size) {
  struct lgetxattr_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  int i;
  struct iovec *v;
  size_t vcount;


  int path_size_value;
  int name_size_value;
  

  req_size = sizeof(struct lgetxattr_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_pointer_size(my_arch, server_arch);
    req_size += aconv_pointer_size(my_arch, server_arch);
    req_size += aconv_pointer_size(my_arch, server_arch);
    req_size += aconv_size_t_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
	if( (rsc_const = nr2rsc(__NR_lgetxattr, NO_VALUE, my_arch)) == __RSC_ERROR ) {
    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  if(path == NULL)
    path_size_value = 0;
  else
    path_size_value = aconv_string_size(path, my_arch, server_arch);
  if(name == NULL)
    name_size_value = 0;
  else
    name_size_value = aconv_string_size(name, my_arch, server_arch);
  req->req_size += path_size_value + name_size_value;
  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->path = path; 
    req->name = name; 
    req->value = value; 
    req->size = size; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_pointer(path, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
    aconv_pointer(name, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
    aconv_pointer(value, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
    aconv_size_t(&size, my_arch, server_arch, mem); mem += aconv_size_t_size(my_arch, server_arch);
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 3;
  if(path == NULL)
    vcount--;
  if(name == NULL)
    vcount--;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
  i = 1;
 
  if(path != NULL) {
    v[i].iov_len =  path_size_value;
    if(my_arch == server_arch) {
      v[i].iov_base = path;
    } else {

      v[i].iov_base = malloc(v[i].iov_len);
      if(v[i].iov_base == NULL)
        return NULL;
      aconv_string(path, my_arch, server_arch, v[i].iov_base);
    }
    *total_size += v[i].iov_len;
    i++; 
  }
 
  if(name != NULL) {
    v[i].iov_len =  name_size_value;
    if(my_arch == server_arch) {
      v[i].iov_base = name;
    } else {

      v[i].iov_base = malloc(v[i].iov_len);
      if(v[i].iov_base == NULL)
        return NULL;
      aconv_string(name, my_arch, server_arch, v[i].iov_base);
    }
    *total_size += v[i].iov_len;
     
  }
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct lgetxattr_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: path = %p (0x%lX); name = %p (0x%lX); value = %p (0x%lX); size = %ld (0x%lX)", req->path, req->path, req->name, req->name, req->value, req->value, req->size, req->size);

  return v;
}

/* This function build the request for the system call 'link' */
struct iovec *rscc_create_link_request(int *total_size, int *iovec_count, char *oldpath, char *newpath) {
  struct link_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  int i;
  struct iovec *v;
  size_t vcount;


  int oldpath_size_value;
  int newpath_size_value;
  

  req_size = sizeof(struct link_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_pointer_size(my_arch, server_arch);
    req_size += aconv_pointer_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
	if( (rsc_const = nr2rsc(__NR_link, NO_VALUE, my_arch)) == __RSC_ERROR ) {
    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  if(oldpath == NULL)
    oldpath_size_value = 0;
  else
    oldpath_size_value = aconv_string_size(oldpath, my_arch, server_arch);
  if(newpath == NULL)
    newpath_size_value = 0;
  else
    newpath_size_value = aconv_string_size(newpath, my_arch, server_arch);
  req->req_size += oldpath_size_value + newpath_size_value;
  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->oldpath = oldpath; 
    req->newpath = newpath; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_pointer(oldpath, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
    aconv_pointer(newpath, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 3;
  if(oldpath == NULL)
    vcount--;
  if(newpath == NULL)
    vcount--;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
  i = 1;
 
  if(oldpath != NULL) {
    v[i].iov_len =  oldpath_size_value;
    if(my_arch == server_arch) {
      v[i].iov_base = oldpath;
    } else {

      v[i].iov_base = malloc(v[i].iov_len);
      if(v[i].iov_base == NULL)
        return NULL;
      aconv_string(oldpath, my_arch, server_arch, v[i].iov_base);
    }
    *total_size += v[i].iov_len;
    i++; 
  }
 
  if(newpath != NULL) {
    v[i].iov_len =  newpath_size_value;
    if(my_arch == server_arch) {
      v[i].iov_base = newpath;
    } else {

      v[i].iov_base = malloc(v[i].iov_len);
      if(v[i].iov_base == NULL)
        return NULL;
      aconv_string(newpath, my_arch, server_arch, v[i].iov_base);
    }
    *total_size += v[i].iov_len;
     
  }
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct link_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: oldpath = %p (0x%lX); newpath = %p (0x%lX)", req->oldpath, req->oldpath, req->newpath, req->newpath);

  return v;
}

/* This function build the request for the system call 'listen' */
struct iovec *rscc_create_listen_request(int *total_size, int *iovec_count, int sockfd, int backlog) {
  struct listen_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  struct iovec *v;
  size_t vcount;


  

  req_size = sizeof(struct listen_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_int_size(my_arch, server_arch);
    req_size += aconv_int_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
#ifdef __x86_64__
	if( (rsc_const = nr2rsc(__NR_listen, SYS_LISTEN, my_arch)) == __RSC_ERROR ) {
#else
	if( (rsc_const = nr2rsc(__NR_socketcall, SYS_LISTEN, my_arch)) == __RSC_ERROR ) {
#endif
    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->sockfd = sockfd; 
    req->backlog = backlog; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_int(&sockfd, my_arch, server_arch, mem); mem += aconv_int_size(my_arch, server_arch);
    
    aconv_int(&backlog, my_arch, server_arch, mem); mem += aconv_int_size(my_arch, server_arch);
    
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 1;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct listen_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: sockfd = %ld (0x%lX); backlog = %ld (0x%lX)", req->sockfd, req->sockfd, req->backlog, req->backlog);

  return v;
}

/* This function build the request for the system call 'lseek' */
struct iovec *rscc_create_lseek_request(int *total_size, int *iovec_count, int fildes, off_t offset, int whence) {
  struct lseek_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  struct iovec *v;
  size_t vcount;


  

  req_size = sizeof(struct lseek_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_int_size(my_arch, server_arch);
    req_size += aconv_off_t_size(my_arch, server_arch);
    req_size += aconv_int_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
	if( (rsc_const = nr2rsc(__NR_lseek, NO_VALUE, my_arch)) == __RSC_ERROR ) {
    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->fildes = fildes; 
    req->offset = offset; 
    req->whence = whence; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_int(&fildes, my_arch, server_arch, mem); mem += aconv_int_size(my_arch, server_arch);
    
    aconv_off_t(&offset, my_arch, server_arch, mem); mem += aconv_off_t_size(my_arch, server_arch);
    
    aconv_int(&whence, my_arch, server_arch, mem); mem += aconv_int_size(my_arch, server_arch);
    
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 1;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct lseek_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: fildes = %ld (0x%lX); offset = %ld (0x%lX); whence = %ld (0x%lX)", req->fildes, req->fildes, req->offset, req->offset, req->whence, req->whence);

  return v;
}

/* This function build the request for the system call 'lstat64' */
struct iovec *rscc_create_lstat64_request(int *total_size, int *iovec_count, char *path, struct stat64 *buf) {
  struct lstat64_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  int i;
  struct iovec *v;
  size_t vcount;


  int path_size_value;
  

  req_size = sizeof(struct lstat64_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_pointer_size(my_arch, server_arch);
    req_size += aconv_pointer_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
#ifdef __x86_64__
	if( (rsc_const = nr2rsc(__NR_lstat, NO_VALUE, my_arch)) == __RSC_ERROR ) {
#else
	if( (rsc_const = nr2rsc(__NR_lstat64, NO_VALUE, my_arch)) == __RSC_ERROR ) {
#endif

    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  if(path == NULL)
    path_size_value = 0;
  else
    path_size_value = aconv_string_size(path, my_arch, server_arch);
  req->req_size += path_size_value;
  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->path = path; 
    req->buf = buf; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_pointer(path, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
    aconv_pointer(buf, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 2;
  if(path == NULL)
    vcount--;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
  i = 1;
 
  if(path != NULL) {
    v[i].iov_len =  path_size_value;
    if(my_arch == server_arch) {
      v[i].iov_base = path;
    } else {

      v[i].iov_base = malloc(v[i].iov_len);
      if(v[i].iov_base == NULL)
        return NULL;
      aconv_string(path, my_arch, server_arch, v[i].iov_base);
    }
    *total_size += v[i].iov_len;
     
  }
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct lstat64_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: path = %p (0x%lX); buf = %p (0x%lX)", req->path, req->path, req->buf, req->buf);

  return v;
}

/* This function build the request for the system call 'mkdir' */
struct iovec *rscc_create_mkdir_request(int *total_size, int *iovec_count, char *pathname, mode_t mode) {
  struct mkdir_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  int i;
  struct iovec *v;
  size_t vcount;


  int pathname_size_value;
  

  req_size = sizeof(struct mkdir_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_pointer_size(my_arch, server_arch);
    req_size += aconv_mode_t_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
	if( (rsc_const = nr2rsc(__NR_mkdir, NO_VALUE, my_arch)) == __RSC_ERROR ) {
    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  if(pathname == NULL)
    pathname_size_value = 0;
  else
    pathname_size_value = aconv_string_size(pathname, my_arch, server_arch);
  req->req_size += pathname_size_value;
  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->pathname = pathname; 
    req->mode = mode; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_pointer(pathname, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
    aconv_mode_t(&mode, my_arch, server_arch, mem); mem += aconv_mode_t_size(my_arch, server_arch);
    
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 2;
  if(pathname == NULL)
    vcount--;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
  i = 1;
 
  if(pathname != NULL) {
    v[i].iov_len =  pathname_size_value;
    if(my_arch == server_arch) {
      v[i].iov_base = pathname;
    } else {

      v[i].iov_base = malloc(v[i].iov_len);
      if(v[i].iov_base == NULL)
        return NULL;
      aconv_string(pathname, my_arch, server_arch, v[i].iov_base);
    }
    *total_size += v[i].iov_len;
     
  }
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct mkdir_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: pathname = %p (0x%lX); mode = %ld (0x%lX)", req->pathname, req->pathname, req->mode, req->mode);

  return v;
}

/* This function build the request for the system call 'mount' */
struct iovec *rscc_create_mount_request(int *total_size, int *iovec_count, char *source, char *target, char *filesystemtype, unsigned long int mountflags, void *data) {
  struct mount_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  int i;
  struct iovec *v;
  size_t vcount;


  int source_size_value;
  int target_size_value;
  int filesystemtype_size_value;
  int data_size_value;
  

  req_size = sizeof(struct mount_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_pointer_size(my_arch, server_arch);
    req_size += aconv_pointer_size(my_arch, server_arch);
    req_size += aconv_pointer_size(my_arch, server_arch);
    req_size += aconv_u_long_size(my_arch, server_arch);
    req_size += aconv_pointer_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
	if( (rsc_const = nr2rsc(__NR_mount, NO_VALUE, my_arch)) == __RSC_ERROR ) {
    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  if(source == NULL)
    source_size_value = 0;
  else
    source_size_value = aconv_string_size(source, my_arch, server_arch);
  if(target == NULL)
    target_size_value = 0;
  else
    target_size_value = aconv_string_size(target, my_arch, server_arch);
  if(filesystemtype == NULL)
    filesystemtype_size_value = 0;
  else
    filesystemtype_size_value = aconv_string_size(filesystemtype, my_arch, server_arch);
  if(data == NULL)
    data_size_value = 0;
  else
    data_size_value = aconv_string_size(data, my_arch, server_arch);
  req->req_size += source_size_value + target_size_value + filesystemtype_size_value + data_size_value;
  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->source = source; 
    req->target = target; 
    req->filesystemtype = filesystemtype; 
    req->mountflags = mountflags; 
    req->data = data; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_pointer(source, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
    aconv_pointer(target, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
    aconv_pointer(filesystemtype, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
    aconv_u_long(&mountflags, my_arch, server_arch, mem); mem += aconv_u_long_size(my_arch, server_arch);
    
    aconv_pointer(data, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 5;
  if(source == NULL)
    vcount--;
  if(target == NULL)
    vcount--;
  if(filesystemtype == NULL)
    vcount--;
  if(data == NULL)
    vcount--;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
  i = 1;
 
  if(source != NULL) {
    v[i].iov_len =  source_size_value;
    if(my_arch == server_arch) {
      v[i].iov_base = source;
    } else {

      v[i].iov_base = malloc(v[i].iov_len);
      if(v[i].iov_base == NULL)
        return NULL;
      aconv_string(source, my_arch, server_arch, v[i].iov_base);
    }
    *total_size += v[i].iov_len;
    i++; 
  }
 
  if(target != NULL) {
    v[i].iov_len =  target_size_value;
    if(my_arch == server_arch) {
      v[i].iov_base = target;
    } else {

      v[i].iov_base = malloc(v[i].iov_len);
      if(v[i].iov_base == NULL)
        return NULL;
      aconv_string(target, my_arch, server_arch, v[i].iov_base);
    }
    *total_size += v[i].iov_len;
    i++; 
  }
 
  if(filesystemtype != NULL) {
    v[i].iov_len =  filesystemtype_size_value;
    if(my_arch == server_arch) {
      v[i].iov_base = filesystemtype;
    } else {

      v[i].iov_base = malloc(v[i].iov_len);
      if(v[i].iov_base == NULL)
        return NULL;
      aconv_string(filesystemtype, my_arch, server_arch, v[i].iov_base);
    }
    *total_size += v[i].iov_len;
    i++; 
  }
 
  if(data != NULL) {
    v[i].iov_len =  data_size_value;
    if(my_arch == server_arch) {
      v[i].iov_base = data;
    } else {

      v[i].iov_base = malloc(v[i].iov_len);
      if(v[i].iov_base == NULL)
        return NULL;
      aconv_string(data, my_arch, server_arch, v[i].iov_base);
    }
    *total_size += v[i].iov_len;
     
  }
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct mount_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: source = %p (0x%lX); target = %p (0x%lX); filesystemtype = %p (0x%lX); mountflags = %lu (0x%lX); data = %p (0x%lX)", req->source, req->source, req->target, req->target, req->filesystemtype, req->filesystemtype, req->mountflags, req->mountflags, req->data, req->data);

  return v;
}

/* This function build the request for the system call 'open' */
struct iovec *rscc_create_open_request(int *total_size, int *iovec_count, char *pathname, int flags) {
  struct open_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  int i;
  struct iovec *v;
  size_t vcount;


  int pathname_size_value;
  

  req_size = sizeof(struct open_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_pointer_size(my_arch, server_arch);
    req_size += aconv_int_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
	if( (rsc_const = nr2rsc(__NR_open, NO_VALUE, my_arch)) == __RSC_ERROR ) {
    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  if(pathname == NULL)
    pathname_size_value = 0;
  else
    pathname_size_value = aconv_string_size(pathname, my_arch, server_arch);
  req->req_size += pathname_size_value;
  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->pathname = pathname; 
    req->flags = flags; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_pointer(pathname, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
    aconv_int(&flags, my_arch, server_arch, mem); mem += aconv_int_size(my_arch, server_arch);
    
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 2;
  if(pathname == NULL)
    vcount--;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
  i = 1;
 
  if(pathname != NULL) {
    v[i].iov_len =  pathname_size_value;
    if(my_arch == server_arch) {
      v[i].iov_base = pathname;
    } else {

      v[i].iov_base = malloc(v[i].iov_len);
      if(v[i].iov_base == NULL)
        return NULL;
      aconv_string(pathname, my_arch, server_arch, v[i].iov_base);
    }
    *total_size += v[i].iov_len;
     
  }
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct open_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: pathname = %p (0x%lX); flags = %ld (0x%lX)", req->pathname, req->pathname, req->flags, req->flags);

  return v;
}

/* This function build the request for the system call 'pread64' */
struct iovec *rscc_create_pread64_request(int *total_size, int *iovec_count, int fd, void *buf, size_t count, off_t offset) {
  struct pread64_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  struct iovec *v;
  size_t vcount;


  

  req_size = sizeof(struct pread64_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_int_size(my_arch, server_arch);
    req_size += aconv_pointer_size(my_arch, server_arch);
    req_size += aconv_size_t_size(my_arch, server_arch);
    req_size += aconv_off_t_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
	if( (rsc_const = nr2rsc(__NR_pread64, NO_VALUE, my_arch)) == __RSC_ERROR ) {
    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->fd = fd; 
    req->buf = buf; 
    req->count = count; 
    req->offset = offset; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_int(&fd, my_arch, server_arch, mem); mem += aconv_int_size(my_arch, server_arch);
    
    aconv_pointer(buf, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
    aconv_size_t(&count, my_arch, server_arch, mem); mem += aconv_size_t_size(my_arch, server_arch);
    aconv_off_t(&offset, my_arch, server_arch, mem); mem += aconv_off_t_size(my_arch, server_arch);
    
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 1;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct pread64_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: fd = %ld (0x%lX); buf = %p (0x%lX); count = %ld (0x%lX); offset = %ld (0x%lX)", req->fd, req->fd, req->buf, req->buf, req->count, req->count, req->offset, req->offset);

  return v;
}

/* This function build the request for the system call 'pwrite64' */
struct iovec *rscc_create_pwrite64_request(int *total_size, int *iovec_count, int fd, void *buf, size_t count, off_t offset) {
  struct pwrite64_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  int i;
  struct iovec *v;
  size_t vcount;


  size_t count_value;
  

  req_size = sizeof(struct pwrite64_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_int_size(my_arch, server_arch);
    req_size += aconv_pointer_size(my_arch, server_arch);
    req_size += aconv_size_t_size(my_arch, server_arch);
    req_size += aconv_off_t_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
	if( (rsc_const = nr2rsc(__NR_pwrite64, NO_VALUE, my_arch)) == __RSC_ERROR ) {
    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  if(buf == NULL)
    count_value = 0;
  else
    count_value = aconv_bytes_size(count, my_arch, server_arch);
  req->req_size += count_value;
  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->fd = fd; 
    req->buf = buf; 
    req->count = count; 
    req->offset = offset; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_int(&fd, my_arch, server_arch, mem); mem += aconv_int_size(my_arch, server_arch);
    
    aconv_pointer(buf, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
    aconv_size_t(&count, my_arch, server_arch, mem); mem += aconv_size_t_size(my_arch, server_arch);
    aconv_off_t(&offset, my_arch, server_arch, mem); mem += aconv_off_t_size(my_arch, server_arch);
    
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 2;
  if(buf == NULL)
    vcount--;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
  i = 1;
 
  if(buf != NULL) {
    v[i].iov_len =  count_value;
    if(my_arch == server_arch) {
      v[i].iov_base = buf;
    } else {

      v[i].iov_base = malloc(v[i].iov_len);
      if(v[i].iov_base == NULL)
        return NULL;
      aconv_bytes(buf, my_arch, server_arch, v[i].iov_base, count);
    }
    *total_size += v[i].iov_len;
     
  }
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct pwrite64_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: fd = %ld (0x%lX); buf = %p (0x%lX); count = %ld (0x%lX); offset = %ld (0x%lX)", req->fd, req->fd, req->buf, req->buf, req->count, req->count, req->offset, req->offset);

  return v;
}

/* This function build the request for the system call 'read' */
struct iovec *rscc_create_read_request(int *total_size, int *iovec_count, int fd, void *buf, size_t count) {
  struct read_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  struct iovec *v;
  size_t vcount;


  

  req_size = sizeof(struct read_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_int_size(my_arch, server_arch);
    req_size += aconv_pointer_size(my_arch, server_arch);
    req_size += aconv_size_t_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
	if( (rsc_const = nr2rsc(__NR_read, NO_VALUE, my_arch)) == __RSC_ERROR ) {
    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->fd = fd; 
    req->buf = buf; 
    req->count = count; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_int(&fd, my_arch, server_arch, mem); mem += aconv_int_size(my_arch, server_arch);
    
    aconv_pointer(buf, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
    aconv_size_t(&count, my_arch, server_arch, mem); mem += aconv_size_t_size(my_arch, server_arch);
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 1;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct read_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: fd = %ld (0x%lX); buf = %p (0x%lX); count = %ld (0x%lX)", req->fd, req->fd, req->buf, req->buf, req->count, req->count);

  return v;
}

/* This function build the request for the system call 'readlink' */
struct iovec *rscc_create_readlink_request(int *total_size, int *iovec_count, char *path, char *buf, size_t bufsiz) {
  struct readlink_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  int i;
  struct iovec *v;
  size_t vcount;


  int path_size_value;
  

  req_size = sizeof(struct readlink_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_pointer_size(my_arch, server_arch);
    req_size += aconv_pointer_size(my_arch, server_arch);
    req_size += aconv_size_t_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
	if( (rsc_const = nr2rsc(__NR_readlink, NO_VALUE, my_arch)) == __RSC_ERROR ) {
    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  if(path == NULL)
    path_size_value = 0;
  else
    path_size_value = aconv_string_size(path, my_arch, server_arch);
  req->req_size += path_size_value;
  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->path = path; 
    req->buf = buf; 
    req->bufsiz = bufsiz; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_pointer(path, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
    aconv_pointer(buf, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
    aconv_size_t(&bufsiz, my_arch, server_arch, mem); mem += aconv_size_t_size(my_arch, server_arch);
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 2;
  if(path == NULL)
    vcount--;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
  i = 1;
 
  if(path != NULL) {
    v[i].iov_len =  path_size_value;
    if(my_arch == server_arch) {
      v[i].iov_base = path;
    } else {

      v[i].iov_base = malloc(v[i].iov_len);
      if(v[i].iov_base == NULL)
        return NULL;
      aconv_string(path, my_arch, server_arch, v[i].iov_base);
    }
    *total_size += v[i].iov_len;
     
  }
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct readlink_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: path = %p (0x%lX); buf = %p (0x%lX); bufsiz = %ld (0x%lX)", req->path, req->path, req->buf, req->buf, req->bufsiz, req->bufsiz);

  return v;
}

/* This function build the request for the system call 'recv' */
struct iovec *rscc_create_recv_request(int *total_size, int *iovec_count, int s, void *buf, size_t len, int flags) {
  struct recv_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  struct iovec *v;
  size_t vcount;

  /* If the destination architecture doesn't support this syscall, I return immediately */
  if(server_arch == ACONV_X86_64)
    return NULL;


  

  req_size = sizeof(struct recv_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_int_size(my_arch, server_arch);
    req_size += aconv_pointer_size(my_arch, server_arch);
    req_size += aconv_size_t_size(my_arch, server_arch);
    req_size += aconv_int_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
#ifdef __x86_64__ 
  return NULL;
#else
 
#ifdef __x86_64__
	if( (rsc_const = nr2rsc(__NR_recv, SYS_RECV, my_arch)) == __RSC_ERROR ) {
#else
	if( (rsc_const = nr2rsc(__NR_socketcall, SYS_RECV, my_arch)) == __RSC_ERROR ) {
#endif
    free(req);
	  return NULL;
  }
#endif
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->s = s; 
    req->buf = buf; 
    req->len = len; 
    req->flags = flags; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_int(&s, my_arch, server_arch, mem); mem += aconv_int_size(my_arch, server_arch);
    
    aconv_pointer(buf, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
    aconv_size_t(&len, my_arch, server_arch, mem); mem += aconv_size_t_size(my_arch, server_arch);
    aconv_int(&flags, my_arch, server_arch, mem); mem += aconv_int_size(my_arch, server_arch);
    
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 1;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct recv_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: s = %ld (0x%lX); buf = %p (0x%lX); len = %ld (0x%lX); flags = %ld (0x%lX)", req->s, req->s, req->buf, req->buf, req->len, req->len, req->flags, req->flags);

  return v;
}

/* This function build the request for the system call 'recvfrom' */
struct iovec *rscc_create_recvfrom_request(int *total_size, int *iovec_count, int s, void *buf, size_t len, int flags, struct sockaddr *from, socklen_t *fromlen) {
  struct recvfrom_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  int i;
  struct iovec *v;
  size_t vcount;


  int fromlen_size_value;
 
  socklen_t fromlen_value;
  /* The size of 'from' is contained in the memory pointed by 'fromlen',
   * but if the latter is NULL I cannot know the size of 'from'. */
  if(from != NULL && fromlen == NULL)
    return NULL;
  

  req_size = sizeof(struct recvfrom_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_int_size(my_arch, server_arch);
    req_size += aconv_pointer_size(my_arch, server_arch);
    req_size += aconv_size_t_size(my_arch, server_arch);
    req_size += aconv_int_size(my_arch, server_arch);
    req_size += aconv_pointer_size(my_arch, server_arch);
    req_size += aconv_pointer_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
#ifdef __x86_64__
	if( (rsc_const = nr2rsc(__NR_recvfrom, SYS_RECVFROM, my_arch)) == __RSC_ERROR ) {
#else
	if( (rsc_const = nr2rsc(__NR_socketcall, SYS_RECVFROM, my_arch)) == __RSC_ERROR ) {
#endif
    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  if(fromlen == NULL)
    fromlen_size_value = 0;
  else
    fromlen_size_value = aconv_socklen_t_size(my_arch, server_arch);
  if(from == NULL)
    fromlen_value = 0;
  else
    fromlen_value = *fromlen;
  req->req_size += fromlen_value + fromlen_size_value;
  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->s = s; 
    req->buf = buf; 
    req->len = len; 
    req->flags = flags; 
    req->from = from; 
    req->fromlen = fromlen; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_int(&s, my_arch, server_arch, mem); mem += aconv_int_size(my_arch, server_arch);
    
    aconv_pointer(buf, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
    aconv_size_t(&len, my_arch, server_arch, mem); mem += aconv_size_t_size(my_arch, server_arch);
    aconv_int(&flags, my_arch, server_arch, mem); mem += aconv_int_size(my_arch, server_arch);
    
    aconv_pointer(from, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
    aconv_pointer(fromlen, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 3;
  if(fromlen == NULL)
    vcount--;
  if(from == NULL)
    vcount--;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
  i = 1;
 
  if(fromlen != NULL) {
    v[i].iov_len =  fromlen_size_value;
    if(my_arch == server_arch) {
      v[i].iov_base = fromlen;
    } else {
      socklen_t  fromlen_new = *fromlen;

      v[i].iov_base = malloc(v[i].iov_len);
      if(v[i].iov_base == NULL)
        return NULL;
      if(*fromlen < aconv_struct_sockaddr_size(my_arch, server_arch))
        fromlen_new = aconv_struct_sockaddr_size(my_arch, server_arch);
      aconv_socklen_t(&fromlen_new, my_arch, server_arch, v[i].iov_base);
    }
    *total_size += v[i].iov_len;
    i++; 
  }
 
  if(from != NULL) {
    v[i].iov_len =  fromlen_value;
    if(my_arch == server_arch) {
      v[i].iov_base = from;
    } else {

      v[i].iov_base = malloc(v[i].iov_len);
      if(v[i].iov_base == NULL)
        return NULL;
      aconv_struct_sockaddr(from, my_arch, server_arch, v[i].iov_base);
    }
    *total_size += v[i].iov_len;
     
  }
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct recvfrom_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: s = %ld (0x%lX); buf = %p (0x%lX); len = %ld (0x%lX); flags = %ld (0x%lX); from = %p (0x%lX); fromlen = %p (0x%lX)", req->s, req->s, req->buf, req->buf, req->len, req->len, req->flags, req->flags, req->from, req->from, req->fromlen, req->fromlen);

  return v;
}

/* This function build the request for the system call 'rename' */
struct iovec *rscc_create_rename_request(int *total_size, int *iovec_count, char *oldpath, char *newpath) {
  struct rename_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  int i;
  struct iovec *v;
  size_t vcount;


  int oldpath_size_value;
  int newpath_size_value;
  

  req_size = sizeof(struct rename_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_pointer_size(my_arch, server_arch);
    req_size += aconv_pointer_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
	if( (rsc_const = nr2rsc(__NR_rename, NO_VALUE, my_arch)) == __RSC_ERROR ) {
    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  if(oldpath == NULL)
    oldpath_size_value = 0;
  else
    oldpath_size_value = aconv_string_size(oldpath, my_arch, server_arch);
  if(newpath == NULL)
    newpath_size_value = 0;
  else
    newpath_size_value = aconv_string_size(newpath, my_arch, server_arch);
  req->req_size += oldpath_size_value + newpath_size_value;
  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->oldpath = oldpath; 
    req->newpath = newpath; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_pointer(oldpath, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
    aconv_pointer(newpath, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 3;
  if(oldpath == NULL)
    vcount--;
  if(newpath == NULL)
    vcount--;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
  i = 1;
 
  if(oldpath != NULL) {
    v[i].iov_len =  oldpath_size_value;
    if(my_arch == server_arch) {
      v[i].iov_base = oldpath;
    } else {

      v[i].iov_base = malloc(v[i].iov_len);
      if(v[i].iov_base == NULL)
        return NULL;
      aconv_string(oldpath, my_arch, server_arch, v[i].iov_base);
    }
    *total_size += v[i].iov_len;
    i++; 
  }
 
  if(newpath != NULL) {
    v[i].iov_len =  newpath_size_value;
    if(my_arch == server_arch) {
      v[i].iov_base = newpath;
    } else {

      v[i].iov_base = malloc(v[i].iov_len);
      if(v[i].iov_base == NULL)
        return NULL;
      aconv_string(newpath, my_arch, server_arch, v[i].iov_base);
    }
    *total_size += v[i].iov_len;
     
  }
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct rename_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: oldpath = %p (0x%lX); newpath = %p (0x%lX)", req->oldpath, req->oldpath, req->newpath, req->newpath);

  return v;
}

/* This function build the request for the system call 'rmdir' */
struct iovec *rscc_create_rmdir_request(int *total_size, int *iovec_count, char *pathname) {
  struct rmdir_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  int i;
  struct iovec *v;
  size_t vcount;


  int pathname_size_value;
  

  req_size = sizeof(struct rmdir_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_pointer_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
	if( (rsc_const = nr2rsc(__NR_rmdir, NO_VALUE, my_arch)) == __RSC_ERROR ) {
    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  if(pathname == NULL)
    pathname_size_value = 0;
  else
    pathname_size_value = aconv_string_size(pathname, my_arch, server_arch);
  req->req_size += pathname_size_value;
  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->pathname = pathname; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_pointer(pathname, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 2;
  if(pathname == NULL)
    vcount--;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
  i = 1;
 
  if(pathname != NULL) {
    v[i].iov_len =  pathname_size_value;
    if(my_arch == server_arch) {
      v[i].iov_base = pathname;
    } else {

      v[i].iov_base = malloc(v[i].iov_len);
      if(v[i].iov_base == NULL)
        return NULL;
      aconv_string(pathname, my_arch, server_arch, v[i].iov_base);
    }
    *total_size += v[i].iov_len;
     
  }
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct rmdir_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: pathname = %p (0x%lX)", req->pathname, req->pathname);

  return v;
}

/* This function build the request for the system call 'send' */
struct iovec *rscc_create_send_request(int *total_size, int *iovec_count, int s, void *buf, size_t len, int flags) {
  struct send_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  int i;
  struct iovec *v;
  size_t vcount;

  /* If the destination architecture doesn't support this syscall, I return immediately */
  if(server_arch == ACONV_X86_64)
    return NULL;


  size_t len_value;
  

  req_size = sizeof(struct send_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_int_size(my_arch, server_arch);
    req_size += aconv_pointer_size(my_arch, server_arch);
    req_size += aconv_size_t_size(my_arch, server_arch);
    req_size += aconv_int_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
#ifdef __x86_64__ 
  return NULL;
#else
 
#ifdef __x86_64__
	if( (rsc_const = nr2rsc(__NR_send, SYS_SEND, my_arch)) == __RSC_ERROR ) {
#else
	if( (rsc_const = nr2rsc(__NR_socketcall, SYS_SEND, my_arch)) == __RSC_ERROR ) {
#endif
    free(req);
	  return NULL;
  }
#endif
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  if(buf == NULL)
    len_value = 0;
  else
    len_value = aconv_bytes_size(len, my_arch, server_arch);
  req->req_size += len_value;
  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->s = s; 
    req->buf = buf; 
    req->len = len; 
    req->flags = flags; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_int(&s, my_arch, server_arch, mem); mem += aconv_int_size(my_arch, server_arch);
    
    aconv_pointer(buf, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
    aconv_size_t(&len, my_arch, server_arch, mem); mem += aconv_size_t_size(my_arch, server_arch);
    aconv_int(&flags, my_arch, server_arch, mem); mem += aconv_int_size(my_arch, server_arch);
    
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 2;
  if(buf == NULL)
    vcount--;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
  i = 1;
 
  if(buf != NULL) {
    v[i].iov_len =  len_value;
    if(my_arch == server_arch) {
      v[i].iov_base = buf;
    } else {

      v[i].iov_base = malloc(v[i].iov_len);
      if(v[i].iov_base == NULL)
        return NULL;
      aconv_bytes(buf, my_arch, server_arch, v[i].iov_base, len);
    }
    *total_size += v[i].iov_len;
     
  }
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct send_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: s = %ld (0x%lX); buf = %p (0x%lX); len = %ld (0x%lX); flags = %ld (0x%lX)", req->s, req->s, req->buf, req->buf, req->len, req->len, req->flags, req->flags);

  return v;
}

/* This function build the request for the system call 'sendto' */
struct iovec *rscc_create_sendto_request(int *total_size, int *iovec_count, int s, void *buf, size_t len, int flags, struct sockaddr *to, socklen_t tolen) {
  struct sendto_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  int i;
  struct iovec *v;
  size_t vcount;


  size_t len_value;
  socklen_t tolen_value;
  

  req_size = sizeof(struct sendto_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_int_size(my_arch, server_arch);
    req_size += aconv_pointer_size(my_arch, server_arch);
    req_size += aconv_size_t_size(my_arch, server_arch);
    req_size += aconv_int_size(my_arch, server_arch);
    req_size += aconv_pointer_size(my_arch, server_arch);
    req_size += aconv_socklen_t_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
#ifdef __x86_64__
	if( (rsc_const = nr2rsc(__NR_sendto, SYS_SENDTO, my_arch)) == __RSC_ERROR ) {
#else
	if( (rsc_const = nr2rsc(__NR_socketcall, SYS_SENDTO, my_arch)) == __RSC_ERROR ) {
#endif
    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  if(buf == NULL)
    len_value = 0;
  else
    len_value = aconv_bytes_size(len, my_arch, server_arch);
  if(to == NULL)
    tolen_value = 0;
  else
    tolen_value = aconv_struct_sockaddr_size(my_arch, server_arch);
  req->req_size += len_value + tolen_value;
  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->s = s; 
    req->buf = buf; 
    req->len = len; 
    req->flags = flags; 
    req->to = to; 
    req->tolen = tolen; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    socklen_t tolen_new = tolen;
    aconv_int(&s, my_arch, server_arch, mem); mem += aconv_int_size(my_arch, server_arch);
    
    aconv_pointer(buf, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
    aconv_size_t(&len, my_arch, server_arch, mem); mem += aconv_size_t_size(my_arch, server_arch);
    aconv_int(&flags, my_arch, server_arch, mem); mem += aconv_int_size(my_arch, server_arch);
    
    aconv_pointer(to, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
    if(tolen < aconv_struct_sockaddr_size(my_arch, server_arch))
      tolen_new = aconv_struct_sockaddr_size(my_arch, server_arch);
    aconv_socklen_t(&tolen_new, my_arch, server_arch, mem); mem += aconv_socklen_t_size(my_arch, server_arch);
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 3;
  if(buf == NULL)
    vcount--;
  if(to == NULL)
    vcount--;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
  i = 1;
 
  if(buf != NULL) {
    v[i].iov_len =  len_value;
    if(my_arch == server_arch) {
      v[i].iov_base = buf;
    } else {

      v[i].iov_base = malloc(v[i].iov_len);
      if(v[i].iov_base == NULL)
        return NULL;
      aconv_bytes(buf, my_arch, server_arch, v[i].iov_base, len);
    }
    *total_size += v[i].iov_len;
    i++; 
  }
 
  if(to != NULL) {
    v[i].iov_len =  tolen_value;
    if(my_arch == server_arch) {
      v[i].iov_base = to;
    } else {

      v[i].iov_base = malloc(v[i].iov_len);
      if(v[i].iov_base == NULL)
        return NULL;
      aconv_struct_sockaddr(to, my_arch, server_arch, v[i].iov_base);
    }
    *total_size += v[i].iov_len;
     
  }
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct sendto_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: s = %ld (0x%lX); buf = %p (0x%lX); len = %ld (0x%lX); flags = %ld (0x%lX); to = %p (0x%lX); tolen = %ld (0x%lX)", req->s, req->s, req->buf, req->buf, req->len, req->len, req->flags, req->flags, req->to, req->to, req->tolen, req->tolen);

  return v;
}

/* This function build the request for the system call 'setdomainname' */
struct iovec *rscc_create_setdomainname_request(int *total_size, int *iovec_count, char *name, size_t len) {
  struct setdomainname_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  int i;
  struct iovec *v;
  size_t vcount;


  size_t len_value;
  

  req_size = sizeof(struct setdomainname_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_pointer_size(my_arch, server_arch);
    req_size += aconv_size_t_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
	if( (rsc_const = nr2rsc(__NR_setdomainname, NO_VALUE, my_arch)) == __RSC_ERROR ) {
    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  if(name == NULL)
    len_value = 0;
  else
    len_value = len;
  req->req_size += len_value;
  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->name = name; 
    req->len = len; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_pointer(name, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
    aconv_size_t(&len, my_arch, server_arch, mem); mem += aconv_size_t_size(my_arch, server_arch);
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 2;
  if(name == NULL)
    vcount--;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
  i = 1;
 
  if(name != NULL) {
    v[i].iov_len =  len_value;
    if(my_arch == server_arch) {
      v[i].iov_base = name;
    } else {

      v[i].iov_base = malloc(v[i].iov_len);
      if(v[i].iov_base == NULL)
        return NULL;
      aconv_string(name, my_arch, server_arch, v[i].iov_base);
    }
    *total_size += v[i].iov_len;
     
  }
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct setdomainname_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: name = %p (0x%lX); len = %ld (0x%lX)", req->name, req->name, req->len, req->len);

  return v;
}

/* This function build the request for the system call 'sethostname' */
struct iovec *rscc_create_sethostname_request(int *total_size, int *iovec_count, char *name, size_t len) {
  struct sethostname_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  int i;
  struct iovec *v;
  size_t vcount;


  size_t len_value;
  

  req_size = sizeof(struct sethostname_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_pointer_size(my_arch, server_arch);
    req_size += aconv_size_t_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
	if( (rsc_const = nr2rsc(__NR_sethostname, NO_VALUE, my_arch)) == __RSC_ERROR ) {
    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  if(name == NULL)
    len_value = 0;
  else
    len_value = len;
  req->req_size += len_value;
  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->name = name; 
    req->len = len; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_pointer(name, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
    aconv_size_t(&len, my_arch, server_arch, mem); mem += aconv_size_t_size(my_arch, server_arch);
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 2;
  if(name == NULL)
    vcount--;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
  i = 1;
 
  if(name != NULL) {
    v[i].iov_len =  len_value;
    if(my_arch == server_arch) {
      v[i].iov_base = name;
    } else {

      v[i].iov_base = malloc(v[i].iov_len);
      if(v[i].iov_base == NULL)
        return NULL;
      aconv_string(name, my_arch, server_arch, v[i].iov_base);
    }
    *total_size += v[i].iov_len;
     
  }
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct sethostname_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: name = %p (0x%lX); len = %ld (0x%lX)", req->name, req->name, req->len, req->len);

  return v;
}

/* This function build the request for the system call 'setsockopt' */
struct iovec *rscc_create_setsockopt_request(int *total_size, int *iovec_count, int s, int level, int optname, void *optval, socklen_t optlen) {
  struct setsockopt_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  int i;
  struct iovec *v;
  size_t vcount;


  socklen_t optlen_value;
  

  req_size = sizeof(struct setsockopt_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_int_size(my_arch, server_arch);
    req_size += aconv_int_size(my_arch, server_arch);
    req_size += aconv_int_size(my_arch, server_arch);
    req_size += aconv_pointer_size(my_arch, server_arch);
    req_size += aconv_socklen_t_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
#ifdef __x86_64__
	if( (rsc_const = nr2rsc(__NR_setsockopt, SYS_SETSOCKOPT, my_arch)) == __RSC_ERROR ) {
#else
	if( (rsc_const = nr2rsc(__NR_socketcall, SYS_SETSOCKOPT, my_arch)) == __RSC_ERROR ) {
#endif
    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  if(optval == NULL)
    optlen_value = 0;
  else
    optlen_value = aconv_bytes_size(optlen, my_arch, server_arch);
  req->req_size += optlen_value;
  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->s = s; 
    req->level = level; 
    req->optname = optname; 
    req->optval = optval; 
    req->optlen = optlen; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_int(&s, my_arch, server_arch, mem); mem += aconv_int_size(my_arch, server_arch);
    
    aconv_int(&level, my_arch, server_arch, mem); mem += aconv_int_size(my_arch, server_arch);
    
    aconv_int(&optname, my_arch, server_arch, mem); mem += aconv_int_size(my_arch, server_arch);
    
    aconv_pointer(optval, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
    aconv_socklen_t(&optlen, my_arch, server_arch, mem); mem += aconv_socklen_t_size(my_arch, server_arch);
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 2;
  if(optval == NULL)
    vcount--;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
  i = 1;
 
  if(optval != NULL) {
    v[i].iov_len =  optlen_value;
    if(my_arch == server_arch) {
      v[i].iov_base = optval;
    } else {

      v[i].iov_base = malloc(v[i].iov_len);
      if(v[i].iov_base == NULL)
        return NULL;
      aconv_bytes(optval, my_arch, server_arch, v[i].iov_base, optlen);
    }
    *total_size += v[i].iov_len;
     
  }
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct setsockopt_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: s = %ld (0x%lX); level = %ld (0x%lX); optname = %ld (0x%lX); optval = %p (0x%lX); optlen = %ld (0x%lX)", req->s, req->s, req->level, req->level, req->optname, req->optname, req->optval, req->optval, req->optlen, req->optlen);

  return v;
}

/* This function build the request for the system call 'settimeofday' */
struct iovec *rscc_create_settimeofday_request(int *total_size, int *iovec_count, struct timeval *tv, struct timezone *tz) {
  struct settimeofday_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  int i;
  struct iovec *v;
  size_t vcount;


  int tv_size_value;
  int tz_size_value;
  

  req_size = sizeof(struct settimeofday_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_pointer_size(my_arch, server_arch);
    req_size += aconv_pointer_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
	if( (rsc_const = nr2rsc(__NR_settimeofday, NO_VALUE, my_arch)) == __RSC_ERROR ) {
    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  if(tv == NULL)
    tv_size_value = 0;
  else
    tv_size_value = aconv_struct_timeval_size(my_arch, server_arch);
  if(tz == NULL)
    tz_size_value = 0;
  else
    tz_size_value = aconv_struct_timezone_size(my_arch, server_arch);
  req->req_size += tv_size_value + tz_size_value;
  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->tv = tv; 
    req->tz = tz; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_pointer(tv, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
    aconv_pointer(tz, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 3;
  if(tv == NULL)
    vcount--;
  if(tz == NULL)
    vcount--;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
  i = 1;
 
  if(tv != NULL) {
    v[i].iov_len =  tv_size_value;
    if(my_arch == server_arch) {
      v[i].iov_base = tv;
    } else {

      v[i].iov_base = malloc(v[i].iov_len);
      if(v[i].iov_base == NULL)
        return NULL;
      aconv_struct_timeval(tv, my_arch, server_arch, v[i].iov_base);
    }
    *total_size += v[i].iov_len;
    i++; 
  }
 
  if(tz != NULL) {
    v[i].iov_len =  tz_size_value;
    if(my_arch == server_arch) {
      v[i].iov_base = tz;
    } else {

      v[i].iov_base = malloc(v[i].iov_len);
      if(v[i].iov_base == NULL)
        return NULL;
      aconv_struct_timezone(tz, my_arch, server_arch, v[i].iov_base);
    }
    *total_size += v[i].iov_len;
     
  }
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct settimeofday_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: tv = %p (0x%lX); tz = %p (0x%lX)", req->tv, req->tv, req->tz, req->tz);

  return v;
}

/* This function build the request for the system call 'shutdown' */
struct iovec *rscc_create_shutdown_request(int *total_size, int *iovec_count, int s, int how) {
  struct shutdown_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  struct iovec *v;
  size_t vcount;


  

  req_size = sizeof(struct shutdown_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_int_size(my_arch, server_arch);
    req_size += aconv_int_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
#ifdef __x86_64__
	if( (rsc_const = nr2rsc(__NR_shutdown, SYS_SHUTDOWN, my_arch)) == __RSC_ERROR ) {
#else
	if( (rsc_const = nr2rsc(__NR_socketcall, SYS_SHUTDOWN, my_arch)) == __RSC_ERROR ) {
#endif
    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->s = s; 
    req->how = how; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_int(&s, my_arch, server_arch, mem); mem += aconv_int_size(my_arch, server_arch);
    
    aconv_int(&how, my_arch, server_arch, mem); mem += aconv_int_size(my_arch, server_arch);
    
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 1;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct shutdown_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: s = %ld (0x%lX); how = %ld (0x%lX)", req->s, req->s, req->how, req->how);

  return v;
}

/* This function build the request for the system call 'socket' */
struct iovec *rscc_create_socket_request(int *total_size, int *iovec_count, int domain, int type, int protocol) {
  struct socket_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  struct iovec *v;
  size_t vcount;


  

  req_size = sizeof(struct socket_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_int_size(my_arch, server_arch);
    req_size += aconv_int_size(my_arch, server_arch);
    req_size += aconv_int_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
#ifdef __x86_64__
	if( (rsc_const = nr2rsc(__NR_socket, SYS_SOCKET, my_arch)) == __RSC_ERROR ) {
#else
	if( (rsc_const = nr2rsc(__NR_socketcall, SYS_SOCKET, my_arch)) == __RSC_ERROR ) {
#endif
    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->domain = domain; 
    req->type = type; 
    req->protocol = protocol; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_int(&domain, my_arch, server_arch, mem); mem += aconv_int_size(my_arch, server_arch);
    
    aconv_int(&type, my_arch, server_arch, mem); mem += aconv_int_size(my_arch, server_arch);
    
    aconv_int(&protocol, my_arch, server_arch, mem); mem += aconv_int_size(my_arch, server_arch);
    
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 1;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct socket_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: domain = %ld (0x%lX); type = %ld (0x%lX); protocol = %ld (0x%lX)", req->domain, req->domain, req->type, req->type, req->protocol, req->protocol);

  return v;
}

/* This function build the request for the system call 'stat64' */
struct iovec *rscc_create_stat64_request(int *total_size, int *iovec_count, char *path, struct stat64 *buf) {
  struct stat64_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  int i;
  struct iovec *v;
  size_t vcount;


  int path_size_value;
  

  req_size = sizeof(struct stat64_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_pointer_size(my_arch, server_arch);
    req_size += aconv_pointer_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
#ifdef __x86_64__
	if( (rsc_const = nr2rsc(__NR_stat, NO_VALUE, my_arch)) == __RSC_ERROR ) {
#else
	if( (rsc_const = nr2rsc(__NR_stat64, NO_VALUE, my_arch)) == __RSC_ERROR ) {
#endif

    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  if(path == NULL)
    path_size_value = 0;
  else
    path_size_value = aconv_string_size(path, my_arch, server_arch);
  req->req_size += path_size_value;
  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->path = path; 
    req->buf = buf; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_pointer(path, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
    aconv_pointer(buf, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 2;
  if(path == NULL)
    vcount--;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
  i = 1;
 
  if(path != NULL) {
    v[i].iov_len =  path_size_value;
    if(my_arch == server_arch) {
      v[i].iov_base = path;
    } else {

      v[i].iov_base = malloc(v[i].iov_len);
      if(v[i].iov_base == NULL)
        return NULL;
      aconv_string(path, my_arch, server_arch, v[i].iov_base);
    }
    *total_size += v[i].iov_len;
     
  }
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct stat64_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: path = %p (0x%lX); buf = %p (0x%lX)", req->path, req->path, req->buf, req->buf);

  return v;
}

/* This function build the request for the system call 'statfs64' */
struct iovec *rscc_create_statfs64_request(int *total_size, int *iovec_count, char *path, struct statfs64 *buf) {
  struct statfs64_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  int i;
  struct iovec *v;
  size_t vcount;


  int path_size_value;
  

  req_size = sizeof(struct statfs64_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_pointer_size(my_arch, server_arch);
    req_size += aconv_pointer_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
#ifdef __x86_64__
	if( (rsc_const = nr2rsc(__NR_statfs, NO_VALUE, my_arch)) == __RSC_ERROR ) {
#else
	if( (rsc_const = nr2rsc(__NR_statfs64, NO_VALUE, my_arch)) == __RSC_ERROR ) {
#endif

    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  if(path == NULL)
    path_size_value = 0;
  else
    path_size_value = aconv_string_size(path, my_arch, server_arch);
  req->req_size += path_size_value;
  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->path = path; 
    req->buf = buf; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_pointer(path, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
    aconv_pointer(buf, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 2;
  if(path == NULL)
    vcount--;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
  i = 1;
 
  if(path != NULL) {
    v[i].iov_len =  path_size_value;
    if(my_arch == server_arch) {
      v[i].iov_base = path;
    } else {

      v[i].iov_base = malloc(v[i].iov_len);
      if(v[i].iov_base == NULL)
        return NULL;
      aconv_string(path, my_arch, server_arch, v[i].iov_base);
    }
    *total_size += v[i].iov_len;
     
  }
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct statfs64_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: path = %p (0x%lX); buf = %p (0x%lX)", req->path, req->path, req->buf, req->buf);

  return v;
}

/* This function build the request for the system call 'symlink' */
struct iovec *rscc_create_symlink_request(int *total_size, int *iovec_count, char *oldpath, char *newpath) {
  struct symlink_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  int i;
  struct iovec *v;
  size_t vcount;


  int oldpath_size_value;
  int newpath_size_value;
  

  req_size = sizeof(struct symlink_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_pointer_size(my_arch, server_arch);
    req_size += aconv_pointer_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
	if( (rsc_const = nr2rsc(__NR_symlink, NO_VALUE, my_arch)) == __RSC_ERROR ) {
    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  if(oldpath == NULL)
    oldpath_size_value = 0;
  else
    oldpath_size_value = aconv_string_size(oldpath, my_arch, server_arch);
  if(newpath == NULL)
    newpath_size_value = 0;
  else
    newpath_size_value = aconv_string_size(newpath, my_arch, server_arch);
  req->req_size += oldpath_size_value + newpath_size_value;
  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->oldpath = oldpath; 
    req->newpath = newpath; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_pointer(oldpath, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
    aconv_pointer(newpath, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 3;
  if(oldpath == NULL)
    vcount--;
  if(newpath == NULL)
    vcount--;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
  i = 1;
 
  if(oldpath != NULL) {
    v[i].iov_len =  oldpath_size_value;
    if(my_arch == server_arch) {
      v[i].iov_base = oldpath;
    } else {

      v[i].iov_base = malloc(v[i].iov_len);
      if(v[i].iov_base == NULL)
        return NULL;
      aconv_string(oldpath, my_arch, server_arch, v[i].iov_base);
    }
    *total_size += v[i].iov_len;
    i++; 
  }
 
  if(newpath != NULL) {
    v[i].iov_len =  newpath_size_value;
    if(my_arch == server_arch) {
      v[i].iov_base = newpath;
    } else {

      v[i].iov_base = malloc(v[i].iov_len);
      if(v[i].iov_base == NULL)
        return NULL;
      aconv_string(newpath, my_arch, server_arch, v[i].iov_base);
    }
    *total_size += v[i].iov_len;
     
  }
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct symlink_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: oldpath = %p (0x%lX); newpath = %p (0x%lX)", req->oldpath, req->oldpath, req->newpath, req->newpath);

  return v;
}

/* This function build the request for the system call 'truncate64' */
struct iovec *rscc_create_truncate64_request(int *total_size, int *iovec_count, char *path, __off64_t length) {
  struct truncate64_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  int i;
  struct iovec *v;
  size_t vcount;


  int path_size_value;
  

  req_size = sizeof(struct truncate64_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_pointer_size(my_arch, server_arch);
    req_size += aconv___off64_t_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
#ifdef __x86_64__
	if( (rsc_const = nr2rsc(__NR_truncate, NO_VALUE, my_arch)) == __RSC_ERROR ) {
#else
	if( (rsc_const = nr2rsc(__NR_truncate64, NO_VALUE, my_arch)) == __RSC_ERROR ) {
#endif

    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  if(path == NULL)
    path_size_value = 0;
  else
    path_size_value = aconv_string_size(path, my_arch, server_arch);
  req->req_size += path_size_value;
  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->path = path; 
    req->length = length; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_pointer(path, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
    aconv___off64_t(&length, my_arch, server_arch, mem); mem += aconv___off64_t_size(my_arch, server_arch);
    
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 2;
  if(path == NULL)
    vcount--;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
  i = 1;
 
  if(path != NULL) {
    v[i].iov_len =  path_size_value;
    if(my_arch == server_arch) {
      v[i].iov_base = path;
    } else {

      v[i].iov_base = malloc(v[i].iov_len);
      if(v[i].iov_base == NULL)
        return NULL;
      aconv_string(path, my_arch, server_arch, v[i].iov_base);
    }
    *total_size += v[i].iov_len;
     
  }
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct truncate64_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: path = %p (0x%lX); length = %ld (0x%lX)", req->path, req->path, req->length, req->length);

  return v;
}

/* This function build the request for the system call 'umount2' */
struct iovec *rscc_create_umount2_request(int *total_size, int *iovec_count, char *target, int flags) {
  struct umount2_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  int i;
  struct iovec *v;
  size_t vcount;


  int target_size_value;
  

  req_size = sizeof(struct umount2_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_pointer_size(my_arch, server_arch);
    req_size += aconv_int_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
	if( (rsc_const = nr2rsc(__NR_umount2, NO_VALUE, my_arch)) == __RSC_ERROR ) {
    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  if(target == NULL)
    target_size_value = 0;
  else
    target_size_value = aconv_string_size(target, my_arch, server_arch);
  req->req_size += target_size_value;
  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->target = target; 
    req->flags = flags; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_pointer(target, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
    aconv_int(&flags, my_arch, server_arch, mem); mem += aconv_int_size(my_arch, server_arch);
    
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 2;
  if(target == NULL)
    vcount--;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
  i = 1;
 
  if(target != NULL) {
    v[i].iov_len =  target_size_value;
    if(my_arch == server_arch) {
      v[i].iov_base = target;
    } else {

      v[i].iov_base = malloc(v[i].iov_len);
      if(v[i].iov_base == NULL)
        return NULL;
      aconv_string(target, my_arch, server_arch, v[i].iov_base);
    }
    *total_size += v[i].iov_len;
     
  }
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct umount2_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: target = %p (0x%lX); flags = %ld (0x%lX)", req->target, req->target, req->flags, req->flags);

  return v;
}

/* This function build the request for the system call 'uname' */
struct iovec *rscc_create_uname_request(int *total_size, int *iovec_count, struct utsname *buf) {
  struct uname_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  struct iovec *v;
  size_t vcount;


  

  req_size = sizeof(struct uname_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_pointer_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
	if( (rsc_const = nr2rsc(__NR_uname, NO_VALUE, my_arch)) == __RSC_ERROR ) {
    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->buf = buf; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_pointer(buf, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 1;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct uname_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: buf = %p (0x%lX)", req->buf, req->buf);

  return v;
}

/* This function build the request for the system call 'unlink' */
struct iovec *rscc_create_unlink_request(int *total_size, int *iovec_count, char *pathname) {
  struct unlink_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  int i;
  struct iovec *v;
  size_t vcount;


  int pathname_size_value;
  

  req_size = sizeof(struct unlink_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_pointer_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
	if( (rsc_const = nr2rsc(__NR_unlink, NO_VALUE, my_arch)) == __RSC_ERROR ) {
    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  if(pathname == NULL)
    pathname_size_value = 0;
  else
    pathname_size_value = aconv_string_size(pathname, my_arch, server_arch);
  req->req_size += pathname_size_value;
  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->pathname = pathname; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_pointer(pathname, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 2;
  if(pathname == NULL)
    vcount--;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
  i = 1;
 
  if(pathname != NULL) {
    v[i].iov_len =  pathname_size_value;
    if(my_arch == server_arch) {
      v[i].iov_base = pathname;
    } else {

      v[i].iov_base = malloc(v[i].iov_len);
      if(v[i].iov_base == NULL)
        return NULL;
      aconv_string(pathname, my_arch, server_arch, v[i].iov_base);
    }
    *total_size += v[i].iov_len;
     
  }
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct unlink_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: pathname = %p (0x%lX)", req->pathname, req->pathname);

  return v;
}

/* This function build the request for the system call 'utime' */
struct iovec *rscc_create_utime_request(int *total_size, int *iovec_count, char *filename, struct utimbuf *buf) {
  struct utime_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  int i;
  struct iovec *v;
  size_t vcount;


  int filename_size_value;
  int buf_size_value;
  

  req_size = sizeof(struct utime_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_pointer_size(my_arch, server_arch);
    req_size += aconv_pointer_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
	if( (rsc_const = nr2rsc(__NR_utime, NO_VALUE, my_arch)) == __RSC_ERROR ) {
    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  if(filename == NULL)
    filename_size_value = 0;
  else
    filename_size_value = aconv_string_size(filename, my_arch, server_arch);
  if(buf == NULL)
    buf_size_value = 0;
  else
    buf_size_value = aconv_struct_utimbuf_size(my_arch, server_arch);
  req->req_size += filename_size_value + buf_size_value;
  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->filename = filename; 
    req->buf = buf; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_pointer(filename, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
    aconv_pointer(buf, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 3;
  if(filename == NULL)
    vcount--;
  if(buf == NULL)
    vcount--;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
  i = 1;
 
  if(filename != NULL) {
    v[i].iov_len =  filename_size_value;
    if(my_arch == server_arch) {
      v[i].iov_base = filename;
    } else {

      v[i].iov_base = malloc(v[i].iov_len);
      if(v[i].iov_base == NULL)
        return NULL;
      aconv_string(filename, my_arch, server_arch, v[i].iov_base);
    }
    *total_size += v[i].iov_len;
    i++; 
  }
 
  if(buf != NULL) {
    v[i].iov_len =  buf_size_value;
    if(my_arch == server_arch) {
      v[i].iov_base = buf;
    } else {

      v[i].iov_base = malloc(v[i].iov_len);
      if(v[i].iov_base == NULL)
        return NULL;
      aconv_struct_utimbuf(buf, my_arch, server_arch, v[i].iov_base);
    }
    *total_size += v[i].iov_len;
     
  }
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct utime_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: filename = %p (0x%lX); buf = %p (0x%lX)", req->filename, req->filename, req->buf, req->buf);

  return v;
}

/* This function build the request for the system call 'utimes' */
struct iovec *rscc_create_utimes_request(int *total_size, int *iovec_count, char *filename, struct timeval tv[2]) {
  struct utimes_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  int i;
  struct iovec *v;
  size_t vcount;


  int filename_size_value;
  

  req_size = sizeof(struct utimes_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_pointer_size(my_arch, server_arch);
    req_size += aconv_array_size(my_arch, server_arch, 2, aconv_struct_timeval_size);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
	if( (rsc_const = nr2rsc(__NR_utimes, NO_VALUE, my_arch)) == __RSC_ERROR ) {
    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  if(filename == NULL)
    filename_size_value = 0;
  else
    filename_size_value = aconv_string_size(filename, my_arch, server_arch);
  req->req_size += filename_size_value;
  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->filename = filename; 
    if(tv != NULL) {
      (req->tv)[0] = tv[0];
      (req->tv)[1] = tv[1];
    }
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_pointer(filename, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
    if(tv != NULL) {
      aconv_array(tv, my_arch, server_arch, 2, mem, aconv_struct_timeval_size, aconv_struct_timeval);
    }
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 2;
  if(filename == NULL)
    vcount--;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
  i = 1;
 
  if(filename != NULL) {
    v[i].iov_len =  filename_size_value;
    if(my_arch == server_arch) {
      v[i].iov_base = filename;
    } else {

      v[i].iov_base = malloc(v[i].iov_len);
      if(v[i].iov_base == NULL)
        return NULL;
      aconv_string(filename, my_arch, server_arch, v[i].iov_base);
    }
    *total_size += v[i].iov_len;
     
  }
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct utimes_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: filename = %p (0x%lX); tv = %p (0x%lX)", req->filename, req->filename, req->tv, req->tv);

  return v;
}

/* This function build the request for the system call 'write' */
struct iovec *rscc_create_write_request(int *total_size, int *iovec_count, int fd, void *buf, size_t count) {
  struct write_req *req;
  enum rsc_constant rsc_const;
  int req_size;
  int i;
  struct iovec *v;
  size_t vcount;


  size_t count_value;
  

  req_size = sizeof(struct write_req);
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);
    req_size += aconv_int_size(my_arch, server_arch);
    req_size += aconv_pointer_size(my_arch, server_arch);
    req_size += aconv_size_t_size(my_arch, server_arch);
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
 
	if( (rsc_const = nr2rsc(__NR_write, NO_VALUE, my_arch)) == __RSC_ERROR ) {
    free(req);
	  return NULL;
  }
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

  if(buf == NULL)
    count_value = 0;
  else
    count_value = aconv_bytes_size(count, my_arch, server_arch);
  req->req_size += count_value;
  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
    req->fd = fd; 
    req->buf = buf; 
    req->count = count; 
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
    aconv_int(&fd, my_arch, server_arch, mem); mem += aconv_int_size(my_arch, server_arch);
    
    aconv_pointer(buf, my_arch, server_arch, mem); mem += aconv_pointer_size(my_arch, server_arch);
    
    aconv_size_t(&count, my_arch, server_arch, mem); mem += aconv_size_t_size(my_arch, server_arch);
  }
        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 2;
  if(buf == NULL)
    vcount--;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
  i = 1;
 
  if(buf != NULL) {
    v[i].iov_len =  count_value;
    if(my_arch == server_arch) {
      v[i].iov_base = buf;
    } else {

      v[i].iov_base = malloc(v[i].iov_len);
      if(v[i].iov_base == NULL)
        return NULL;
      aconv_bytes(buf, my_arch, server_arch, v[i].iov_base, count);
    }
    *total_size += v[i].iov_len;
     
  }
 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct write_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: fd = %ld (0x%lX); buf = %p (0x%lX); count = %ld (0x%lX)", req->fd, req->fd, req->buf, req->buf, req->count, req->count);

  return v;
}


/*##########################################################*/
/*##                                                      ##*/
/*##  RESPONSE MANAGEMENT FUNCTIONS                       ##*/
/*##                                                      ##*/
/*##########################################################*/
struct iovec *rscc_manage__llseek_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, unsigned int fd, unsigned long int offset_high, unsigned long int offset_low, loff_t *result, unsigned int whence) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);

  
  /* I read the buffers */
  if(resp_header->resp_size > sizeof(struct sys_resp_header)) {
    int i;
    
    vcount = 1;
    if(result == NULL)
      vcount--;
 
    if(vcount != 0) {
	    v = calloc(vcount, sizeof(struct iovec));
	    if(v == NULL) {
	      fprintf(stderr, "Cannot allocate memory for vector v");
	      return NULL;
	    }
	
	    *nbytes = 0;
	    i = 0;
	   
      if(result != NULL) {
	      v[i].iov_base = result;
	      v[i].iov_len =  sizeof(loff_t);
	      *nbytes += sizeof(loff_t); 
	       
      }
	   
    }
  }


  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_accept_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);

  
  /* I read the buffers */
  if(resp_header->resp_size > sizeof(struct sys_resp_header)) {
    int i;
    
    vcount = 2;
    if(addrlen == NULL)
      vcount--;
    if(addr == NULL)
      vcount--;
 
    if(vcount != 0) {
	    v = calloc(vcount, sizeof(struct iovec));
	    if(v == NULL) {
	      fprintf(stderr, "Cannot allocate memory for vector v");
	      return NULL;
	    }
	
	    *nbytes = 0;
	    i = 0;
	   
      if(addrlen != NULL) {
	      v[i].iov_base = addrlen;
	      v[i].iov_len =  sizeof(socklen_t);
	      *nbytes += sizeof(socklen_t); 
	      i++; 
      }
	   
      if(addr != NULL) {
	      v[i].iov_base = addr;
	      v[i].iov_len =  *addrlen;
	      *nbytes += *addrlen; 
	       
      }
	   
    }
  }


  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_access_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, char *pathname, int mode) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);



  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_adjtimex_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, struct timex *buf) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);

  
  /* I read the buffers */
  if(resp_header->resp_size > sizeof(struct sys_resp_header)) {
    int i;
    
    vcount = 1;
    if(buf == NULL)
      vcount--;
 
    if(vcount != 0) {
	    v = calloc(vcount, sizeof(struct iovec));
	    if(v == NULL) {
	      fprintf(stderr, "Cannot allocate memory for vector v");
	      return NULL;
	    }
	
	    *nbytes = 0;
	    i = 0;
	   
      if(buf != NULL) {
	      v[i].iov_base = buf;
	      v[i].iov_len =  sizeof(struct timex);
	      *nbytes += sizeof(struct timex); 
	       
      }
	   
    }
  }


  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_bind_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int sockfd, struct sockaddr *my_addr, socklen_t addrlen) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);



  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_chdir_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, char *path) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);



  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_chmod_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, char *path, mode_t mode) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);



  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_chown_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, char *path, uid_t owner, gid_t group) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);



  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_chown32_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, char *path, uid_t owner, gid_t group) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);



  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_clock_getres_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, clockid_t clk_id, struct timespec *res) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);

  
  /* I read the buffers */
  if(resp_header->resp_size > sizeof(struct sys_resp_header)) {
    int i;
    
    vcount = 1;
    if(res == NULL)
      vcount--;
 
    if(vcount != 0) {
	    v = calloc(vcount, sizeof(struct iovec));
	    if(v == NULL) {
	      fprintf(stderr, "Cannot allocate memory for vector v");
	      return NULL;
	    }
	
	    *nbytes = 0;
	    i = 0;
	   
      if(res != NULL) {
	      v[i].iov_base = res;
	      v[i].iov_len =  sizeof(struct timespec);
	      *nbytes += sizeof(struct timespec); 
	       
      }
	   
    }
  }


  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_clock_gettime_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, clockid_t clk_id, struct timespec *tp) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);

  
  /* I read the buffers */
  if(resp_header->resp_size > sizeof(struct sys_resp_header)) {
    int i;
    
    vcount = 1;
    if(tp == NULL)
      vcount--;
 
    if(vcount != 0) {
	    v = calloc(vcount, sizeof(struct iovec));
	    if(v == NULL) {
	      fprintf(stderr, "Cannot allocate memory for vector v");
	      return NULL;
	    }
	
	    *nbytes = 0;
	    i = 0;
	   
      if(tp != NULL) {
	      v[i].iov_base = tp;
	      v[i].iov_len =  sizeof(struct timespec);
	      *nbytes += sizeof(struct timespec); 
	       
      }
	   
    }
  }


  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_clock_settime_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, clockid_t clk_id, struct timespec *tp) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);



  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_close_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int fd) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);



  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_connect_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int sockfd, struct sockaddr *serv_addr, socklen_t addrlen) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);



  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_dup_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int oldfd) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);



  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_dup2_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int oldfd, int newfd) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);



  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_fchdir_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int fd) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);



  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_fchmod_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int fildes, mode_t mode) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);



  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_fchown_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int fd, uid_t owner, gid_t group) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);



  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_fchown32_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int fd, uid_t owner, gid_t group) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);



  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_fdatasync_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int fd) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);



  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_fgetxattr_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int filedes, char *name, void *value, size_t size) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);

  
  /* I read the buffers */
  if(resp_header->resp_size > sizeof(struct sys_resp_header)) {
    int i;
    
    vcount = 1;
    if(value == NULL)
      vcount--;
 
    if(vcount != 0) {
	    v = calloc(vcount, sizeof(struct iovec));
	    if(v == NULL) {
	      fprintf(stderr, "Cannot allocate memory for vector v");
	      return NULL;
	    }
	
	    *nbytes = 0;
	    i = 0;
	   
      if(value != NULL) {
	      v[i].iov_base = value;
	      v[i].iov_len =  size;
	      *nbytes += size; 
	       
      }
	   
    }
  }


  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_fstat64_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int filedes, struct stat64 *buf) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);

  
  /* I read the buffers */
  if(resp_header->resp_size > sizeof(struct sys_resp_header)) {
    int i;
    
    vcount = 1;
    if(buf == NULL)
      vcount--;
 
    if(vcount != 0) {
	    v = calloc(vcount, sizeof(struct iovec));
	    if(v == NULL) {
	      fprintf(stderr, "Cannot allocate memory for vector v");
	      return NULL;
	    }
	
	    *nbytes = 0;
	    i = 0;
	   
      if(buf != NULL) {
	      v[i].iov_base = buf;
	      v[i].iov_len =  sizeof(struct stat64);
	      *nbytes += sizeof(struct stat64); 
	       
      }
	   
    }
  }


  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_fstatfs64_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, unsigned int fd, struct statfs64 *buf) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);

  
  /* I read the buffers */
  if(resp_header->resp_size > sizeof(struct sys_resp_header)) {
    int i;
    
    vcount = 1;
    if(buf == NULL)
      vcount--;
 
    if(vcount != 0) {
	    v = calloc(vcount, sizeof(struct iovec));
	    if(v == NULL) {
	      fprintf(stderr, "Cannot allocate memory for vector v");
	      return NULL;
	    }
	
	    *nbytes = 0;
	    i = 0;
	   
      if(buf != NULL) {
	      v[i].iov_base = buf;
	      v[i].iov_len =  sizeof(struct statfs64);
	      *nbytes += sizeof(struct statfs64); 
	       
      }
	   
    }
  }


  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_fsync_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int fd) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);



  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_ftruncate64_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int fd, __off64_t length) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);



  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_getdents64_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, unsigned int fd, struct dirent64 *dirp, unsigned int count) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);

  
  /* I read the buffers */
  if(resp_header->resp_size > sizeof(struct sys_resp_header)) {
    int i;
    
    vcount = 1;
    if(dirp == NULL)
      vcount--;
 
    if(vcount != 0) {
	    v = calloc(vcount, sizeof(struct iovec));
	    if(v == NULL) {
	      fprintf(stderr, "Cannot allocate memory for vector v");
	      return NULL;
	    }
	
	    *nbytes = 0;
	    i = 0;
	   
      if(dirp != NULL) {
	      v[i].iov_base = dirp;
	      v[i].iov_len =  count;
	      *nbytes += count; 
	       
      }
	   
    }
  }


  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_getpeername_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int s, struct sockaddr *name, socklen_t *namelen) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);

  
  /* I read the buffers */
  if(resp_header->resp_size > sizeof(struct sys_resp_header)) {
    int i;
    
    vcount = 2;
    if(namelen == NULL)
      vcount--;
    if(name == NULL)
      vcount--;
 
    if(vcount != 0) {
	    v = calloc(vcount, sizeof(struct iovec));
	    if(v == NULL) {
	      fprintf(stderr, "Cannot allocate memory for vector v");
	      return NULL;
	    }
	
	    *nbytes = 0;
	    i = 0;
	   
      if(namelen != NULL) {
	      v[i].iov_base = namelen;
	      v[i].iov_len =  sizeof(socklen_t);
	      *nbytes += sizeof(socklen_t); 
	      i++; 
      }
	   
      if(name != NULL) {
	      v[i].iov_base = name;
	      v[i].iov_len =  *namelen;
	      *nbytes += *namelen; 
	       
      }
	   
    }
  }


  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_getsockname_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int s, struct sockaddr *name, socklen_t *namelen) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);

  
  /* I read the buffers */
  if(resp_header->resp_size > sizeof(struct sys_resp_header)) {
    int i;
    
    vcount = 2;
    if(namelen == NULL)
      vcount--;
    if(name == NULL)
      vcount--;
 
    if(vcount != 0) {
	    v = calloc(vcount, sizeof(struct iovec));
	    if(v == NULL) {
	      fprintf(stderr, "Cannot allocate memory for vector v");
	      return NULL;
	    }
	
	    *nbytes = 0;
	    i = 0;
	   
      if(namelen != NULL) {
	      v[i].iov_base = namelen;
	      v[i].iov_len =  sizeof(socklen_t);
	      *nbytes += sizeof(socklen_t); 
	      i++; 
      }
	   
      if(name != NULL) {
	      v[i].iov_base = name;
	      v[i].iov_len =  *namelen;
	      *nbytes += *namelen; 
	       
      }
	   
    }
  }


  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_getsockopt_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int s, int level, int optname, void *optval, socklen_t *optlen) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);

  
  /* I read the buffers */
  if(resp_header->resp_size > sizeof(struct sys_resp_header)) {
    int i;
    
    vcount = 2;
    if(optlen == NULL)
      vcount--;
    if(optval == NULL)
      vcount--;
 
    if(vcount != 0) {
	    v = calloc(vcount, sizeof(struct iovec));
	    if(v == NULL) {
	      fprintf(stderr, "Cannot allocate memory for vector v");
	      return NULL;
	    }
	
	    *nbytes = 0;
	    i = 0;
	   
      if(optlen != NULL) {
	      v[i].iov_base = optlen;
	      v[i].iov_len =  sizeof(socklen_t);
	      *nbytes += sizeof(socklen_t); 
	      i++; 
      }
	   
      if(optval != NULL) {
	      v[i].iov_base = optval;
	      v[i].iov_len =  *optlen;
	      *nbytes += *optlen; 
	       
      }
	   
    }
  }


  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_gettimeofday_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, struct timeval *tv, struct timezone *tz) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);

  
  /* I read the buffers */
  if(resp_header->resp_size > sizeof(struct sys_resp_header)) {
    int i;
    
    vcount = 2;
    if(tv == NULL)
      vcount--;
    if(tz == NULL)
      vcount--;
 
    if(vcount != 0) {
	    v = calloc(vcount, sizeof(struct iovec));
	    if(v == NULL) {
	      fprintf(stderr, "Cannot allocate memory for vector v");
	      return NULL;
	    }
	
	    *nbytes = 0;
	    i = 0;
	   
      if(tv != NULL) {
	      v[i].iov_base = tv;
	      v[i].iov_len =  sizeof(struct timeval);
	      *nbytes += sizeof(struct timeval); 
	      i++; 
      }
	   
      if(tz != NULL) {
	      v[i].iov_base = tz;
	      v[i].iov_len =  sizeof(struct timezone);
	      *nbytes += sizeof(struct timezone); 
	       
      }
	   
    }
  }


  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_getxattr_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, char *path, char *name, void *value, size_t size) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);

  
  /* I read the buffers */
  if(resp_header->resp_size > sizeof(struct sys_resp_header)) {
    int i;
    
    vcount = 1;
    if(value == NULL)
      vcount--;
 
    if(vcount != 0) {
	    v = calloc(vcount, sizeof(struct iovec));
	    if(v == NULL) {
	      fprintf(stderr, "Cannot allocate memory for vector v");
	      return NULL;
	    }
	
	    *nbytes = 0;
	    i = 0;
	   
      if(value != NULL) {
	      v[i].iov_base = value;
	      v[i].iov_len =  size;
	      *nbytes += size; 
	       
      }
	   
    }
  }


  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_lchown_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, char *path, uid_t owner, gid_t group) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);



  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_lchown32_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, char *path, uid_t owner, gid_t group) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);



  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_lgetxattr_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, char *path, char *name, void *value, size_t size) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);

  
  /* I read the buffers */
  if(resp_header->resp_size > sizeof(struct sys_resp_header)) {
    int i;
    
    vcount = 1;
    if(value == NULL)
      vcount--;
 
    if(vcount != 0) {
	    v = calloc(vcount, sizeof(struct iovec));
	    if(v == NULL) {
	      fprintf(stderr, "Cannot allocate memory for vector v");
	      return NULL;
	    }
	
	    *nbytes = 0;
	    i = 0;
	   
      if(value != NULL) {
	      v[i].iov_base = value;
	      v[i].iov_len =  size;
	      *nbytes += size; 
	       
      }
	   
    }
  }


  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_link_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, char *oldpath, char *newpath) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);



  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_listen_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int sockfd, int backlog) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);



  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_lseek_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int fildes, off_t offset, int whence) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);



  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_lstat64_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, char *path, struct stat64 *buf) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);

  
  /* I read the buffers */
  if(resp_header->resp_size > sizeof(struct sys_resp_header)) {
    int i;
    
    vcount = 1;
    if(buf == NULL)
      vcount--;
 
    if(vcount != 0) {
	    v = calloc(vcount, sizeof(struct iovec));
	    if(v == NULL) {
	      fprintf(stderr, "Cannot allocate memory for vector v");
	      return NULL;
	    }
	
	    *nbytes = 0;
	    i = 0;
	   
      if(buf != NULL) {
	      v[i].iov_base = buf;
	      v[i].iov_len =  sizeof(struct stat64);
	      *nbytes += sizeof(struct stat64); 
	       
      }
	   
    }
  }


  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_mkdir_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, char *pathname, mode_t mode) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);



  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_mount_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, char *source, char *target, char *filesystemtype, unsigned long int mountflags, void *data) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);



  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_open_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, char *pathname, int flags) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);



  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_pread64_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int fd, void *buf, size_t count, off_t offset) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);

  
  /* I read the buffers */
  if(resp_header->resp_size > sizeof(struct sys_resp_header)) {
    int i;
    
    vcount = 1;
    if(buf == NULL)
      vcount--;
 
    if(vcount != 0) {
	    v = calloc(vcount, sizeof(struct iovec));
	    if(v == NULL) {
	      fprintf(stderr, "Cannot allocate memory for vector v");
	      return NULL;
	    }
	
	    *nbytes = 0;
	    i = 0;
	   
      if(buf != NULL) {
	      v[i].iov_base = buf;
	      v[i].iov_len =  count;
	      *nbytes += count; 
	       
      }
	   
    }
  }


  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_pwrite64_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int fd, void *buf, size_t count, off_t offset) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);



  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_read_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int fd, void *buf, size_t count) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);

  
  /* I read the buffers */
  if(resp_header->resp_size > sizeof(struct sys_resp_header)) {
    int i;
    
    vcount = 1;
    if(buf == NULL)
      vcount--;
 
    if(vcount != 0) {
	    v = calloc(vcount, sizeof(struct iovec));
	    if(v == NULL) {
	      fprintf(stderr, "Cannot allocate memory for vector v");
	      return NULL;
	    }
	
	    *nbytes = 0;
	    i = 0;
	   
	    if(buf != NULL && resp_header->resp_retval > 0) {
	      v[i].iov_base = buf;
	      v[i].iov_len =  resp_header->resp_retval;
	      *nbytes += resp_header->resp_retval;
	       
	    }
	   
    }
  }


  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_readlink_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, char *path, char *buf, size_t bufsiz) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);

  
  /* I read the buffers */
  if(resp_header->resp_size > sizeof(struct sys_resp_header)) {
    int i;
    
    vcount = 1;
    if(buf == NULL)
      vcount--;
 
    if(vcount != 0) {
	    v = calloc(vcount, sizeof(struct iovec));
	    if(v == NULL) {
	      fprintf(stderr, "Cannot allocate memory for vector v");
	      return NULL;
	    }
	
	    *nbytes = 0;
	    i = 0;
	   
      if(buf != NULL) {
	      v[i].iov_base = buf;
	      v[i].iov_len =  bufsiz;
	      *nbytes += bufsiz; 
	       
      }
	   
    }
  }


  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_recv_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int s, void *buf, size_t len, int flags) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);

  
  /* I read the buffers */
  if(resp_header->resp_size > sizeof(struct sys_resp_header)) {
    int i;
    
    vcount = 1;
    if(buf == NULL)
      vcount--;
 
    if(vcount != 0) {
	    v = calloc(vcount, sizeof(struct iovec));
	    if(v == NULL) {
	      fprintf(stderr, "Cannot allocate memory for vector v");
	      return NULL;
	    }
	
	    *nbytes = 0;
	    i = 0;
	   
      if(buf != NULL) {
	      v[i].iov_base = buf;
	      v[i].iov_len =  len;
	      *nbytes += len; 
	       
      }
	   
    }
  }


  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_recvfrom_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int s, void *buf, size_t len, int flags, struct sockaddr *from, socklen_t *fromlen) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);

  
  /* I read the buffers */
  if(resp_header->resp_size > sizeof(struct sys_resp_header)) {
    int i;
    
    vcount = 2;
    if(buf == NULL)
      vcount--;
    if(fromlen == NULL)
      vcount--;
 
    if(vcount != 0) {
	    v = calloc(vcount, sizeof(struct iovec));
	    if(v == NULL) {
	      fprintf(stderr, "Cannot allocate memory for vector v");
	      return NULL;
	    }
	
	    *nbytes = 0;
	    i = 0;
	   
      if(buf != NULL) {
	      v[i].iov_base = buf;
	      v[i].iov_len =  len;
	      *nbytes += len; 
	      i++; 
      }
	   
      if(fromlen != NULL) {
	      v[i].iov_base = fromlen;
	      v[i].iov_len =  sizeof(socklen_t);
	      *nbytes += sizeof(socklen_t); 
	       
      }
	   
    }
  }


  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_rename_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, char *oldpath, char *newpath) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);



  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_rmdir_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, char *pathname) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);



  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_send_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int s, void *buf, size_t len, int flags) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);



  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_sendto_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int s, void *buf, size_t len, int flags, struct sockaddr *to, socklen_t tolen) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);



  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_setdomainname_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, char *name, size_t len) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);



  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_sethostname_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, char *name, size_t len) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);



  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_setsockopt_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int s, int level, int optname, void *optval, socklen_t optlen) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);



  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_settimeofday_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, struct timeval *tv, struct timezone *tz) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);



  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_shutdown_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int s, int how) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);



  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_socket_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int domain, int type, int protocol) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);



  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_stat64_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, char *path, struct stat64 *buf) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);

  
  /* I read the buffers */
  if(resp_header->resp_size > sizeof(struct sys_resp_header)) {
    int i;
    
    vcount = 1;
    if(buf == NULL)
      vcount--;
 
    if(vcount != 0) {
	    v = calloc(vcount, sizeof(struct iovec));
	    if(v == NULL) {
	      fprintf(stderr, "Cannot allocate memory for vector v");
	      return NULL;
	    }
	
	    *nbytes = 0;
	    i = 0;
	   
      if(buf != NULL) {
	      v[i].iov_base = buf;
	      v[i].iov_len =  sizeof(struct stat64);
	      *nbytes += sizeof(struct stat64); 
	       
      }
	   
    }
  }


  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_statfs64_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, char *path, struct statfs64 *buf) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);

  
  /* I read the buffers */
  if(resp_header->resp_size > sizeof(struct sys_resp_header)) {
    int i;
    
    vcount = 1;
    if(buf == NULL)
      vcount--;
 
    if(vcount != 0) {
	    v = calloc(vcount, sizeof(struct iovec));
	    if(v == NULL) {
	      fprintf(stderr, "Cannot allocate memory for vector v");
	      return NULL;
	    }
	
	    *nbytes = 0;
	    i = 0;
	   
      if(buf != NULL) {
	      v[i].iov_base = buf;
	      v[i].iov_len =  sizeof(struct statfs64);
	      *nbytes += sizeof(struct statfs64); 
	       
      }
	   
    }
  }


  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_symlink_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, char *oldpath, char *newpath) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);



  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_truncate64_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, char *path, __off64_t length) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);



  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_umount2_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, char *target, int flags) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);



  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_uname_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, struct utsname *buf) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);

  
  /* I read the buffers */
  if(resp_header->resp_size > sizeof(struct sys_resp_header)) {
    int i;
    
    vcount = 1;
    if(buf == NULL)
      vcount--;
 
    if(vcount != 0) {
	    v = calloc(vcount, sizeof(struct iovec));
	    if(v == NULL) {
	      fprintf(stderr, "Cannot allocate memory for vector v");
	      return NULL;
	    }
	
	    *nbytes = 0;
	    i = 0;
	   
      if(buf != NULL) {
	      v[i].iov_base = buf;
	      v[i].iov_len =  sizeof(struct utsname);
	      *nbytes += sizeof(struct utsname); 
	       
      }
	   
    }
  }


  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_unlink_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, char *pathname) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);



  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_utime_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, char *filename, struct utimbuf *buf) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);



  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_utimes_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, char *filename, struct timeval tv[2]) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);



  *iovec_count = vcount;
  return v;
}

struct iovec *rscc_manage_write_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int fd, void *buf, size_t count) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);



  *iovec_count = vcount;
  return v;
}



/*##########################################################*/
/*##                                                      ##*/
/*##  RSCC FUNCTIONS                                      ##*/
/*##                                                      ##*/
/*##########################################################*/
int rscc__llseek(unsigned int fd, unsigned long int offset_high, unsigned long int offset_low, loff_t *result, unsigned int whence) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create__llseek_request(&nbytes, &iovec_count, fd, offset_high, offset_low, result, whence);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall '_llseek'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage__llseek_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage__llseek_response(&resp_header, &iovec_count, &nbytes, fd, offset_high, offset_low, result, whence);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_accept_request(&nbytes, &iovec_count, sockfd, addr, addrlen);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'accept'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_accept_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_accept_response(&resp_header, &iovec_count, &nbytes, sockfd, addr, addrlen);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_access(char *pathname, int mode) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_access_request(&nbytes, &iovec_count, pathname, mode);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'access'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_access_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_access_response(&resp_header, &iovec_count, &nbytes, pathname, mode);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_adjtimex(struct timex *buf) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_adjtimex_request(&nbytes, &iovec_count, buf);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'adjtimex'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_adjtimex_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_adjtimex_response(&resp_header, &iovec_count, &nbytes, buf);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_bind(int sockfd, struct sockaddr *my_addr, socklen_t addrlen) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_bind_request(&nbytes, &iovec_count, sockfd, my_addr, addrlen);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'bind'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_bind_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_bind_response(&resp_header, &iovec_count, &nbytes, sockfd, my_addr, addrlen);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_chdir(char *path) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_chdir_request(&nbytes, &iovec_count, path);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'chdir'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_chdir_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_chdir_response(&resp_header, &iovec_count, &nbytes, path);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_chmod(char *path, mode_t mode) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_chmod_request(&nbytes, &iovec_count, path, mode);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'chmod'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_chmod_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_chmod_response(&resp_header, &iovec_count, &nbytes, path, mode);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_chown(char *path, uid_t owner, gid_t group) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_chown_request(&nbytes, &iovec_count, path, owner, group);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'chown'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_chown_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_chown_response(&resp_header, &iovec_count, &nbytes, path, owner, group);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_chown32(char *path, uid_t owner, gid_t group) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_chown32_request(&nbytes, &iovec_count, path, owner, group);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'chown32'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_chown32_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_chown32_response(&resp_header, &iovec_count, &nbytes, path, owner, group);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_clock_getres(clockid_t clk_id, struct timespec *res) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_clock_getres_request(&nbytes, &iovec_count, clk_id, res);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'clock_getres'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_clock_getres_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_clock_getres_response(&resp_header, &iovec_count, &nbytes, clk_id, res);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_clock_gettime(clockid_t clk_id, struct timespec *tp) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_clock_gettime_request(&nbytes, &iovec_count, clk_id, tp);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'clock_gettime'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_clock_gettime_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_clock_gettime_response(&resp_header, &iovec_count, &nbytes, clk_id, tp);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_clock_settime(clockid_t clk_id, struct timespec *tp) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_clock_settime_request(&nbytes, &iovec_count, clk_id, tp);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'clock_settime'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_clock_settime_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_clock_settime_response(&resp_header, &iovec_count, &nbytes, clk_id, tp);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_close(int fd) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_close_request(&nbytes, &iovec_count, fd);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'close'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_close_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_close_response(&resp_header, &iovec_count, &nbytes, fd);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_connect(int sockfd, struct sockaddr *serv_addr, socklen_t addrlen) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_connect_request(&nbytes, &iovec_count, sockfd, serv_addr, addrlen);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'connect'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_connect_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_connect_response(&resp_header, &iovec_count, &nbytes, sockfd, serv_addr, addrlen);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_dup(int oldfd) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_dup_request(&nbytes, &iovec_count, oldfd);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'dup'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_dup_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_dup_response(&resp_header, &iovec_count, &nbytes, oldfd);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_dup2(int oldfd, int newfd) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_dup2_request(&nbytes, &iovec_count, oldfd, newfd);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'dup2'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_dup2_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_dup2_response(&resp_header, &iovec_count, &nbytes, oldfd, newfd);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_fchdir(int fd) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_fchdir_request(&nbytes, &iovec_count, fd);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'fchdir'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_fchdir_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_fchdir_response(&resp_header, &iovec_count, &nbytes, fd);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_fchmod(int fildes, mode_t mode) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_fchmod_request(&nbytes, &iovec_count, fildes, mode);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'fchmod'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_fchmod_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_fchmod_response(&resp_header, &iovec_count, &nbytes, fildes, mode);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_fchown(int fd, uid_t owner, gid_t group) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_fchown_request(&nbytes, &iovec_count, fd, owner, group);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'fchown'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_fchown_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_fchown_response(&resp_header, &iovec_count, &nbytes, fd, owner, group);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_fchown32(int fd, uid_t owner, gid_t group) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_fchown32_request(&nbytes, &iovec_count, fd, owner, group);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'fchown32'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_fchown32_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_fchown32_response(&resp_header, &iovec_count, &nbytes, fd, owner, group);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_fdatasync(int fd) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_fdatasync_request(&nbytes, &iovec_count, fd);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'fdatasync'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_fdatasync_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_fdatasync_response(&resp_header, &iovec_count, &nbytes, fd);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_fgetxattr(int filedes, char *name, void *value, size_t size) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_fgetxattr_request(&nbytes, &iovec_count, filedes, name, value, size);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'fgetxattr'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_fgetxattr_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_fgetxattr_response(&resp_header, &iovec_count, &nbytes, filedes, name, value, size);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_fstat64(int filedes, struct stat64 *buf) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_fstat64_request(&nbytes, &iovec_count, filedes, buf);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'fstat64'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_fstat64_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_fstat64_response(&resp_header, &iovec_count, &nbytes, filedes, buf);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_fstatfs64(unsigned int fd, struct statfs64 *buf) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_fstatfs64_request(&nbytes, &iovec_count, fd, buf);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'fstatfs64'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_fstatfs64_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_fstatfs64_response(&resp_header, &iovec_count, &nbytes, fd, buf);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_fsync(int fd) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_fsync_request(&nbytes, &iovec_count, fd);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'fsync'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_fsync_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_fsync_response(&resp_header, &iovec_count, &nbytes, fd);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_ftruncate64(int fd, __off64_t length) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_ftruncate64_request(&nbytes, &iovec_count, fd, length);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'ftruncate64'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_ftruncate64_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_ftruncate64_response(&resp_header, &iovec_count, &nbytes, fd, length);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_getdents64(unsigned int fd, struct dirent64 *dirp, unsigned int count) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_getdents64_request(&nbytes, &iovec_count, fd, dirp, count);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'getdents64'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_getdents64_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_getdents64_response(&resp_header, &iovec_count, &nbytes, fd, dirp, count);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_getpeername(int s, struct sockaddr *name, socklen_t *namelen) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_getpeername_request(&nbytes, &iovec_count, s, name, namelen);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'getpeername'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_getpeername_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_getpeername_response(&resp_header, &iovec_count, &nbytes, s, name, namelen);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_getsockname(int s, struct sockaddr *name, socklen_t *namelen) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_getsockname_request(&nbytes, &iovec_count, s, name, namelen);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'getsockname'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_getsockname_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_getsockname_response(&resp_header, &iovec_count, &nbytes, s, name, namelen);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_getsockopt(int s, int level, int optname, void *optval, socklen_t *optlen) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_getsockopt_request(&nbytes, &iovec_count, s, level, optname, optval, optlen);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'getsockopt'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_getsockopt_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_getsockopt_response(&resp_header, &iovec_count, &nbytes, s, level, optname, optval, optlen);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_gettimeofday(struct timeval *tv, struct timezone *tz) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_gettimeofday_request(&nbytes, &iovec_count, tv, tz);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'gettimeofday'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_gettimeofday_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_gettimeofday_response(&resp_header, &iovec_count, &nbytes, tv, tz);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_getxattr(char *path, char *name, void *value, size_t size) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_getxattr_request(&nbytes, &iovec_count, path, name, value, size);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'getxattr'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_getxattr_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_getxattr_response(&resp_header, &iovec_count, &nbytes, path, name, value, size);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_lchown(char *path, uid_t owner, gid_t group) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_lchown_request(&nbytes, &iovec_count, path, owner, group);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'lchown'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_lchown_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_lchown_response(&resp_header, &iovec_count, &nbytes, path, owner, group);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_lchown32(char *path, uid_t owner, gid_t group) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_lchown32_request(&nbytes, &iovec_count, path, owner, group);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'lchown32'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_lchown32_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_lchown32_response(&resp_header, &iovec_count, &nbytes, path, owner, group);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_lgetxattr(char *path, char *name, void *value, size_t size) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_lgetxattr_request(&nbytes, &iovec_count, path, name, value, size);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'lgetxattr'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_lgetxattr_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_lgetxattr_response(&resp_header, &iovec_count, &nbytes, path, name, value, size);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_link(char *oldpath, char *newpath) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_link_request(&nbytes, &iovec_count, oldpath, newpath);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'link'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_link_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_link_response(&resp_header, &iovec_count, &nbytes, oldpath, newpath);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_listen(int sockfd, int backlog) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_listen_request(&nbytes, &iovec_count, sockfd, backlog);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'listen'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_listen_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_listen_response(&resp_header, &iovec_count, &nbytes, sockfd, backlog);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_lseek(int fildes, off_t offset, int whence) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_lseek_request(&nbytes, &iovec_count, fildes, offset, whence);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'lseek'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_lseek_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_lseek_response(&resp_header, &iovec_count, &nbytes, fildes, offset, whence);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_lstat64(char *path, struct stat64 *buf) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_lstat64_request(&nbytes, &iovec_count, path, buf);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'lstat64'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_lstat64_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_lstat64_response(&resp_header, &iovec_count, &nbytes, path, buf);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_mkdir(char *pathname, mode_t mode) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_mkdir_request(&nbytes, &iovec_count, pathname, mode);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'mkdir'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_mkdir_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_mkdir_response(&resp_header, &iovec_count, &nbytes, pathname, mode);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_mount(char *source, char *target, char *filesystemtype, unsigned long int mountflags, void *data) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_mount_request(&nbytes, &iovec_count, source, target, filesystemtype, mountflags, data);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'mount'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_mount_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_mount_response(&resp_header, &iovec_count, &nbytes, source, target, filesystemtype, mountflags, data);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_open(char *pathname, int flags) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_open_request(&nbytes, &iovec_count, pathname, flags);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'open'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_open_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_open_response(&resp_header, &iovec_count, &nbytes, pathname, flags);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_pread64(int fd, void *buf, size_t count, off_t offset) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_pread64_request(&nbytes, &iovec_count, fd, buf, count, offset);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'pread64'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_pread64_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_pread64_response(&resp_header, &iovec_count, &nbytes, fd, buf, count, offset);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_pwrite64(int fd, void *buf, size_t count, off_t offset) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_pwrite64_request(&nbytes, &iovec_count, fd, buf, count, offset);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'pwrite64'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_pwrite64_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_pwrite64_response(&resp_header, &iovec_count, &nbytes, fd, buf, count, offset);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_read(int fd, void *buf, size_t count) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_read_request(&nbytes, &iovec_count, fd, buf, count);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'read'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_read_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_read_response(&resp_header, &iovec_count, &nbytes, fd, buf, count);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_readlink(char *path, char *buf, size_t bufsiz) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_readlink_request(&nbytes, &iovec_count, path, buf, bufsiz);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'readlink'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_readlink_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_readlink_response(&resp_header, &iovec_count, &nbytes, path, buf, bufsiz);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_recv(int s, void *buf, size_t len, int flags) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_recv_request(&nbytes, &iovec_count, s, buf, len, flags);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'recv'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_recv_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_recv_response(&resp_header, &iovec_count, &nbytes, s, buf, len, flags);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_recvfrom(int s, void *buf, size_t len, int flags, struct sockaddr *from, socklen_t *fromlen) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_recvfrom_request(&nbytes, &iovec_count, s, buf, len, flags, from, fromlen);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'recvfrom'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_recvfrom_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_recvfrom_response(&resp_header, &iovec_count, &nbytes, s, buf, len, flags, from, fromlen);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_rename(char *oldpath, char *newpath) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_rename_request(&nbytes, &iovec_count, oldpath, newpath);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'rename'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_rename_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_rename_response(&resp_header, &iovec_count, &nbytes, oldpath, newpath);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_rmdir(char *pathname) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_rmdir_request(&nbytes, &iovec_count, pathname);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'rmdir'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_rmdir_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_rmdir_response(&resp_header, &iovec_count, &nbytes, pathname);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_send(int s, void *buf, size_t len, int flags) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_send_request(&nbytes, &iovec_count, s, buf, len, flags);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'send'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_send_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_send_response(&resp_header, &iovec_count, &nbytes, s, buf, len, flags);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_sendto(int s, void *buf, size_t len, int flags, struct sockaddr *to, socklen_t tolen) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_sendto_request(&nbytes, &iovec_count, s, buf, len, flags, to, tolen);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'sendto'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_sendto_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_sendto_response(&resp_header, &iovec_count, &nbytes, s, buf, len, flags, to, tolen);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_setdomainname(char *name, size_t len) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_setdomainname_request(&nbytes, &iovec_count, name, len);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'setdomainname'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_setdomainname_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_setdomainname_response(&resp_header, &iovec_count, &nbytes, name, len);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_sethostname(char *name, size_t len) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_sethostname_request(&nbytes, &iovec_count, name, len);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'sethostname'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_sethostname_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_sethostname_response(&resp_header, &iovec_count, &nbytes, name, len);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_setsockopt(int s, int level, int optname, void *optval, socklen_t optlen) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_setsockopt_request(&nbytes, &iovec_count, s, level, optname, optval, optlen);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'setsockopt'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_setsockopt_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_setsockopt_response(&resp_header, &iovec_count, &nbytes, s, level, optname, optval, optlen);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_settimeofday(struct timeval *tv, struct timezone *tz) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_settimeofday_request(&nbytes, &iovec_count, tv, tz);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'settimeofday'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_settimeofday_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_settimeofday_response(&resp_header, &iovec_count, &nbytes, tv, tz);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_shutdown(int s, int how) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_shutdown_request(&nbytes, &iovec_count, s, how);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'shutdown'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_shutdown_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_shutdown_response(&resp_header, &iovec_count, &nbytes, s, how);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_socket(int domain, int type, int protocol) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_socket_request(&nbytes, &iovec_count, domain, type, protocol);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'socket'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_socket_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_socket_response(&resp_header, &iovec_count, &nbytes, domain, type, protocol);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_stat64(char *path, struct stat64 *buf) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_stat64_request(&nbytes, &iovec_count, path, buf);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'stat64'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_stat64_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_stat64_response(&resp_header, &iovec_count, &nbytes, path, buf);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_statfs64(char *path, struct statfs64 *buf) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_statfs64_request(&nbytes, &iovec_count, path, buf);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'statfs64'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_statfs64_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_statfs64_response(&resp_header, &iovec_count, &nbytes, path, buf);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_symlink(char *oldpath, char *newpath) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_symlink_request(&nbytes, &iovec_count, oldpath, newpath);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'symlink'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_symlink_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_symlink_response(&resp_header, &iovec_count, &nbytes, oldpath, newpath);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_truncate64(char *path, __off64_t length) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_truncate64_request(&nbytes, &iovec_count, path, length);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'truncate64'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_truncate64_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_truncate64_response(&resp_header, &iovec_count, &nbytes, path, length);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_umount2(char *target, int flags) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_umount2_request(&nbytes, &iovec_count, target, flags);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'umount2'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_umount2_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_umount2_response(&resp_header, &iovec_count, &nbytes, target, flags);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_uname(struct utsname *buf) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_uname_request(&nbytes, &iovec_count, buf);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'uname'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_uname_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_uname_response(&resp_header, &iovec_count, &nbytes, buf);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_unlink(char *pathname) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_unlink_request(&nbytes, &iovec_count, pathname);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'unlink'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_unlink_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_unlink_response(&resp_header, &iovec_count, &nbytes, pathname);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_utime(char *filename, struct utimbuf *buf) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_utime_request(&nbytes, &iovec_count, filename, buf);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'utime'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_utime_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_utime_response(&resp_header, &iovec_count, &nbytes, filename, buf);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_utimes(char *filename, struct timeval tv[2]) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_utimes_request(&nbytes, &iovec_count, filename, tv);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'utimes'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_utimes_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_utimes_response(&resp_header, &iovec_count, &nbytes, filename, tv);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
int rscc_write(int fd, void *buf, size_t count) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_write_request(&nbytes, &iovec_count, fd, buf, count);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'write'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_write_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_write_response(&resp_header, &iovec_count, &nbytes, fd, buf, count);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}

# if 0
int rsc_recvmsg(int s, struct msghdr *msg, int flags) {
  struct recvmsg_req recvmsg_req;
  struct recvmsg_resp recvmsg_resp;
  int nwrite, nread, i, total_size;
  size_t *iov_len_array;
  enum rsc_constant rsc_const;


  memset(&recvmsg_req, 0, sizeof(struct recvmsg_req));
  if( (rsc_const = nr2rsc(__NR_socketcall, SYS_RECVMSG, my_arch)) == __RSC_ERROR )
    return -1;
  recvmsg_req.req_rsc_const = htons(rsc_const);
  /* The size of the request is formed by:
   * 1. the size of structure recvmsg_req
   * 2. the size of the msg->msg_name and msg->msg_controll buffers 
   * 3. the sizes of iov_base buffers inside the msg->msg_iov array */
  total_size = sizeof(struct recvmsg_req);
  if(msg->msg_name != NULL)
    total_size += msg->msg_namelen;

  if(msg->msg_control != NULL)
    total_size += msg->msg_controllen;
  
  if(msg->msg_iov != NULL)
    total_size += msg->msg_iovlen * sizeof(size_t);

  recvmsg_req.req_size = htonl(total_size);
  recvmsg_req.s = s;
  memcpy(&(recvmsg_req.msg), msg, sizeof(recvmsg_req.msg));
  recvmsg_req.flags = flags;

  printf("RECVMSG: Header: req_rsc_const = %d (%lX); req_size = %d (%lX)\n", ntohl(recvmsg_req.req_rsc_const), ntohl(recvmsg_req.req_rsc_const), ntohl(recvmsg_req.req_size), ntohl(recvmsg_req.req_size));
  printf("s = %d, flags = %d\n", recvmsg_req.s, recvmsg_req.flags);
  RSC_PRINT_MSGHDR(RSCD_REQ_RESP, msg);

  /* I send the request header */
  nwrite = write_n_bytes(rsc_sockfd, &recvmsg_req, sizeof(struct recvmsg_req));
  if(nwrite != sizeof(struct recvmsg_req)) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, sizeof(struct recvmsg_req));
    return -1;
  }

  /* Now I have to send the data pointed by the pointer inside the msg structure: */
  /* 1. "msg_name": it can be null, so I send it only if it isn't null. */
  if(msg->msg_name != NULL) {
    printf("Sending msg_name (len = %d)\n", msg->msg_namelen);
    nwrite = write_n_bytes(rsc_sockfd, msg->msg_name, msg->msg_namelen);
    printf("Sent %d/%d bytes\n", nwrite, msg->msg_namelen);
    if(nwrite != msg->msg_namelen) {
      fprintf(stderr, "I've sent only %d/%d bytes of msg->msg_name.\n", nwrite, msg->msg_namelen);
      return -1;
    }
  }
  
  /* 2. "msg_iov": it's an array of buffers so I don't need to send them, but I have
   *               to send the length of each buffer. */
  if(msg->msg_iov != NULL) {
    iov_len_array = calloc(msg->msg_iovlen, sizeof(size_t));
    for(i = 0; i < msg->msg_iovlen; i++) {
      printf("msg->msg_iov[%d].iov_len = %d\n", i, (msg->msg_iov[i]).iov_len);
      iov_len_array[i] = (msg->msg_iov[i]).iov_len;
    }
  }

  printf("msg->msg_iovlen = %d\n", msg->msg_iovlen);
  for(i = 0; i < msg->msg_iovlen; i++) { printf("iov_len_array[%d] = %d\n", i, iov_len_array[i]); }

  nwrite = write_n_bytes(rsc_sockfd, iov_len_array, msg->msg_iovlen * sizeof(size_t));
  printf("Sent %d/%d byte od msg->msg_iov\n", nwrite, msg->msg_iovlen);
  if(nwrite != msg->msg_iovlen * sizeof(size_t)) {
    fprintf(stderr, "I've sent only %d/%d bytes of msg->msg_name.\n", nwrite, msg->msg_iovlen);
    return -1;
  }

  /* 3. "msg_control" */
  if(msg->msg_control != NULL) {
    printf("Sending msg_control (len = %d)\n", msg->msg_controllen);
    nwrite = write_n_bytes(rsc_sockfd, msg->msg_control, msg->msg_controllen);
    printf("Sent %d/%d byte od msg->msg_control\n", nwrite, msg->msg_controllen);
    if(nwrite != msg->msg_controllen) {
      fprintf(stderr, "I've sent only %d/%d bytes of msg->msg_name.\n", nwrite, msg->msg_controllen);
      return -1;
    }
  }
  
  nread = read_n_bytes(rsc_sockfd, &recvmsg_resp, sizeof(struct recvmsg_resp));
  if(nread != sizeof(struct recvmsg_resp)) {
    fprintf(stderr, "I've read only %d/%d bytes.\n", nwrite, sizeof(struct recvmsg_req));
    return -1;
  }
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s", rsc2str(recvmsg_resp.resp_type));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader: resp_type = %d (0x%lX); resp_size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", recvmsg_resp.resp_type, recvmsg_resp.resp_type, recvmsg_resp.resp_size, recvmsg_resp.resp_size, recvmsg_resp.resp_retval, recvmsg_resp.resp_retval, recvmsg_resp.resp_errno, recvmsg_resp.resp_errno);

  if(recvmsg_resp.resp_retval != -1) {
    int i;
    for(i = 0; i < msg->msg_iovlen; i++) {
      nread = read_n_bytes(rsc_sockfd, msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len);
      printf("Reading into buffer # %d; read %d bytes; buffer size = %d bytes\n", i, nread, msg->msg_iov[i].iov_len);
    }
  }
  
  printf("############## => recvmsg_resp.msg_controllen = %d\n", recvmsg_resp.msg_controllen);
  msg->msg_controllen = recvmsg_resp.msg_controllen;
  if(recvmsg_resp.msg_controllen != 0)
    nread = read_n_bytes(rsc_sockfd, msg->msg_control, recvmsg_resp.msg_controllen);
  else
    msg->msg_control = NULL;

  RSC_PRINT_MSGHDR(RSCD_REQ_RESP, msg);
  errno = recvmsg_resp.resp_errno;
  return recvmsg_resp.resp_retval;
}
#endif

/* This function build the request for the system call 'ioctl' */
struct iovec *rscc_create_ioctl_request(int *total_size, int *iovec_count, u_int32_t size_type, int d, int request, void *arg) {
  struct ioctl_req *ioctl_req;
  enum rsc_constant rsc_const;
  int i;
  struct iovec *v;
  size_t vcount;
  int arg_size_value;

  ioctl_req = calloc(1, sizeof(struct ioctl_req));
  if(ioctl_req == NULL)
    return NULL;
	if( (rsc_const = nr2rsc(__NR_ioctl, NO_VALUE, my_arch)) == __RSC_ERROR ) {
    free(ioctl_req);
	  return NULL;
  }
  ioctl_req->req_type = RSC_SYS_REQ;
  ioctl_req->req_rsc_const = htons(rsc_const);

  /* If arg is NULL or is a write pointer, don't send it */
  if(arg != NULL && (size_type & IOCTL_R))
    arg_size_value = size_type & IOCTL_LENMASK;
  else
    arg_size_value = 0;


  ioctl_req->req_size = htonl(sizeof(struct ioctl_req) + arg_size_value);

	ioctl_req->d = d;
  ioctl_req->request = request;
  ioctl_req->arg = arg;        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 1;
  if(arg != NULL && (size_type & IOCTL_R))
    vcount++;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = ioctl_req;
  v[0].iov_len = sizeof(struct ioctl_req);
  *total_size = v[0].iov_len;
  i = 1;
 
  if(arg != NULL && (size_type & IOCTL_R)) {
    v[i].iov_base = arg;
    v[i].iov_len =  arg_size_value;
    *total_size += v[i].iov_len;
  }
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(ioctl_req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct ioctl_req),
      rsc2str(ntohs(ioctl_req->req_rsc_const)), ntohs(ioctl_req->req_rsc_const), 
      ntohl(ioctl_req->req_size), ntohl(ioctl_req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: d = %ld (0x%lX); request = %ld (0x%lX); arg = %p (0x%lX)", 
      ioctl_req->d, ioctl_req->d, ioctl_req->request, ioctl_req->request, ioctl_req->arg, ioctl_req->arg);

  return v;
}

struct iovec *rscc_manage_ioctl_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, u_int32_t size_type, void *arg) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  int byte_num = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);

  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_type = %d (0x%lX); resp_size = %d (0x%lX) bytes; resp_rsc_const = %d (0x%lX); resp_retval = %d (0x%lX); errno = %d (0x%lX)\n", 
      sizeof(struct sys_resp_header),
      resp_header->resp_type, resp_header->resp_type,
      resp_header->resp_size, resp_header->resp_size, 
      resp_header->resp_rsc_const, resp_header->resp_rsc_const, 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);

  if((resp_header->resp_size > sizeof(struct sys_resp_header)) && 
      (arg != NULL) && (size_type & IOCTL_W)) {
    v = calloc(1, sizeof(struct iovec));
	  if(v == NULL) {
	    fprintf(stderr, "Cannot allocate memory for vector v");
	    return NULL;
	  }
    v[0].iov_base = arg;
    v[0].iov_len = size_type & IOCTL_LENMASK;
    vcount = 1;
    byte_num = v[0].iov_len;
  }
  *nbytes = byte_num;
  *iovec_count = vcount;
  return v;
}

int rscc_ioctl(int d, int request, void *arg) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  u_int32_t size_type;

  /* I get the type and the size of 'arg' */
  size_type = rscc_check_ioctl_request(request);
  /* An error occurs or the 'request' isn't managed */
  if(size_type == 0 || size_type == IOCTL_UNMANAGED)
    return -1;


  /* I build the request */
  v = rscc_create_ioctl_request(&nbytes, &iovec_count, size_type, d, request, arg);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'ioctl'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);
  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }
  
  /* I read the additional data, if there is. */
  v = rscc_manage_ioctl_response(&resp_header, &iovec_count, &nbytes, size_type, arg);
  if(v != NULL) {
    nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
    if(nread != nbytes) {
      fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
      return -1;
    }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}

/***********************************************************************************************/
/***********************************************************************************************/
/***********************************************************************************************/

#ifndef RSCDEBUG
static 
#endif
struct ioctl_cache *ioctl_cache_init(int size) {
  struct ioctl_cache *cache;
  cache = calloc(1, sizeof(struct ioctl_cache));
  if(cache == NULL)
    return NULL;
  cache->size = size;
  cache->nentry = 0;

  return cache;
}

#ifndef RSCDEBUG
static 
#endif
void ioctl_cache_add(struct ioctl_cache *cache, int request, u_int32_t size_type) {
  struct ioctl_cache_el *el;
  el = calloc(1, sizeof(struct ioctl_cache_el));
  assert(el != NULL);
  /* I fill the request and update the pointers */
  el->request    = request;
  el->size_type  = size_type;
  /* There isn't room, I have to pop the last element,
   * before push it the new one */
  if(cache->nentry == cache->size) {
    cache->last = cache->last->prev;
    free(cache->last->next);
    cache->last->next = NULL;
    cache->nentry -= 1;
  } else if(cache->nentry == 0) 
    cache->last = el;
  el->next = cache->first;
  if(cache->first != NULL)
    cache->first->prev = el;
  cache->first = el;
  cache->nentry += 1;
}


#ifndef RSCDEBUG
static 
#endif
u_int32_t ioctl_cache_search(struct ioctl_cache *cache, int request) {
  struct ioctl_cache_el *el;
  for(el = cache->first; el != NULL; el = el->next) {
    if(el->request == request)
      return el->size_type;
  }

  return 0;
}

/* Returns the size_type for the given request. The returned values
 * can be:
 * - 0: if an error occurs
 * - IOCTL_UNMANAGED: if the server doesn't manage 'request'
 * - otherwise is the size_type value */
u_int32_t rscc_check_ioctl_request(int request) {
  struct ioctl_req_header req;
  struct ioctl_resp_header resp;
  int ret;
  u_int32_t size_type;

  /* I control if the request is in the cache */
  size_type = ioctl_cache_search(ioctl_cache, request);
  if(size_type == 0) {
	  /* otherwise I call the server */
	  bzero(&req, sizeof(struct ioctl_req_header));
	  req.req_type = RSC_IOCTL_REQ;
	  req.req_size = htonl(sizeof(struct ioctl_req_header));
	  req.req_ioctl_request = htonl(request);
	
	  /* I send the request */
	  ret = write_n_bytes(rsc_sockfd, &req, sizeof(struct ioctl_req_header));
	  if(ret != sizeof(struct ioctl_req_header))
	    return 0;
	
	  /* I wait the answer */
	  ret = read_n_bytes(rsc_sockfd, &resp, sizeof(struct ioctl_resp_header));
	  if(ret != sizeof(struct ioctl_resp_header))
	    return 0;
	  resp.resp_size = ntohl(resp.resp_size);
	  resp.resp_size_type = ntohl(resp.resp_size_type);
	  /* I add it to the cache */
	  ioctl_cache_add(ioctl_cache, request, resp.resp_size_type);

    size_type = resp.resp_size_type;
  }

  return size_type;
}

#ifndef RSCDEBUG
static 
#endif
u_int16_t fcntl_cmd_type(int cmd) {
  u_int16_t res = 0;
  switch(cmd) {
    case F_GETFD:
    case F_GETFL:
    case F_GETOWN:
    case F_GETSIG:
    case F_GETLEASE:
      res = FCNTL_NO_3RD_ARG;
      break;
    case F_DUPFD:
    case F_SETFD:
    case F_SETFL:
    case F_SETOWN:
    case F_SETSIG:
    case F_SETLEASE:
    case F_NOTIFY:
      res = FCNTL_3RD_LONG;
      break;
    case F_SETLK:
    case F_SETLKW:
      res = FCNTL_3RD_FLOCK_R;
      break;
    case F_GETLK:
      res = FCNTL_3RD_FLOCK_RW;
      break;
    default:
      res = 0;
      break;
  }

  return res;
}

/* This function build the request for the system call 'fcntl' */
struct iovec *rscc_create_fcntl_request(int *total_size, int *iovec_count, u_int16_t cmd_type, int fd, int cmd, long third_arg) {
  struct fcntl_req *fcntl_req;
  enum rsc_constant rsc_const;
  struct iovec *v;
  size_t vcount;
  int third_arg_size;
  

  fcntl_req = calloc(1, sizeof(struct fcntl_req));
  if(fcntl_req == NULL)
    return NULL;
	if( (rsc_const = nr2rsc(__NR_fcntl, NO_VALUE, my_arch)) == __RSC_ERROR ) {
    free(fcntl_req);
	  return NULL;
  }
  fcntl_req->req_type = RSC_SYS_REQ;
  fcntl_req->req_rsc_const = htons(rsc_const);

	fcntl_req->fd = fd;
  fcntl_req->cmd = cmd;
	fcntl_req->cmd_type = cmd_type;
  /* If there is a third argument, I manage it */
  if(cmd_type == FCNTL_NO_3RD_ARG) {
    fcntl_req->req_size = htonl(sizeof(struct fcntl_req));
  
    *iovec_count = 1;
    v = calloc(*iovec_count, sizeof(struct iovec));
    if(v == NULL) {
      fprintf(stderr, "Cannot allocate memory for vector v");
      return NULL;
    }
    v[0].iov_base = fcntl_req;
    v[0].iov_len = sizeof(struct fcntl_req);
    *total_size = v[0].iov_len;
  } else {
    /* I set the request fields accordingly with the
     * type of the third argument */
    if(cmd_type == FCNTL_3RD_LONG) {
      third_arg_size = 0;
      fcntl_req->third.arg = third_arg;
      vcount = 1;
    } else {
      struct flock *lock = (struct flock *)third_arg;
      vcount = 1;
      third_arg_size = 0;
      if(lock != NULL && (cmd_type == FCNTL_3RD_FLOCK_R || cmd_type == FCNTL_3RD_FLOCK_RW)) {
        third_arg_size = sizeof(struct flock);
        vcount = 2;
      }
      fcntl_req->third.lock = lock;
    }
  
    fcntl_req->req_size = htonl(sizeof(struct fcntl_req) + third_arg_size);

    /* There are pointers to buffers used by the system call to read data, so
     * I've to send them. */
    v = calloc(vcount, sizeof(struct iovec));
    if(v == NULL) {
      fprintf(stderr, "Cannot allocate memory for vector v");
      return NULL;
    }

    v[0].iov_base = fcntl_req;
    v[0].iov_len = sizeof(struct fcntl_req);
    *total_size = v[0].iov_len;
 
    /* If vcount == 2, the third argument is a non-NULL pointer
     * to a struct flock. */
    if(vcount == 2) {
      v[1].iov_base = fcntl_req->third.lock;
      v[1].iov_len =  sizeof(struct flock);
      *total_size += v[1].iov_len;
    }
    *iovec_count = vcount;
  } 

	rsc_const = nr2rsc(__NR_fcntl, NO_VALUE, my_arch);
  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(fcntl_req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct fcntl_req),
      rsc2str(ntohs(fcntl_req->req_rsc_const)), ntohs(fcntl_req->req_rsc_const), 
      ntohl(fcntl_req->req_size), ntohl(fcntl_req->req_size));
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: fd = %ld (0x%lX); cmd = %ld (0x%lX);", fcntl_req->fd, fcntl_req->fd, fcntl_req->cmd, fcntl_req->cmd);
  
  return v;
 
}

struct iovec *rscc_manage_fcntl_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, u_int16_t cmd_type, long third_arg) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  int bytes_num = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);

  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_type = %d (0x%lX); resp_size = %d (0x%lX) bytes; resp_rsc_const = %d (0x%lX); resp_retval = %d (0x%lX); errno = %d (0x%lX)\n", 
      sizeof(struct sys_resp_header),
      resp_header->resp_type, resp_header->resp_type,
      resp_header->resp_size, resp_header->resp_size, 
      resp_header->resp_rsc_const, resp_header->resp_rsc_const, 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);

  
  /* If the third argument is a write pointer to a struct flock and the 
   * size of the response is greater than the size of a normal response,
   * read the flock structure */
  if( ((cmd_type == FCNTL_3RD_FLOCK_W) || (cmd_type == FCNTL_3RD_FLOCK_RW)) &&
      (resp_header->resp_size > sizeof(struct sys_resp_header)) ) {
            /* I read the 'lock' argument (id it's not NULL) */
      struct flock *lock = (struct flock *)third_arg;
      if( lock != NULL) {
        v = calloc(1, sizeof(struct iovec));
        if(v == NULL) {
	        fprintf(stderr, "Cannot allocate memory for vector v");
          return NULL;
        }
        v[0].iov_base = lock;
        v[0].iov_len = sizeof(struct flock);
        vcount = 1;
        bytes_num = v[0].iov_len;
      }
  }
  *iovec_count = vcount;
  *nbytes = bytes_num;
  return v;
}

int rscc_fcntl(int fd, int cmd, ...) {
  va_list ap;
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  long third_arg = 0;
  u_int16_t cmd_type;
  /* I get some info about 'cmd' */
  if((cmd_type = fcntl_cmd_type(cmd)) == 0)
    return -1;
  /* If there is a third argument, I read it */
  if(cmd_type != FCNTL_NO_3RD_ARG) {
    va_start(ap, cmd);
    third_arg = va_arg(ap, long);
    va_end(ap);
  }

  /* I build the request */
  v = rscc_create_fcntl_request(&nbytes, &iovec_count, cmd_type, fd, cmd, third_arg);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'fcntl'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);
  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }
  /* I read the additional data, if there is. */
  v = rscc_manage_fcntl_response(&resp_header, &iovec_count, &nbytes, cmd_type, third_arg);
  if(v != NULL) {
    nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
    if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }

  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
