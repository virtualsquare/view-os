/*   
 *   This is part of Remote System Call (RSC) Library.
 *
 *   utils.c: some utility functions
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
#include <unistd.h>
#include <errno.h>
#include <sys/uio.h>

#include "debug.h"
#include "utils.h"


int write_n_bytes(int fd, void *buffer, int nbytes) {
  int n, nwritten;
  char *buf = buffer;
#ifdef RSCDEBUG
  int total_bytes = nbytes;
#endif

  assert(fd >= 0);
  /* assert(buf != NULL); */
  /* If the buffer is null, I return nbytes.
   * In this way, if the caller has made a mistake passing me a empty buffer,
   * It doesn't recevie an error. */
  if(buf == NULL) return nbytes;
  assert(nbytes >= 0);

  nwritten = 0;
  while(nbytes > 0) {
    n = write(fd, buf, nbytes);
    if( (n == -1) || (n == 0) ) {
      if(n == -1) { RSC_DEBUG(RSCD_RW, "write error: '%s'", strerror(errno)); }
      break;
    }
  
    /* assert(n > 0); */
    nwritten += n;
    nbytes -= n;
    buf += n;
  }
  
  RSC_DEBUG(RSCD_RW, "[fd = %d; buf = %p (len = %d bytes)] written %d/%d bytes.", fd, buffer, total_bytes, nwritten, total_bytes);

  return nwritten;
}

int read_n_bytes(int fd, void *buffer, int nbytes) {
  int n, nread;
  void *buf = buffer;
#ifdef RSCDEBUG
  int total_bytes = nbytes;
#endif
  assert(fd >= 0);
  assert(buf != NULL);
  assert(nbytes >= 0);

  nread = 0;
  while(nbytes > 0) {
    n = read(fd, buf, nbytes);
    if( (n == -1) || (n == 0) ) {
      if(n == -1) { RSC_DEBUG(RSCD_RW, "read error: '%s'", strerror(errno)); }
      if(n == 0 || (n == -1 && errno != EINTR)) { break; }
      n = 0;
      /* break; */
    }
    
    /* assert(n > 0); */
    nread += n;
    nbytes -= n;
    buf += n;
  }
  
  RSC_DEBUG(RSCD_RW, "[fd = %d; buf = %p (len = %d bytes)] read %d/%d bytes.", fd, buffer, total_bytes, nread, total_bytes);
  return nread;
}

int rwv_n_bytes(rwv_fun fun, int fd, struct iovec *vector, size_t count, int nbytes) {
  int i, n, nrw;
  struct iovec *v, *v_orig;
  int total_bytes;
#ifdef RSCDEBUG
  int original_count = count;
#endif
  
  assert(fd >= 0);
  assert(vector != NULL);
  assert(count > 0);

  /* I copy the vector, because I've to work on it */
  v = calloc(count, sizeof(struct iovec));
  assert(v != NULL);
  v_orig = v;
  int total = 0;
  for(i = 0; i < count; i ++) {
    v[i].iov_base = vector[i].iov_base;
    v[i].iov_len = vector[i].iov_len;
    total += v[i].iov_len;
  }
  total_bytes = nbytes;
  nrw = 0;
  while(nbytes > 0) {
    n = fun(fd, v, count);
    if( (n == -1) || (n == 0) ) {
      if(n == -1) { RSC_DEBUG(RSCD_RW, "function error: '%s'", strerror(errno)); }
      if(n == 0 || (n == -1 && errno != EINTR)) { break; }
      n = 0;
    }
    nrw += n;
    nbytes -= n;
    /* I've read/write all */
    if(nrw == total_bytes)
      break;

    for(i = 0; i < count; i++) {
      if(v[i].iov_len <= n)
        n -= v[i].iov_len;
      else
        break;
    }
    v[i].iov_base = v[i].iov_base + n;
    v[i].iov_len  -= n;
    v += i;
    count -= i;
    
  }
  
  RSC_DEBUG(RSCD_RW, "[fd = %d; vector = %p; count = %d] read/write %d/%d bytes.", fd, vector, original_count, nrw, total_bytes);
  free(v_orig);
  return nrw;
}
