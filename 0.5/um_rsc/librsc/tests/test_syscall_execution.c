/*   
 *   This is part of Remote System Call (RSC) Library.
 *
 *   test_syscall_execution.c: system call execution tests 
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
#include "rsc_client.h"
#include "rsc_server.h"
#include "test_rsc_server.h"

#define __USE_LARGEFILE64
#include "fill_request.h"
#include "fill_write_pointers.h"
#include "type_equality.h"
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


static void dump(void *p, int size, int bytenum) {
  int i;
  fprintf(stderr, "Mem %p[%d bytes]:", p, size);
  for(i = 0; i < size;  i++) {
    if(i % bytenum == 0)
      fprintf(stderr, "\n\t%p:\t", p+i);

    fprintf(stderr, "%.2X", 0xFF & *(char *)(p+i));
  }
  fprintf(stderr, "\n");
}

void client_test__llseek(int fd) {
#ifdef __x86_64__ 
  return NULL;
#else
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct _llseek_req *in = fill__llseek_request();
  struct _llseek_req *local = fill__llseek_request();
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create__llseek_request(&nbytes, &iov_count, in->fd, in->offset_high, in->offset_low, in->result, in->whence);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage__llseek_response(&resp_hd, &iov_count, &nbytes, in->fd, in->offset_high, in->offset_low, in->result, in->whence);
  assert(resp_iov != NULL); 
  ret = readv(fd, resp_iov, iov_count);
  assert(ret == nbytes);
  free(resp_iov);
  /* I fill the 'local' request, in this way I can compare this local copy with
   * the remote one 'in' */
  _llseek_fill_write_pointers(local->fd, local->offset_high, local->offset_low, local->result, local->whence);
  assert(local->fd == in->fd);
  assert(local->offset_high == in->offset_high);
  assert(local->offset_low == in->offset_low);
  assert(compare_loff_t(local->result, in->result));
  assert(local->whence == in->whence);

  free_filled__llseek_request(in, 0);
  free_filled__llseek_request(local, 0);
#endif
 
}

void server_test__llseek(int fd, enum arch server_arch, enum arch client_arch) {
#ifdef __x86_64__ 
  return NULL;
#else
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct _llseek_req *input = fill__llseek_request();
  struct _llseek_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre__llseek_exec(req_hd, client_arch);
  req = (struct _llseek_req *) req_hd;
  /* I test the content of the request */
  assert(req->fd == input->fd);
  assert(req->offset_high == input->offset_high);
  assert(req->offset_low == input->offset_low);
  assert(req->whence == input->whence);

  /* I simulate the execution of the system call, calling
   * a function that fills the write pointer of the request. */
  ret = _llseek_fill_write_pointers(req->fd, req->offset_high, req->offset_low, req->result, req->whence);

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post__llseek_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled__llseek_request(input, 0);
#endif
 
}
void client_test_accept(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct accept_req *in = fill_accept_request(FALSE);
  struct accept_req *local = fill_accept_request(FALSE);
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_accept_request(&nbytes, &iov_count, in->sockfd, in->addr, in->addrlen);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_accept_response(&resp_hd, &iov_count, &nbytes, in->sockfd, in->addr, in->addrlen);
  assert(resp_iov != NULL); 
  ret = readv(fd, resp_iov, iov_count);
  assert(ret == nbytes);
  free(resp_iov);
  /* I fill the 'local' request, in this way I can compare this local copy with
   * the remote one 'in' */
  accept_fill_write_pointers(local->sockfd, local->addr, local->addrlen);
  assert(local->sockfd == in->sockfd);
  assert(compare_struct_sockaddr(local->addr, in->addr));
  assert(compare_socklen_t(local->addrlen, in->addrlen));

  free_filled_accept_request(in, 0);
  free_filled_accept_request(local, 0);
 
}

void server_test_accept(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct accept_req *input = fill_accept_request(FALSE);
  struct accept_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_accept_exec(req_hd, client_arch);
  req = (struct accept_req *) req_hd;
  /* I test the content of the request */
  assert(req->sockfd == input->sockfd);

  /* I simulate the execution of the system call, calling
   * a function that fills the write pointer of the request. */
  ret = accept_fill_write_pointers(req->sockfd, req->addr, req->addrlen);

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_accept_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_accept_request(input, 0);
 
}
void client_test_access(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct access_req *in = fill_access_request(FALSE);
  struct access_req *local = fill_access_request(FALSE);
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_access_request(&nbytes, &iov_count, in->pathname, in->mode);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_access_response(&resp_hd, &iov_count, &nbytes, in->pathname, in->mode);
  assert(resp_iov == NULL); 
  assert(compare_string(local->pathname, in->pathname));
  assert(local->mode == in->mode);

  free_filled_access_request(in, 0);
  free_filled_access_request(local, 0);
 
}

void server_test_access(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct access_req *input = fill_access_request(FALSE);
  struct access_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_access_exec(req_hd, client_arch);
  req = (struct access_req *) req_hd;
  /* I test the content of the request */
  assert(compare_string(req->pathname, input->pathname));
  assert(req->mode == input->mode);

  /* The syscall doesn't have write pointers, so I do nothing */

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_access_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_access_request(input, 0);
 
}
void client_test_adjtimex(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct adjtimex_req *in = fill_adjtimex_request(FALSE);
  struct adjtimex_req *local = fill_adjtimex_request(FALSE);
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_adjtimex_request(&nbytes, &iov_count, in->buf);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_adjtimex_response(&resp_hd, &iov_count, &nbytes, in->buf);
  assert(resp_iov != NULL); 
  ret = readv(fd, resp_iov, iov_count);
  assert(ret == nbytes);
  free(resp_iov);
  /* I fill the 'local' request, in this way I can compare this local copy with
   * the remote one 'in' */
  adjtimex_fill_write_pointers(local->buf);
  assert(compare_struct_timex(local->buf, in->buf));

  free_filled_adjtimex_request(in, 0);
  free_filled_adjtimex_request(local, 0);
 
}

void server_test_adjtimex(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct adjtimex_req *input = fill_adjtimex_request(FALSE);
  struct adjtimex_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_adjtimex_exec(req_hd, client_arch);
  req = (struct adjtimex_req *) req_hd;
  /* I test the content of the request */

  /* I simulate the execution of the system call, calling
   * a function that fills the write pointer of the request. */
  ret = adjtimex_fill_write_pointers(req->buf);

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_adjtimex_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_adjtimex_request(input, 0);
 
}
void client_test_bind(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct bind_req *in = fill_bind_request(FALSE);
  struct bind_req *local = fill_bind_request(FALSE);
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_bind_request(&nbytes, &iov_count, in->sockfd, in->my_addr, in->addrlen);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_bind_response(&resp_hd, &iov_count, &nbytes, in->sockfd, in->my_addr, in->addrlen);
  assert(resp_iov == NULL); 
  assert(local->sockfd == in->sockfd);
  assert(compare_struct_sockaddr(local->my_addr, in->my_addr));
  assert(local->addrlen == in->addrlen);

  free_filled_bind_request(in, 0);
  free_filled_bind_request(local, 0);
 
}

void server_test_bind(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct bind_req *input = fill_bind_request(FALSE);
  struct bind_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_bind_exec(req_hd, client_arch);
  req = (struct bind_req *) req_hd;
  /* I test the content of the request */
  assert(req->sockfd == input->sockfd);
  assert(compare_struct_sockaddr(req->my_addr, input->my_addr));
  assert(req->addrlen == input->addrlen);

  /* The syscall doesn't have write pointers, so I do nothing */

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_bind_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_bind_request(input, 0);
 
}
void client_test_chdir(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct chdir_req *in = fill_chdir_request(FALSE);
  struct chdir_req *local = fill_chdir_request(FALSE);
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_chdir_request(&nbytes, &iov_count, in->path);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_chdir_response(&resp_hd, &iov_count, &nbytes, in->path);
  assert(resp_iov == NULL); 
  assert(compare_string(local->path, in->path));

  free_filled_chdir_request(in, 0);
  free_filled_chdir_request(local, 0);
 
}

void server_test_chdir(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct chdir_req *input = fill_chdir_request(FALSE);
  struct chdir_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_chdir_exec(req_hd, client_arch);
  req = (struct chdir_req *) req_hd;
  /* I test the content of the request */
  assert(compare_string(req->path, input->path));

  /* The syscall doesn't have write pointers, so I do nothing */

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_chdir_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_chdir_request(input, 0);
 
}
void client_test_chmod(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct chmod_req *in = fill_chmod_request(FALSE);
  struct chmod_req *local = fill_chmod_request(FALSE);
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_chmod_request(&nbytes, &iov_count, in->path, in->mode);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_chmod_response(&resp_hd, &iov_count, &nbytes, in->path, in->mode);
  assert(resp_iov == NULL); 
  assert(compare_string(local->path, in->path));
  assert(local->mode == in->mode);

  free_filled_chmod_request(in, 0);
  free_filled_chmod_request(local, 0);
 
}

void server_test_chmod(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct chmod_req *input = fill_chmod_request(FALSE);
  struct chmod_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_chmod_exec(req_hd, client_arch);
  req = (struct chmod_req *) req_hd;
  /* I test the content of the request */
  assert(compare_string(req->path, input->path));
  assert(req->mode == input->mode);

  /* The syscall doesn't have write pointers, so I do nothing */

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_chmod_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_chmod_request(input, 0);
 
}
void client_test_chown(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct chown_req *in = fill_chown_request(FALSE);
  struct chown_req *local = fill_chown_request(FALSE);
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_chown_request(&nbytes, &iov_count, in->path, in->owner, in->group);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_chown_response(&resp_hd, &iov_count, &nbytes, in->path, in->owner, in->group);
  assert(resp_iov == NULL); 
  assert(compare_string(local->path, in->path));
  assert(local->owner == in->owner);
  assert(local->group == in->group);

  free_filled_chown_request(in, 0);
  free_filled_chown_request(local, 0);
 
}

void server_test_chown(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct chown_req *input = fill_chown_request(FALSE);
  struct chown_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_chown_exec(req_hd, client_arch);
  req = (struct chown_req *) req_hd;
  /* I test the content of the request */
  assert(compare_string(req->path, input->path));
  assert(req->owner == input->owner);
  assert(req->group == input->group);

  /* The syscall doesn't have write pointers, so I do nothing */

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_chown_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_chown_request(input, 0);
 
}
void client_test_chown32(int fd) {
#ifdef __powerpc__ 
  return NULL;
#elif defined __x86_64__ 
  return NULL;
#else
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct chown32_req *in = fill_chown32_request(FALSE);
  struct chown32_req *local = fill_chown32_request(FALSE);
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_chown32_request(&nbytes, &iov_count, in->path, in->owner, in->group);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_chown32_response(&resp_hd, &iov_count, &nbytes, in->path, in->owner, in->group);
  assert(resp_iov == NULL); 
  assert(compare_string(local->path, in->path));
  assert(local->owner == in->owner);
  assert(local->group == in->group);

  free_filled_chown32_request(in, 0);
  free_filled_chown32_request(local, 0);
#endif
 
}

void server_test_chown32(int fd, enum arch server_arch, enum arch client_arch) {
#ifdef __powerpc__ 
  return NULL;
#elif defined __x86_64__ 
  return NULL;
#else
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct chown32_req *input = fill_chown32_request(FALSE);
  struct chown32_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_chown32_exec(req_hd, client_arch);
  req = (struct chown32_req *) req_hd;
  /* I test the content of the request */
  assert(compare_string(req->path, input->path));
  assert(req->owner == input->owner);
  assert(req->group == input->group);

  /* The syscall doesn't have write pointers, so I do nothing */

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_chown32_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_chown32_request(input, 0);
#endif
 
}
void client_test_clock_getres(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct clock_getres_req *in = fill_clock_getres_request();
  struct clock_getres_req *local = fill_clock_getres_request();
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_clock_getres_request(&nbytes, &iov_count, in->clk_id, in->res);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_clock_getres_response(&resp_hd, &iov_count, &nbytes, in->clk_id, in->res);
  assert(resp_iov != NULL); 
  ret = readv(fd, resp_iov, iov_count);
  assert(ret == nbytes);
  free(resp_iov);
  /* I fill the 'local' request, in this way I can compare this local copy with
   * the remote one 'in' */
  clock_getres_fill_write_pointers(local->clk_id, local->res);
  assert(local->clk_id == in->clk_id);
  assert(compare_struct_timespec(local->res, in->res));

  free_filled_clock_getres_request(in, 0);
  free_filled_clock_getres_request(local, 0);
 
}

void server_test_clock_getres(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct clock_getres_req *input = fill_clock_getres_request();
  struct clock_getres_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_clock_getres_exec(req_hd, client_arch);
  req = (struct clock_getres_req *) req_hd;
  /* I test the content of the request */
  assert(req->clk_id == input->clk_id);

  /* I simulate the execution of the system call, calling
   * a function that fills the write pointer of the request. */
  ret = clock_getres_fill_write_pointers(req->clk_id, req->res);

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_clock_getres_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_clock_getres_request(input, 0);
 
}
void client_test_clock_gettime(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct clock_gettime_req *in = fill_clock_gettime_request();
  struct clock_gettime_req *local = fill_clock_gettime_request();
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_clock_gettime_request(&nbytes, &iov_count, in->clk_id, in->tp);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_clock_gettime_response(&resp_hd, &iov_count, &nbytes, in->clk_id, in->tp);
  assert(resp_iov != NULL); 
  ret = readv(fd, resp_iov, iov_count);
  assert(ret == nbytes);
  free(resp_iov);
  /* I fill the 'local' request, in this way I can compare this local copy with
   * the remote one 'in' */
  clock_gettime_fill_write_pointers(local->clk_id, local->tp);
  assert(local->clk_id == in->clk_id);
  assert(compare_struct_timespec(local->tp, in->tp));

  free_filled_clock_gettime_request(in, 0);
  free_filled_clock_gettime_request(local, 0);
 
}

void server_test_clock_gettime(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct clock_gettime_req *input = fill_clock_gettime_request();
  struct clock_gettime_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_clock_gettime_exec(req_hd, client_arch);
  req = (struct clock_gettime_req *) req_hd;
  /* I test the content of the request */
  assert(req->clk_id == input->clk_id);

  /* I simulate the execution of the system call, calling
   * a function that fills the write pointer of the request. */
  ret = clock_gettime_fill_write_pointers(req->clk_id, req->tp);

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_clock_gettime_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_clock_gettime_request(input, 0);
 
}
void client_test_clock_settime(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct clock_settime_req *in = fill_clock_settime_request(FALSE);
  struct clock_settime_req *local = fill_clock_settime_request(FALSE);
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_clock_settime_request(&nbytes, &iov_count, in->clk_id, in->tp);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_clock_settime_response(&resp_hd, &iov_count, &nbytes, in->clk_id, in->tp);
  assert(resp_iov == NULL); 
  assert(local->clk_id == in->clk_id);
  assert(compare_struct_timespec(local->tp, in->tp));

  free_filled_clock_settime_request(in, 0);
  free_filled_clock_settime_request(local, 0);
 
}

void server_test_clock_settime(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct clock_settime_req *input = fill_clock_settime_request(FALSE);
  struct clock_settime_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_clock_settime_exec(req_hd, client_arch);
  req = (struct clock_settime_req *) req_hd;
  /* I test the content of the request */
  assert(req->clk_id == input->clk_id);
  assert(compare_struct_timespec(req->tp, input->tp));

  /* The syscall doesn't have write pointers, so I do nothing */

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_clock_settime_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_clock_settime_request(input, 0);
 
}
void client_test_close(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct close_req *in = fill_close_request();
  struct close_req *local = fill_close_request();
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_close_request(&nbytes, &iov_count, in->fd);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_close_response(&resp_hd, &iov_count, &nbytes, in->fd);
  assert(resp_iov == NULL); 
  assert(local->fd == in->fd);

  free_filled_close_request(in, 0);
  free_filled_close_request(local, 0);
 
}

void server_test_close(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct close_req *input = fill_close_request();
  struct close_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_close_exec(req_hd, client_arch);
  req = (struct close_req *) req_hd;
  /* I test the content of the request */
  assert(req->fd == input->fd);

  /* The syscall doesn't have write pointers, so I do nothing */

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_close_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_close_request(input, 0);
 
}
void client_test_connect(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct connect_req *in = fill_connect_request(FALSE);
  struct connect_req *local = fill_connect_request(FALSE);
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_connect_request(&nbytes, &iov_count, in->sockfd, in->serv_addr, in->addrlen);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_connect_response(&resp_hd, &iov_count, &nbytes, in->sockfd, in->serv_addr, in->addrlen);
  assert(resp_iov == NULL); 
  assert(local->sockfd == in->sockfd);
  assert(compare_struct_sockaddr(local->serv_addr, in->serv_addr));
  assert(local->addrlen == in->addrlen);

  free_filled_connect_request(in, 0);
  free_filled_connect_request(local, 0);
 
}

void server_test_connect(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct connect_req *input = fill_connect_request(FALSE);
  struct connect_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_connect_exec(req_hd, client_arch);
  req = (struct connect_req *) req_hd;
  /* I test the content of the request */
  assert(req->sockfd == input->sockfd);
  assert(compare_struct_sockaddr(req->serv_addr, input->serv_addr));
  assert(req->addrlen == input->addrlen);

  /* The syscall doesn't have write pointers, so I do nothing */

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_connect_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_connect_request(input, 0);
 
}
void client_test_dup(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct dup_req *in = fill_dup_request();
  struct dup_req *local = fill_dup_request();
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_dup_request(&nbytes, &iov_count, in->oldfd);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_dup_response(&resp_hd, &iov_count, &nbytes, in->oldfd);
  assert(resp_iov == NULL); 
  assert(local->oldfd == in->oldfd);

  free_filled_dup_request(in, 0);
  free_filled_dup_request(local, 0);
 
}

void server_test_dup(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct dup_req *input = fill_dup_request();
  struct dup_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_dup_exec(req_hd, client_arch);
  req = (struct dup_req *) req_hd;
  /* I test the content of the request */
  assert(req->oldfd == input->oldfd);

  /* The syscall doesn't have write pointers, so I do nothing */

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_dup_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_dup_request(input, 0);
 
}
void client_test_dup2(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct dup2_req *in = fill_dup2_request();
  struct dup2_req *local = fill_dup2_request();
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_dup2_request(&nbytes, &iov_count, in->oldfd, in->newfd);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_dup2_response(&resp_hd, &iov_count, &nbytes, in->oldfd, in->newfd);
  assert(resp_iov == NULL); 
  assert(local->oldfd == in->oldfd);
  assert(local->newfd == in->newfd);

  free_filled_dup2_request(in, 0);
  free_filled_dup2_request(local, 0);
 
}

void server_test_dup2(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct dup2_req *input = fill_dup2_request();
  struct dup2_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_dup2_exec(req_hd, client_arch);
  req = (struct dup2_req *) req_hd;
  /* I test the content of the request */
  assert(req->oldfd == input->oldfd);
  assert(req->newfd == input->newfd);

  /* The syscall doesn't have write pointers, so I do nothing */

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_dup2_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_dup2_request(input, 0);
 
}
void client_test_fchdir(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct fchdir_req *in = fill_fchdir_request();
  struct fchdir_req *local = fill_fchdir_request();
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_fchdir_request(&nbytes, &iov_count, in->fd);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_fchdir_response(&resp_hd, &iov_count, &nbytes, in->fd);
  assert(resp_iov == NULL); 
  assert(local->fd == in->fd);

  free_filled_fchdir_request(in, 0);
  free_filled_fchdir_request(local, 0);
 
}

void server_test_fchdir(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct fchdir_req *input = fill_fchdir_request();
  struct fchdir_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_fchdir_exec(req_hd, client_arch);
  req = (struct fchdir_req *) req_hd;
  /* I test the content of the request */
  assert(req->fd == input->fd);

  /* The syscall doesn't have write pointers, so I do nothing */

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_fchdir_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_fchdir_request(input, 0);
 
}
void client_test_fchmod(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct fchmod_req *in = fill_fchmod_request();
  struct fchmod_req *local = fill_fchmod_request();
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_fchmod_request(&nbytes, &iov_count, in->fildes, in->mode);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_fchmod_response(&resp_hd, &iov_count, &nbytes, in->fildes, in->mode);
  assert(resp_iov == NULL); 
  assert(local->fildes == in->fildes);
  assert(local->mode == in->mode);

  free_filled_fchmod_request(in, 0);
  free_filled_fchmod_request(local, 0);
 
}

void server_test_fchmod(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct fchmod_req *input = fill_fchmod_request();
  struct fchmod_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_fchmod_exec(req_hd, client_arch);
  req = (struct fchmod_req *) req_hd;
  /* I test the content of the request */
  assert(req->fildes == input->fildes);
  assert(req->mode == input->mode);

  /* The syscall doesn't have write pointers, so I do nothing */

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_fchmod_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_fchmod_request(input, 0);
 
}
void client_test_fchown(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct fchown_req *in = fill_fchown_request();
  struct fchown_req *local = fill_fchown_request();
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_fchown_request(&nbytes, &iov_count, in->fd, in->owner, in->group);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_fchown_response(&resp_hd, &iov_count, &nbytes, in->fd, in->owner, in->group);
  assert(resp_iov == NULL); 
  assert(local->fd == in->fd);
  assert(local->owner == in->owner);
  assert(local->group == in->group);

  free_filled_fchown_request(in, 0);
  free_filled_fchown_request(local, 0);
 
}

void server_test_fchown(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct fchown_req *input = fill_fchown_request();
  struct fchown_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_fchown_exec(req_hd, client_arch);
  req = (struct fchown_req *) req_hd;
  /* I test the content of the request */
  assert(req->fd == input->fd);
  assert(req->owner == input->owner);
  assert(req->group == input->group);

  /* The syscall doesn't have write pointers, so I do nothing */

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_fchown_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_fchown_request(input, 0);
 
}
void client_test_fchown32(int fd) {
#ifdef __powerpc__ 
  return NULL;
#elif defined __x86_64__ 
  return NULL;
#else
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct fchown32_req *in = fill_fchown32_request();
  struct fchown32_req *local = fill_fchown32_request();
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_fchown32_request(&nbytes, &iov_count, in->fd, in->owner, in->group);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_fchown32_response(&resp_hd, &iov_count, &nbytes, in->fd, in->owner, in->group);
  assert(resp_iov == NULL); 
  assert(local->fd == in->fd);
  assert(local->owner == in->owner);
  assert(local->group == in->group);

  free_filled_fchown32_request(in, 0);
  free_filled_fchown32_request(local, 0);
#endif
 
}

void server_test_fchown32(int fd, enum arch server_arch, enum arch client_arch) {
#ifdef __powerpc__ 
  return NULL;
#elif defined __x86_64__ 
  return NULL;
#else
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct fchown32_req *input = fill_fchown32_request();
  struct fchown32_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_fchown32_exec(req_hd, client_arch);
  req = (struct fchown32_req *) req_hd;
  /* I test the content of the request */
  assert(req->fd == input->fd);
  assert(req->owner == input->owner);
  assert(req->group == input->group);

  /* The syscall doesn't have write pointers, so I do nothing */

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_fchown32_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_fchown32_request(input, 0);
#endif
 
}
void client_test_fdatasync(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct fdatasync_req *in = fill_fdatasync_request();
  struct fdatasync_req *local = fill_fdatasync_request();
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_fdatasync_request(&nbytes, &iov_count, in->fd);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_fdatasync_response(&resp_hd, &iov_count, &nbytes, in->fd);
  assert(resp_iov == NULL); 
  assert(local->fd == in->fd);

  free_filled_fdatasync_request(in, 0);
  free_filled_fdatasync_request(local, 0);
 
}

void server_test_fdatasync(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct fdatasync_req *input = fill_fdatasync_request();
  struct fdatasync_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_fdatasync_exec(req_hd, client_arch);
  req = (struct fdatasync_req *) req_hd;
  /* I test the content of the request */
  assert(req->fd == input->fd);

  /* The syscall doesn't have write pointers, so I do nothing */

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_fdatasync_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_fdatasync_request(input, 0);
 
}
void client_test_fgetxattr(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct fgetxattr_req *in = fill_fgetxattr_request(FALSE);
  struct fgetxattr_req *local = fill_fgetxattr_request(FALSE);
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_fgetxattr_request(&nbytes, &iov_count, in->filedes, in->name, in->value, in->size);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_fgetxattr_response(&resp_hd, &iov_count, &nbytes, in->filedes, in->name, in->value, in->size);
  assert(resp_iov != NULL); 
  ret = readv(fd, resp_iov, iov_count);
  assert(ret == nbytes);
  free(resp_iov);
  /* I fill the 'local' request, in this way I can compare this local copy with
   * the remote one 'in' */
  fgetxattr_fill_write_pointers(local->filedes, local->name, local->value, local->size);
  assert(local->filedes == in->filedes);
  assert(compare_string(local->name, in->name));
  assert(compare_mem(local->value, in->value, in->size));
  assert(local->size == in->size);

  free_filled_fgetxattr_request(in, 0);
  free_filled_fgetxattr_request(local, 0);
 
}

void server_test_fgetxattr(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct fgetxattr_req *input = fill_fgetxattr_request(FALSE);
  struct fgetxattr_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_fgetxattr_exec(req_hd, client_arch);
  req = (struct fgetxattr_req *) req_hd;
  /* I test the content of the request */
  assert(req->filedes == input->filedes);
  assert(compare_string(req->name, input->name));
  assert(req->size == input->size);

  /* I simulate the execution of the system call, calling
   * a function that fills the write pointer of the request. */
  ret = fgetxattr_fill_write_pointers(req->filedes, req->name, req->value, req->size);

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_fgetxattr_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_fgetxattr_request(input, 0);
 
}
void client_test_fstat64(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct fstat64_req *in = fill_fstat64_request();
  struct fstat64_req *local = fill_fstat64_request();
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_fstat64_request(&nbytes, &iov_count, in->filedes, in->buf);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_fstat64_response(&resp_hd, &iov_count, &nbytes, in->filedes, in->buf);
  assert(resp_iov != NULL); 
  ret = readv(fd, resp_iov, iov_count);
  assert(ret == nbytes);
  free(resp_iov);
  /* I fill the 'local' request, in this way I can compare this local copy with
   * the remote one 'in' */
  fstat64_fill_write_pointers(local->filedes, local->buf);
  assert(local->filedes == in->filedes);
  assert(compare_struct_stat64(local->buf, in->buf));

  free_filled_fstat64_request(in, 0);
  free_filled_fstat64_request(local, 0);
 
}

void server_test_fstat64(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct fstat64_req *input = fill_fstat64_request();
  struct fstat64_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_fstat64_exec(req_hd, client_arch);
  req = (struct fstat64_req *) req_hd;
  /* I test the content of the request */
  assert(req->filedes == input->filedes);

  /* I simulate the execution of the system call, calling
   * a function that fills the write pointer of the request. */
  ret = fstat64_fill_write_pointers(req->filedes, req->buf);

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_fstat64_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_fstat64_request(input, 0);
 
}
void client_test_fstatfs64(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct fstatfs64_req *in = fill_fstatfs64_request();
  struct fstatfs64_req *local = fill_fstatfs64_request();
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_fstatfs64_request(&nbytes, &iov_count, in->fd, in->buf);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_fstatfs64_response(&resp_hd, &iov_count, &nbytes, in->fd, in->buf);
  assert(resp_iov != NULL); 
  ret = readv(fd, resp_iov, iov_count);
  assert(ret == nbytes);
  free(resp_iov);
  /* I fill the 'local' request, in this way I can compare this local copy with
   * the remote one 'in' */
  fstatfs64_fill_write_pointers(local->fd, local->buf);
  assert(local->fd == in->fd);
  assert(compare_struct_statfs64(local->buf, in->buf));

  free_filled_fstatfs64_request(in, 0);
  free_filled_fstatfs64_request(local, 0);
 
}

void server_test_fstatfs64(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct fstatfs64_req *input = fill_fstatfs64_request();
  struct fstatfs64_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_fstatfs64_exec(req_hd, client_arch);
  req = (struct fstatfs64_req *) req_hd;
  /* I test the content of the request */
  assert(req->fd == input->fd);

  /* I simulate the execution of the system call, calling
   * a function that fills the write pointer of the request. */
  ret = fstatfs64_fill_write_pointers(req->fd, req->buf);

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_fstatfs64_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_fstatfs64_request(input, 0);
 
}
void client_test_fsync(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct fsync_req *in = fill_fsync_request();
  struct fsync_req *local = fill_fsync_request();
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_fsync_request(&nbytes, &iov_count, in->fd);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_fsync_response(&resp_hd, &iov_count, &nbytes, in->fd);
  assert(resp_iov == NULL); 
  assert(local->fd == in->fd);

  free_filled_fsync_request(in, 0);
  free_filled_fsync_request(local, 0);
 
}

void server_test_fsync(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct fsync_req *input = fill_fsync_request();
  struct fsync_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_fsync_exec(req_hd, client_arch);
  req = (struct fsync_req *) req_hd;
  /* I test the content of the request */
  assert(req->fd == input->fd);

  /* The syscall doesn't have write pointers, so I do nothing */

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_fsync_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_fsync_request(input, 0);
 
}
void client_test_ftruncate64(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct ftruncate64_req *in = fill_ftruncate64_request();
  struct ftruncate64_req *local = fill_ftruncate64_request();
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_ftruncate64_request(&nbytes, &iov_count, in->fd, in->length);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_ftruncate64_response(&resp_hd, &iov_count, &nbytes, in->fd, in->length);
  assert(resp_iov == NULL); 
  assert(local->fd == in->fd);
  assert(local->length == in->length);

  free_filled_ftruncate64_request(in, 0);
  free_filled_ftruncate64_request(local, 0);
 
}

void server_test_ftruncate64(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct ftruncate64_req *input = fill_ftruncate64_request();
  struct ftruncate64_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_ftruncate64_exec(req_hd, client_arch);
  req = (struct ftruncate64_req *) req_hd;
  /* I test the content of the request */
  assert(req->fd == input->fd);
  assert(req->length == input->length);

  /* The syscall doesn't have write pointers, so I do nothing */

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_ftruncate64_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_ftruncate64_request(input, 0);
 
}
void client_test_getdents64(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct getdents64_req *in = fill_getdents64_request();
  struct getdents64_req *local = fill_getdents64_request();
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_getdents64_request(&nbytes, &iov_count, in->fd, in->dirp, in->count);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_getdents64_response(&resp_hd, &iov_count, &nbytes, in->fd, in->dirp, in->count);
  assert(resp_iov != NULL); 
  ret = readv(fd, resp_iov, iov_count);
  assert(ret == nbytes);
  free(resp_iov);
  /* I fill the 'local' request, in this way I can compare this local copy with
   * the remote one 'in' */
  getdents64_fill_write_pointers(local->fd, local->dirp, local->count);
  assert(local->fd == in->fd);
  assert(compare_struct_dirent64(local->dirp, in->dirp));
  assert(local->count == in->count);

  free_filled_getdents64_request(in, 0);
  free_filled_getdents64_request(local, 0);
 
}

void server_test_getdents64(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct getdents64_req *input = fill_getdents64_request();
  struct getdents64_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_getdents64_exec(req_hd, client_arch);
  req = (struct getdents64_req *) req_hd;
  /* I test the content of the request */
  assert(req->fd == input->fd);
  assert(req->count == input->count);

  /* I simulate the execution of the system call, calling
   * a function that fills the write pointer of the request. */
  ret = getdents64_fill_write_pointers(req->fd, req->dirp, req->count);

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_getdents64_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_getdents64_request(input, 0);
 
}
void client_test_getpeername(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct getpeername_req *in = fill_getpeername_request(FALSE);
  struct getpeername_req *local = fill_getpeername_request(FALSE);
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_getpeername_request(&nbytes, &iov_count, in->s, in->name, in->namelen);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_getpeername_response(&resp_hd, &iov_count, &nbytes, in->s, in->name, in->namelen);
  assert(resp_iov != NULL); 
  ret = readv(fd, resp_iov, iov_count);
  assert(ret == nbytes);
  free(resp_iov);
  /* I fill the 'local' request, in this way I can compare this local copy with
   * the remote one 'in' */
  getpeername_fill_write_pointers(local->s, local->name, local->namelen);
  assert(local->s == in->s);
  assert(compare_struct_sockaddr(local->name, in->name));
  assert(compare_socklen_t(local->namelen, in->namelen));

  free_filled_getpeername_request(in, 0);
  free_filled_getpeername_request(local, 0);
 
}

void server_test_getpeername(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct getpeername_req *input = fill_getpeername_request(FALSE);
  struct getpeername_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_getpeername_exec(req_hd, client_arch);
  req = (struct getpeername_req *) req_hd;
  /* I test the content of the request */
  assert(req->s == input->s);

  /* I simulate the execution of the system call, calling
   * a function that fills the write pointer of the request. */
  ret = getpeername_fill_write_pointers(req->s, req->name, req->namelen);

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_getpeername_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_getpeername_request(input, 0);
 
}
void client_test_getsockname(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct getsockname_req *in = fill_getsockname_request(FALSE);
  struct getsockname_req *local = fill_getsockname_request(FALSE);
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_getsockname_request(&nbytes, &iov_count, in->s, in->name, in->namelen);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_getsockname_response(&resp_hd, &iov_count, &nbytes, in->s, in->name, in->namelen);
  assert(resp_iov != NULL); 
  ret = readv(fd, resp_iov, iov_count);
  assert(ret == nbytes);
  free(resp_iov);
  /* I fill the 'local' request, in this way I can compare this local copy with
   * the remote one 'in' */
  getsockname_fill_write_pointers(local->s, local->name, local->namelen);
  assert(local->s == in->s);
  assert(compare_struct_sockaddr(local->name, in->name));
  assert(compare_socklen_t(local->namelen, in->namelen));

  free_filled_getsockname_request(in, 0);
  free_filled_getsockname_request(local, 0);
 
}

void server_test_getsockname(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct getsockname_req *input = fill_getsockname_request(FALSE);
  struct getsockname_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_getsockname_exec(req_hd, client_arch);
  req = (struct getsockname_req *) req_hd;
  /* I test the content of the request */
  assert(req->s == input->s);

  /* I simulate the execution of the system call, calling
   * a function that fills the write pointer of the request. */
  ret = getsockname_fill_write_pointers(req->s, req->name, req->namelen);

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_getsockname_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_getsockname_request(input, 0);
 
}
void client_test_getsockopt(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct getsockopt_req *in = fill_getsockopt_request(FALSE);
  struct getsockopt_req *local = fill_getsockopt_request(FALSE);
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_getsockopt_request(&nbytes, &iov_count, in->s, in->level, in->optname, in->optval, in->optlen);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_getsockopt_response(&resp_hd, &iov_count, &nbytes, in->s, in->level, in->optname, in->optval, in->optlen);
  assert(resp_iov != NULL); 
  ret = readv(fd, resp_iov, iov_count);
  assert(ret == nbytes);
  free(resp_iov);
  /* I fill the 'local' request, in this way I can compare this local copy with
   * the remote one 'in' */
  getsockopt_fill_write_pointers(local->s, local->level, local->optname, local->optval, local->optlen);
  assert(local->s == in->s);
  assert(local->level == in->level);
  assert(local->optname == in->optname);
  assert(compare_mem(local->optval, in->optval, *(in->optlen)));
  assert(compare_socklen_t(local->optlen, in->optlen));

  free_filled_getsockopt_request(in, 0);
  free_filled_getsockopt_request(local, 0);
 
}

void server_test_getsockopt(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct getsockopt_req *input = fill_getsockopt_request(FALSE);
  struct getsockopt_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_getsockopt_exec(req_hd, client_arch);
  req = (struct getsockopt_req *) req_hd;
  /* I test the content of the request */
  assert(req->s == input->s);
  assert(req->level == input->level);
  assert(req->optname == input->optname);

  /* I simulate the execution of the system call, calling
   * a function that fills the write pointer of the request. */
  ret = getsockopt_fill_write_pointers(req->s, req->level, req->optname, req->optval, req->optlen);

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_getsockopt_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_getsockopt_request(input, 0);
 
}
void client_test_gettimeofday(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct gettimeofday_req *in = fill_gettimeofday_request();
  struct gettimeofday_req *local = fill_gettimeofday_request();
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_gettimeofday_request(&nbytes, &iov_count, in->tv, in->tz);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_gettimeofday_response(&resp_hd, &iov_count, &nbytes, in->tv, in->tz);
  assert(resp_iov != NULL); 
  ret = readv(fd, resp_iov, iov_count);
  assert(ret == nbytes);
  free(resp_iov);
  /* I fill the 'local' request, in this way I can compare this local copy with
   * the remote one 'in' */
  gettimeofday_fill_write_pointers(local->tv, local->tz);
  assert(compare_struct_timeval(local->tv, in->tv));
  assert(compare_struct_timezone(local->tz, in->tz));

  free_filled_gettimeofday_request(in, 0);
  free_filled_gettimeofday_request(local, 0);
 
}

void server_test_gettimeofday(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct gettimeofday_req *input = fill_gettimeofday_request();
  struct gettimeofday_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_gettimeofday_exec(req_hd, client_arch);
  req = (struct gettimeofday_req *) req_hd;
  /* I test the content of the request */

  /* I simulate the execution of the system call, calling
   * a function that fills the write pointer of the request. */
  ret = gettimeofday_fill_write_pointers(req->tv, req->tz);

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_gettimeofday_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_gettimeofday_request(input, 0);
 
}
void client_test_getxattr(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct getxattr_req *in = fill_getxattr_request(FALSE, FALSE);
  struct getxattr_req *local = fill_getxattr_request(FALSE, FALSE);
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_getxattr_request(&nbytes, &iov_count, in->path, in->name, in->value, in->size);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_getxattr_response(&resp_hd, &iov_count, &nbytes, in->path, in->name, in->value, in->size);
  assert(resp_iov != NULL); 
  ret = readv(fd, resp_iov, iov_count);
  assert(ret == nbytes);
  free(resp_iov);
  /* I fill the 'local' request, in this way I can compare this local copy with
   * the remote one 'in' */
  getxattr_fill_write_pointers(local->path, local->name, local->value, local->size);
  assert(compare_string(local->path, in->path));
  assert(compare_string(local->name, in->name));
  assert(compare_mem(local->value, in->value, in->size));
  assert(local->size == in->size);

  free_filled_getxattr_request(in, 0);
  free_filled_getxattr_request(local, 0);
 
}

void server_test_getxattr(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct getxattr_req *input = fill_getxattr_request(FALSE, FALSE);
  struct getxattr_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_getxattr_exec(req_hd, client_arch);
  req = (struct getxattr_req *) req_hd;
  /* I test the content of the request */
  assert(compare_string(req->path, input->path));
  assert(compare_string(req->name, input->name));
  assert(req->size == input->size);

  /* I simulate the execution of the system call, calling
   * a function that fills the write pointer of the request. */
  ret = getxattr_fill_write_pointers(req->path, req->name, req->value, req->size);

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_getxattr_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_getxattr_request(input, 0);
 
}
void client_test_lchown(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct lchown_req *in = fill_lchown_request(FALSE);
  struct lchown_req *local = fill_lchown_request(FALSE);
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_lchown_request(&nbytes, &iov_count, in->path, in->owner, in->group);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_lchown_response(&resp_hd, &iov_count, &nbytes, in->path, in->owner, in->group);
  assert(resp_iov == NULL); 
  assert(compare_string(local->path, in->path));
  assert(local->owner == in->owner);
  assert(local->group == in->group);

  free_filled_lchown_request(in, 0);
  free_filled_lchown_request(local, 0);
 
}

void server_test_lchown(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct lchown_req *input = fill_lchown_request(FALSE);
  struct lchown_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_lchown_exec(req_hd, client_arch);
  req = (struct lchown_req *) req_hd;
  /* I test the content of the request */
  assert(compare_string(req->path, input->path));
  assert(req->owner == input->owner);
  assert(req->group == input->group);

  /* The syscall doesn't have write pointers, so I do nothing */

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_lchown_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_lchown_request(input, 0);
 
}
void client_test_lchown32(int fd) {
#ifdef __powerpc__ 
  return NULL;
#elif defined __x86_64__ 
  return NULL;
#else
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct lchown32_req *in = fill_lchown32_request(FALSE);
  struct lchown32_req *local = fill_lchown32_request(FALSE);
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_lchown32_request(&nbytes, &iov_count, in->path, in->owner, in->group);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_lchown32_response(&resp_hd, &iov_count, &nbytes, in->path, in->owner, in->group);
  assert(resp_iov == NULL); 
  assert(compare_string(local->path, in->path));
  assert(local->owner == in->owner);
  assert(local->group == in->group);

  free_filled_lchown32_request(in, 0);
  free_filled_lchown32_request(local, 0);
#endif
 
}

void server_test_lchown32(int fd, enum arch server_arch, enum arch client_arch) {
#ifdef __powerpc__ 
  return NULL;
#elif defined __x86_64__ 
  return NULL;
#else
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct lchown32_req *input = fill_lchown32_request(FALSE);
  struct lchown32_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_lchown32_exec(req_hd, client_arch);
  req = (struct lchown32_req *) req_hd;
  /* I test the content of the request */
  assert(compare_string(req->path, input->path));
  assert(req->owner == input->owner);
  assert(req->group == input->group);

  /* The syscall doesn't have write pointers, so I do nothing */

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_lchown32_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_lchown32_request(input, 0);
#endif
 
}
void client_test_lgetxattr(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct lgetxattr_req *in = fill_lgetxattr_request(FALSE, FALSE);
  struct lgetxattr_req *local = fill_lgetxattr_request(FALSE, FALSE);
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_lgetxattr_request(&nbytes, &iov_count, in->path, in->name, in->value, in->size);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_lgetxattr_response(&resp_hd, &iov_count, &nbytes, in->path, in->name, in->value, in->size);
  assert(resp_iov != NULL); 
  ret = readv(fd, resp_iov, iov_count);
  assert(ret == nbytes);
  free(resp_iov);
  /* I fill the 'local' request, in this way I can compare this local copy with
   * the remote one 'in' */
  lgetxattr_fill_write_pointers(local->path, local->name, local->value, local->size);
  assert(compare_string(local->path, in->path));
  assert(compare_string(local->name, in->name));
  assert(compare_mem(local->value, in->value, in->size));
  assert(local->size == in->size);

  free_filled_lgetxattr_request(in, 0);
  free_filled_lgetxattr_request(local, 0);
 
}

void server_test_lgetxattr(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct lgetxattr_req *input = fill_lgetxattr_request(FALSE, FALSE);
  struct lgetxattr_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_lgetxattr_exec(req_hd, client_arch);
  req = (struct lgetxattr_req *) req_hd;
  /* I test the content of the request */
  assert(compare_string(req->path, input->path));
  assert(compare_string(req->name, input->name));
  assert(req->size == input->size);

  /* I simulate the execution of the system call, calling
   * a function that fills the write pointer of the request. */
  ret = lgetxattr_fill_write_pointers(req->path, req->name, req->value, req->size);

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_lgetxattr_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_lgetxattr_request(input, 0);
 
}
void client_test_link(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct link_req *in = fill_link_request(FALSE, FALSE);
  struct link_req *local = fill_link_request(FALSE, FALSE);
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_link_request(&nbytes, &iov_count, in->oldpath, in->newpath);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_link_response(&resp_hd, &iov_count, &nbytes, in->oldpath, in->newpath);
  assert(resp_iov == NULL); 
  assert(compare_string(local->oldpath, in->oldpath));
  assert(compare_string(local->newpath, in->newpath));

  free_filled_link_request(in, 0);
  free_filled_link_request(local, 0);
 
}

void server_test_link(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct link_req *input = fill_link_request(FALSE, FALSE);
  struct link_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_link_exec(req_hd, client_arch);
  req = (struct link_req *) req_hd;
  /* I test the content of the request */
  assert(compare_string(req->oldpath, input->oldpath));
  assert(compare_string(req->newpath, input->newpath));

  /* The syscall doesn't have write pointers, so I do nothing */

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_link_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_link_request(input, 0);
 
}
void client_test_listen(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct listen_req *in = fill_listen_request();
  struct listen_req *local = fill_listen_request();
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_listen_request(&nbytes, &iov_count, in->sockfd, in->backlog);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_listen_response(&resp_hd, &iov_count, &nbytes, in->sockfd, in->backlog);
  assert(resp_iov == NULL); 
  assert(local->sockfd == in->sockfd);
  assert(local->backlog == in->backlog);

  free_filled_listen_request(in, 0);
  free_filled_listen_request(local, 0);
 
}

void server_test_listen(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct listen_req *input = fill_listen_request();
  struct listen_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_listen_exec(req_hd, client_arch);
  req = (struct listen_req *) req_hd;
  /* I test the content of the request */
  assert(req->sockfd == input->sockfd);
  assert(req->backlog == input->backlog);

  /* The syscall doesn't have write pointers, so I do nothing */

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_listen_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_listen_request(input, 0);
 
}
void client_test_lseek(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct lseek_req *in = fill_lseek_request();
  struct lseek_req *local = fill_lseek_request();
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_lseek_request(&nbytes, &iov_count, in->fildes, in->offset, in->whence);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_lseek_response(&resp_hd, &iov_count, &nbytes, in->fildes, in->offset, in->whence);
  assert(resp_iov == NULL); 
  assert(local->fildes == in->fildes);
  assert(local->offset == in->offset);
  assert(local->whence == in->whence);

  free_filled_lseek_request(in, 0);
  free_filled_lseek_request(local, 0);
 
}

void server_test_lseek(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct lseek_req *input = fill_lseek_request();
  struct lseek_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_lseek_exec(req_hd, client_arch);
  req = (struct lseek_req *) req_hd;
  /* I test the content of the request */
  assert(req->fildes == input->fildes);
  assert(req->offset == input->offset);
  assert(req->whence == input->whence);

  /* The syscall doesn't have write pointers, so I do nothing */

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_lseek_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_lseek_request(input, 0);
 
}
void client_test_lstat64(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct lstat64_req *in = fill_lstat64_request(FALSE);
  struct lstat64_req *local = fill_lstat64_request(FALSE);
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_lstat64_request(&nbytes, &iov_count, in->path, in->buf);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_lstat64_response(&resp_hd, &iov_count, &nbytes, in->path, in->buf);
  assert(resp_iov != NULL); 
  ret = readv(fd, resp_iov, iov_count);
  assert(ret == nbytes);
  free(resp_iov);
  /* I fill the 'local' request, in this way I can compare this local copy with
   * the remote one 'in' */
  lstat64_fill_write_pointers(local->path, local->buf);
  assert(compare_string(local->path, in->path));
  assert(compare_struct_stat64(local->buf, in->buf));

  free_filled_lstat64_request(in, 0);
  free_filled_lstat64_request(local, 0);
 
}

void server_test_lstat64(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct lstat64_req *input = fill_lstat64_request(FALSE);
  struct lstat64_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_lstat64_exec(req_hd, client_arch);
  req = (struct lstat64_req *) req_hd;
  /* I test the content of the request */
  assert(compare_string(req->path, input->path));

  /* I simulate the execution of the system call, calling
   * a function that fills the write pointer of the request. */
  ret = lstat64_fill_write_pointers(req->path, req->buf);

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_lstat64_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_lstat64_request(input, 0);
 
}
void client_test_mkdir(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct mkdir_req *in = fill_mkdir_request(FALSE);
  struct mkdir_req *local = fill_mkdir_request(FALSE);
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_mkdir_request(&nbytes, &iov_count, in->pathname, in->mode);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_mkdir_response(&resp_hd, &iov_count, &nbytes, in->pathname, in->mode);
  assert(resp_iov == NULL); 
  assert(compare_string(local->pathname, in->pathname));
  assert(local->mode == in->mode);

  free_filled_mkdir_request(in, 0);
  free_filled_mkdir_request(local, 0);
 
}

void server_test_mkdir(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct mkdir_req *input = fill_mkdir_request(FALSE);
  struct mkdir_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_mkdir_exec(req_hd, client_arch);
  req = (struct mkdir_req *) req_hd;
  /* I test the content of the request */
  assert(compare_string(req->pathname, input->pathname));
  assert(req->mode == input->mode);

  /* The syscall doesn't have write pointers, so I do nothing */

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_mkdir_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_mkdir_request(input, 0);
 
}
void client_test_mount(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct mount_req *in = fill_mount_request(FALSE, FALSE, FALSE, FALSE);
  struct mount_req *local = fill_mount_request(FALSE, FALSE, FALSE, FALSE);
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_mount_request(&nbytes, &iov_count, in->source, in->target, in->filesystemtype, in->mountflags, in->data);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_mount_response(&resp_hd, &iov_count, &nbytes, in->source, in->target, in->filesystemtype, in->mountflags, in->data);
  assert(resp_iov == NULL); 
  assert(compare_string(local->source, in->source));
  assert(compare_string(local->target, in->target));
  assert(compare_string(local->filesystemtype, in->filesystemtype));
  assert(local->mountflags == in->mountflags);
  assert(compare_mem(local->data, in->data, (strlen(in->data) + 1)));

  free_filled_mount_request(in, 0);
  free_filled_mount_request(local, 0);
 
}

void server_test_mount(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct mount_req *input = fill_mount_request(FALSE, FALSE, FALSE, FALSE);
  struct mount_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_mount_exec(req_hd, client_arch);
  req = (struct mount_req *) req_hd;
  /* I test the content of the request */
  assert(compare_string(req->source, input->source));
  assert(compare_string(req->target, input->target));
  assert(compare_string(req->filesystemtype, input->filesystemtype));
  assert(req->mountflags == input->mountflags);
  assert(compare_mem(req->data, input->data, (strlen(input->data) + 1)));

  /* The syscall doesn't have write pointers, so I do nothing */

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_mount_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_mount_request(input, 0);
 
}
void client_test_open(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct open_req *in = fill_open_request(FALSE);
  struct open_req *local = fill_open_request(FALSE);
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_open_request(&nbytes, &iov_count, in->pathname, in->flags);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_open_response(&resp_hd, &iov_count, &nbytes, in->pathname, in->flags);
  assert(resp_iov == NULL); 
  assert(compare_string(local->pathname, in->pathname));
  assert(local->flags == in->flags);

  free_filled_open_request(in, 0);
  free_filled_open_request(local, 0);
 
}

void server_test_open(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct open_req *input = fill_open_request(FALSE);
  struct open_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_open_exec(req_hd, client_arch);
  req = (struct open_req *) req_hd;
  /* I test the content of the request */
  assert(compare_string(req->pathname, input->pathname));
  assert(req->flags == input->flags);

  /* The syscall doesn't have write pointers, so I do nothing */

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_open_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_open_request(input, 0);
 
}
void client_test_pread64(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct pread64_req *in = fill_pread64_request();
  struct pread64_req *local = fill_pread64_request();
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_pread64_request(&nbytes, &iov_count, in->fd, in->buf, in->count, in->offset);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_pread64_response(&resp_hd, &iov_count, &nbytes, in->fd, in->buf, in->count, in->offset);
  assert(resp_iov != NULL); 
  ret = readv(fd, resp_iov, iov_count);
  assert(ret == nbytes);
  free(resp_iov);
  /* I fill the 'local' request, in this way I can compare this local copy with
   * the remote one 'in' */
  pread64_fill_write_pointers(local->fd, local->buf, local->count, local->offset);
  assert(local->fd == in->fd);
  assert(compare_mem(local->buf, in->buf, in->count));
  assert(local->count == in->count);
  assert(local->offset == in->offset);

  free_filled_pread64_request(in, 0);
  free_filled_pread64_request(local, 0);
 
}

void server_test_pread64(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct pread64_req *input = fill_pread64_request();
  struct pread64_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_pread64_exec(req_hd, client_arch);
  req = (struct pread64_req *) req_hd;
  /* I test the content of the request */
  assert(req->fd == input->fd);
  assert(req->count == input->count);
  assert(req->offset == input->offset);

  /* I simulate the execution of the system call, calling
   * a function that fills the write pointer of the request. */
  ret = pread64_fill_write_pointers(req->fd, req->buf, req->count, req->offset);

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_pread64_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_pread64_request(input, 0);
 
}
void client_test_pwrite64(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct pwrite64_req *in = fill_pwrite64_request(FALSE);
  struct pwrite64_req *local = fill_pwrite64_request(FALSE);
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_pwrite64_request(&nbytes, &iov_count, in->fd, in->buf, in->count, in->offset);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_pwrite64_response(&resp_hd, &iov_count, &nbytes, in->fd, in->buf, in->count, in->offset);
  assert(resp_iov == NULL); 
  assert(local->fd == in->fd);
  assert(compare_mem(local->buf, in->buf, in->count));
  assert(local->count == in->count);
  assert(local->offset == in->offset);

  free_filled_pwrite64_request(in, 0);
  free_filled_pwrite64_request(local, 0);
 
}

void server_test_pwrite64(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct pwrite64_req *input = fill_pwrite64_request(FALSE);
  struct pwrite64_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_pwrite64_exec(req_hd, client_arch);
  req = (struct pwrite64_req *) req_hd;
  /* I test the content of the request */
  assert(req->fd == input->fd);
  assert(compare_mem(req->buf, input->buf, input->count));
  assert(req->count == input->count);
  assert(req->offset == input->offset);

  /* The syscall doesn't have write pointers, so I do nothing */

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_pwrite64_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_pwrite64_request(input, 0);
 
}
void client_test_read(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct read_req *in = fill_read_request();
  struct read_req *local = fill_read_request();
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_read_request(&nbytes, &iov_count, in->fd, in->buf, in->count);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_read_response(&resp_hd, &iov_count, &nbytes, in->fd, in->buf, in->count);
  assert(resp_iov != NULL); 
  ret = readv(fd, resp_iov, iov_count);
  assert(ret == nbytes);
  free(resp_iov);
  /* I fill the 'local' request, in this way I can compare this local copy with
   * the remote one 'in' */
  read_fill_write_pointers(local->fd, local->buf, local->count);
  assert(local->fd == in->fd);
  assert(compare_mem(local->buf, in->buf, in->count));
  assert(local->count == in->count);

  free_filled_read_request(in, 0);
  free_filled_read_request(local, 0);
 
}

void server_test_read(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct read_req *input = fill_read_request();
  struct read_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_read_exec(req_hd, client_arch);
  req = (struct read_req *) req_hd;
  /* I test the content of the request */
  assert(req->fd == input->fd);
  assert(req->count == input->count);

  /* I simulate the execution of the system call, calling
   * a function that fills the write pointer of the request. */
  ret = read_fill_write_pointers(req->fd, req->buf, req->count);

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_read_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_read_request(input, 0);
 
}
void client_test_readlink(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct readlink_req *in = fill_readlink_request(FALSE);
  struct readlink_req *local = fill_readlink_request(FALSE);
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_readlink_request(&nbytes, &iov_count, in->path, in->buf, in->bufsiz);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_readlink_response(&resp_hd, &iov_count, &nbytes, in->path, in->buf, in->bufsiz);
  assert(resp_iov != NULL); 
  ret = readv(fd, resp_iov, iov_count);
  assert(ret == nbytes);
  free(resp_iov);
  /* I fill the 'local' request, in this way I can compare this local copy with
   * the remote one 'in' */
  readlink_fill_write_pointers(local->path, local->buf, local->bufsiz);
  assert(compare_string(local->path, in->path));
  assert(compare_string(local->buf, in->buf));
  assert(local->bufsiz == in->bufsiz);

  free_filled_readlink_request(in, 0);
  free_filled_readlink_request(local, 0);
 
}

void server_test_readlink(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct readlink_req *input = fill_readlink_request(FALSE);
  struct readlink_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_readlink_exec(req_hd, client_arch);
  req = (struct readlink_req *) req_hd;
  /* I test the content of the request */
  assert(compare_string(req->path, input->path));
  assert(req->bufsiz == input->bufsiz);

  /* I simulate the execution of the system call, calling
   * a function that fills the write pointer of the request. */
  ret = readlink_fill_write_pointers(req->path, req->buf, req->bufsiz);

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_readlink_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_readlink_request(input, 0);
 
}
void client_test_recv(int fd) {
#ifdef __x86_64__ 
  return NULL;
#else
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct recv_req *in = fill_recv_request();
  struct recv_req *local = fill_recv_request();
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_recv_request(&nbytes, &iov_count, in->s, in->buf, in->len, in->flags);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_recv_response(&resp_hd, &iov_count, &nbytes, in->s, in->buf, in->len, in->flags);
  assert(resp_iov != NULL); 
  ret = readv(fd, resp_iov, iov_count);
  assert(ret == nbytes);
  free(resp_iov);
  /* I fill the 'local' request, in this way I can compare this local copy with
   * the remote one 'in' */
  recv_fill_write_pointers(local->s, local->buf, local->len, local->flags);
  assert(local->s == in->s);
  assert(compare_mem(local->buf, in->buf, in->len));
  assert(local->len == in->len);
  assert(local->flags == in->flags);

  free_filled_recv_request(in, 0);
  free_filled_recv_request(local, 0);
#endif
 
}

void server_test_recv(int fd, enum arch server_arch, enum arch client_arch) {
#ifdef __x86_64__ 
  return NULL;
#else
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct recv_req *input = fill_recv_request();
  struct recv_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_recv_exec(req_hd, client_arch);
  req = (struct recv_req *) req_hd;
  /* I test the content of the request */
  assert(req->s == input->s);
  assert(req->len == input->len);
  assert(req->flags == input->flags);

  /* I simulate the execution of the system call, calling
   * a function that fills the write pointer of the request. */
  ret = recv_fill_write_pointers(req->s, req->buf, req->len, req->flags);

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_recv_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_recv_request(input, 0);
#endif
 
}
void client_test_recvfrom(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct recvfrom_req *in = fill_recvfrom_request(FALSE, FALSE);
  struct recvfrom_req *local = fill_recvfrom_request(FALSE, FALSE);
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_recvfrom_request(&nbytes, &iov_count, in->s, in->buf, in->len, in->flags, in->from, in->fromlen);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_recvfrom_response(&resp_hd, &iov_count, &nbytes, in->s, in->buf, in->len, in->flags, in->from, in->fromlen);
  assert(resp_iov != NULL); 
  ret = readv(fd, resp_iov, iov_count);
  assert(ret == nbytes);
  free(resp_iov);
  /* I fill the 'local' request, in this way I can compare this local copy with
   * the remote one 'in' */
  recvfrom_fill_write_pointers(local->s, local->buf, local->len, local->flags, local->from, local->fromlen);
  assert(local->s == in->s);
  assert(compare_mem(local->buf, in->buf, in->len));
  assert(local->len == in->len);
  assert(local->flags == in->flags);
  assert(compare_struct_sockaddr(local->from, in->from));
  assert(compare_socklen_t(local->fromlen, in->fromlen));

  free_filled_recvfrom_request(in, 0);
  free_filled_recvfrom_request(local, 0);
 
}

void server_test_recvfrom(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct recvfrom_req *input = fill_recvfrom_request(FALSE, FALSE);
  struct recvfrom_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_recvfrom_exec(req_hd, client_arch);
  req = (struct recvfrom_req *) req_hd;
  /* I test the content of the request */
  assert(req->s == input->s);
  assert(req->len == input->len);
  assert(req->flags == input->flags);
  assert(compare_struct_sockaddr(req->from, input->from));

  /* I simulate the execution of the system call, calling
   * a function that fills the write pointer of the request. */
  ret = recvfrom_fill_write_pointers(req->s, req->buf, req->len, req->flags, req->from, req->fromlen);

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_recvfrom_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_recvfrom_request(input, 0);
 
}
void client_test_rename(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct rename_req *in = fill_rename_request(FALSE, FALSE);
  struct rename_req *local = fill_rename_request(FALSE, FALSE);
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_rename_request(&nbytes, &iov_count, in->oldpath, in->newpath);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_rename_response(&resp_hd, &iov_count, &nbytes, in->oldpath, in->newpath);
  assert(resp_iov == NULL); 
  assert(compare_string(local->oldpath, in->oldpath));
  assert(compare_string(local->newpath, in->newpath));

  free_filled_rename_request(in, 0);
  free_filled_rename_request(local, 0);
 
}

void server_test_rename(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct rename_req *input = fill_rename_request(FALSE, FALSE);
  struct rename_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_rename_exec(req_hd, client_arch);
  req = (struct rename_req *) req_hd;
  /* I test the content of the request */
  assert(compare_string(req->oldpath, input->oldpath));
  assert(compare_string(req->newpath, input->newpath));

  /* The syscall doesn't have write pointers, so I do nothing */

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_rename_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_rename_request(input, 0);
 
}
void client_test_rmdir(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct rmdir_req *in = fill_rmdir_request(FALSE);
  struct rmdir_req *local = fill_rmdir_request(FALSE);
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_rmdir_request(&nbytes, &iov_count, in->pathname);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_rmdir_response(&resp_hd, &iov_count, &nbytes, in->pathname);
  assert(resp_iov == NULL); 
  assert(compare_string(local->pathname, in->pathname));

  free_filled_rmdir_request(in, 0);
  free_filled_rmdir_request(local, 0);
 
}

void server_test_rmdir(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct rmdir_req *input = fill_rmdir_request(FALSE);
  struct rmdir_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_rmdir_exec(req_hd, client_arch);
  req = (struct rmdir_req *) req_hd;
  /* I test the content of the request */
  assert(compare_string(req->pathname, input->pathname));

  /* The syscall doesn't have write pointers, so I do nothing */

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_rmdir_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_rmdir_request(input, 0);
 
}
void client_test_send(int fd) {
#ifdef __x86_64__ 
  return NULL;
#else
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct send_req *in = fill_send_request(FALSE);
  struct send_req *local = fill_send_request(FALSE);
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_send_request(&nbytes, &iov_count, in->s, in->buf, in->len, in->flags);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_send_response(&resp_hd, &iov_count, &nbytes, in->s, in->buf, in->len, in->flags);
  assert(resp_iov == NULL); 
  assert(local->s == in->s);
  assert(compare_mem(local->buf, in->buf, in->len));
  assert(local->len == in->len);
  assert(local->flags == in->flags);

  free_filled_send_request(in, 0);
  free_filled_send_request(local, 0);
#endif
 
}

void server_test_send(int fd, enum arch server_arch, enum arch client_arch) {
#ifdef __x86_64__ 
  return NULL;
#else
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct send_req *input = fill_send_request(FALSE);
  struct send_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_send_exec(req_hd, client_arch);
  req = (struct send_req *) req_hd;
  /* I test the content of the request */
  assert(req->s == input->s);
  assert(compare_mem(req->buf, input->buf, input->len));
  assert(req->len == input->len);
  assert(req->flags == input->flags);

  /* The syscall doesn't have write pointers, so I do nothing */

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_send_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_send_request(input, 0);
#endif
 
}
void client_test_sendto(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct sendto_req *in = fill_sendto_request(FALSE, FALSE);
  struct sendto_req *local = fill_sendto_request(FALSE, FALSE);
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_sendto_request(&nbytes, &iov_count, in->s, in->buf, in->len, in->flags, in->to, in->tolen);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_sendto_response(&resp_hd, &iov_count, &nbytes, in->s, in->buf, in->len, in->flags, in->to, in->tolen);
  assert(resp_iov == NULL); 
  assert(local->s == in->s);
  assert(compare_mem(local->buf, in->buf, in->len));
  assert(local->len == in->len);
  assert(local->flags == in->flags);
  assert(compare_struct_sockaddr(local->to, in->to));
  assert(local->tolen == in->tolen);

  free_filled_sendto_request(in, 0);
  free_filled_sendto_request(local, 0);
 
}

void server_test_sendto(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct sendto_req *input = fill_sendto_request(FALSE, FALSE);
  struct sendto_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_sendto_exec(req_hd, client_arch);
  req = (struct sendto_req *) req_hd;
  /* I test the content of the request */
  assert(req->s == input->s);
  assert(compare_mem(req->buf, input->buf, input->len));
  assert(req->len == input->len);
  assert(req->flags == input->flags);
  assert(compare_struct_sockaddr(req->to, input->to));
  assert(req->tolen == input->tolen);

  /* The syscall doesn't have write pointers, so I do nothing */

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_sendto_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_sendto_request(input, 0);
 
}
void client_test_setdomainname(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct setdomainname_req *in = fill_setdomainname_request(FALSE);
  struct setdomainname_req *local = fill_setdomainname_request(FALSE);
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_setdomainname_request(&nbytes, &iov_count, in->name, in->len);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_setdomainname_response(&resp_hd, &iov_count, &nbytes, in->name, in->len);
  assert(resp_iov == NULL); 
  assert(compare_string(local->name, in->name));
  assert(local->len == in->len);

  free_filled_setdomainname_request(in, 0);
  free_filled_setdomainname_request(local, 0);
 
}

void server_test_setdomainname(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct setdomainname_req *input = fill_setdomainname_request(FALSE);
  struct setdomainname_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_setdomainname_exec(req_hd, client_arch);
  req = (struct setdomainname_req *) req_hd;
  /* I test the content of the request */
  assert(compare_string(req->name, input->name));
  assert(req->len == input->len);

  /* The syscall doesn't have write pointers, so I do nothing */

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_setdomainname_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_setdomainname_request(input, 0);
 
}
void client_test_sethostname(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct sethostname_req *in = fill_sethostname_request(FALSE);
  struct sethostname_req *local = fill_sethostname_request(FALSE);
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_sethostname_request(&nbytes, &iov_count, in->name, in->len);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_sethostname_response(&resp_hd, &iov_count, &nbytes, in->name, in->len);
  assert(resp_iov == NULL); 
  assert(compare_string(local->name, in->name));
  assert(local->len == in->len);

  free_filled_sethostname_request(in, 0);
  free_filled_sethostname_request(local, 0);
 
}

void server_test_sethostname(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct sethostname_req *input = fill_sethostname_request(FALSE);
  struct sethostname_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_sethostname_exec(req_hd, client_arch);
  req = (struct sethostname_req *) req_hd;
  /* I test the content of the request */
  assert(compare_string(req->name, input->name));
  assert(req->len == input->len);

  /* The syscall doesn't have write pointers, so I do nothing */

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_sethostname_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_sethostname_request(input, 0);
 
}
void client_test_setsockopt(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct setsockopt_req *in = fill_setsockopt_request(FALSE);
  struct setsockopt_req *local = fill_setsockopt_request(FALSE);
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_setsockopt_request(&nbytes, &iov_count, in->s, in->level, in->optname, in->optval, in->optlen);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_setsockopt_response(&resp_hd, &iov_count, &nbytes, in->s, in->level, in->optname, in->optval, in->optlen);
  assert(resp_iov == NULL); 
  assert(local->s == in->s);
  assert(local->level == in->level);
  assert(local->optname == in->optname);
  assert(compare_mem(local->optval, in->optval, in->optlen));
  assert(local->optlen == in->optlen);

  free_filled_setsockopt_request(in, 0);
  free_filled_setsockopt_request(local, 0);
 
}

void server_test_setsockopt(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct setsockopt_req *input = fill_setsockopt_request(FALSE);
  struct setsockopt_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_setsockopt_exec(req_hd, client_arch);
  req = (struct setsockopt_req *) req_hd;
  /* I test the content of the request */
  assert(req->s == input->s);
  assert(req->level == input->level);
  assert(req->optname == input->optname);
  assert(compare_mem(req->optval, input->optval, input->optlen));
  assert(req->optlen == input->optlen);

  /* The syscall doesn't have write pointers, so I do nothing */

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_setsockopt_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_setsockopt_request(input, 0);
 
}
void client_test_settimeofday(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct settimeofday_req *in = fill_settimeofday_request(FALSE, FALSE);
  struct settimeofday_req *local = fill_settimeofday_request(FALSE, FALSE);
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_settimeofday_request(&nbytes, &iov_count, in->tv, in->tz);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_settimeofday_response(&resp_hd, &iov_count, &nbytes, in->tv, in->tz);
  assert(resp_iov == NULL); 
  assert(compare_struct_timeval(local->tv, in->tv));
  assert(compare_struct_timezone(local->tz, in->tz));

  free_filled_settimeofday_request(in, 0);
  free_filled_settimeofday_request(local, 0);
 
}

void server_test_settimeofday(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct settimeofday_req *input = fill_settimeofday_request(FALSE, FALSE);
  struct settimeofday_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_settimeofday_exec(req_hd, client_arch);
  req = (struct settimeofday_req *) req_hd;
  /* I test the content of the request */
  assert(compare_struct_timeval(req->tv, input->tv));
  assert(compare_struct_timezone(req->tz, input->tz));

  /* The syscall doesn't have write pointers, so I do nothing */

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_settimeofday_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_settimeofday_request(input, 0);
 
}
void client_test_shutdown(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct shutdown_req *in = fill_shutdown_request();
  struct shutdown_req *local = fill_shutdown_request();
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_shutdown_request(&nbytes, &iov_count, in->s, in->how);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_shutdown_response(&resp_hd, &iov_count, &nbytes, in->s, in->how);
  assert(resp_iov == NULL); 
  assert(local->s == in->s);
  assert(local->how == in->how);

  free_filled_shutdown_request(in, 0);
  free_filled_shutdown_request(local, 0);
 
}

void server_test_shutdown(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct shutdown_req *input = fill_shutdown_request();
  struct shutdown_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_shutdown_exec(req_hd, client_arch);
  req = (struct shutdown_req *) req_hd;
  /* I test the content of the request */
  assert(req->s == input->s);
  assert(req->how == input->how);

  /* The syscall doesn't have write pointers, so I do nothing */

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_shutdown_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_shutdown_request(input, 0);
 
}
void client_test_socket(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct socket_req *in = fill_socket_request();
  struct socket_req *local = fill_socket_request();
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_socket_request(&nbytes, &iov_count, in->domain, in->type, in->protocol);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_socket_response(&resp_hd, &iov_count, &nbytes, in->domain, in->type, in->protocol);
  assert(resp_iov == NULL); 
  assert(local->domain == in->domain);
  assert(local->type == in->type);
  assert(local->protocol == in->protocol);

  free_filled_socket_request(in, 0);
  free_filled_socket_request(local, 0);
 
}

void server_test_socket(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct socket_req *input = fill_socket_request();
  struct socket_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_socket_exec(req_hd, client_arch);
  req = (struct socket_req *) req_hd;
  /* I test the content of the request */
  assert(req->domain == input->domain);
  assert(req->type == input->type);
  assert(req->protocol == input->protocol);

  /* The syscall doesn't have write pointers, so I do nothing */

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_socket_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_socket_request(input, 0);
 
}
void client_test_stat64(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct stat64_req *in = fill_stat64_request(FALSE);
  struct stat64_req *local = fill_stat64_request(FALSE);
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_stat64_request(&nbytes, &iov_count, in->path, in->buf);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_stat64_response(&resp_hd, &iov_count, &nbytes, in->path, in->buf);
  assert(resp_iov != NULL); 
  ret = readv(fd, resp_iov, iov_count);
  assert(ret == nbytes);
  free(resp_iov);
  /* I fill the 'local' request, in this way I can compare this local copy with
   * the remote one 'in' */
  stat64_fill_write_pointers(local->path, local->buf);
  assert(compare_string(local->path, in->path));
  assert(compare_struct_stat64(local->buf, in->buf));

  free_filled_stat64_request(in, 0);
  free_filled_stat64_request(local, 0);
 
}

void server_test_stat64(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct stat64_req *input = fill_stat64_request(FALSE);
  struct stat64_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_stat64_exec(req_hd, client_arch);
  req = (struct stat64_req *) req_hd;
  /* I test the content of the request */
  assert(compare_string(req->path, input->path));

  /* I simulate the execution of the system call, calling
   * a function that fills the write pointer of the request. */
  ret = stat64_fill_write_pointers(req->path, req->buf);

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_stat64_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_stat64_request(input, 0);
 
}
void client_test_statfs64(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct statfs64_req *in = fill_statfs64_request(FALSE);
  struct statfs64_req *local = fill_statfs64_request(FALSE);
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_statfs64_request(&nbytes, &iov_count, in->path, in->buf);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_statfs64_response(&resp_hd, &iov_count, &nbytes, in->path, in->buf);
  assert(resp_iov != NULL); 
  ret = readv(fd, resp_iov, iov_count);
  assert(ret == nbytes);
  free(resp_iov);
  /* I fill the 'local' request, in this way I can compare this local copy with
   * the remote one 'in' */
  statfs64_fill_write_pointers(local->path, local->buf);
  assert(compare_string(local->path, in->path));
  assert(compare_struct_statfs64(local->buf, in->buf));

  free_filled_statfs64_request(in, 0);
  free_filled_statfs64_request(local, 0);
 
}

void server_test_statfs64(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct statfs64_req *input = fill_statfs64_request(FALSE);
  struct statfs64_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_statfs64_exec(req_hd, client_arch);
  req = (struct statfs64_req *) req_hd;
  /* I test the content of the request */
  assert(compare_string(req->path, input->path));

  /* I simulate the execution of the system call, calling
   * a function that fills the write pointer of the request. */
  ret = statfs64_fill_write_pointers(req->path, req->buf);

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_statfs64_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_statfs64_request(input, 0);
 
}
void client_test_symlink(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct symlink_req *in = fill_symlink_request(FALSE, FALSE);
  struct symlink_req *local = fill_symlink_request(FALSE, FALSE);
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_symlink_request(&nbytes, &iov_count, in->oldpath, in->newpath);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_symlink_response(&resp_hd, &iov_count, &nbytes, in->oldpath, in->newpath);
  assert(resp_iov == NULL); 
  assert(compare_string(local->oldpath, in->oldpath));
  assert(compare_string(local->newpath, in->newpath));

  free_filled_symlink_request(in, 0);
  free_filled_symlink_request(local, 0);
 
}

void server_test_symlink(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct symlink_req *input = fill_symlink_request(FALSE, FALSE);
  struct symlink_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_symlink_exec(req_hd, client_arch);
  req = (struct symlink_req *) req_hd;
  /* I test the content of the request */
  assert(compare_string(req->oldpath, input->oldpath));
  assert(compare_string(req->newpath, input->newpath));

  /* The syscall doesn't have write pointers, so I do nothing */

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_symlink_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_symlink_request(input, 0);
 
}
void client_test_truncate64(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct truncate64_req *in = fill_truncate64_request(FALSE);
  struct truncate64_req *local = fill_truncate64_request(FALSE);
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_truncate64_request(&nbytes, &iov_count, in->path, in->length);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_truncate64_response(&resp_hd, &iov_count, &nbytes, in->path, in->length);
  assert(resp_iov == NULL); 
  assert(compare_string(local->path, in->path));
  assert(local->length == in->length);

  free_filled_truncate64_request(in, 0);
  free_filled_truncate64_request(local, 0);
 
}

void server_test_truncate64(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct truncate64_req *input = fill_truncate64_request(FALSE);
  struct truncate64_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_truncate64_exec(req_hd, client_arch);
  req = (struct truncate64_req *) req_hd;
  /* I test the content of the request */
  assert(compare_string(req->path, input->path));
  assert(req->length == input->length);

  /* The syscall doesn't have write pointers, so I do nothing */

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_truncate64_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_truncate64_request(input, 0);
 
}
void client_test_umount2(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct umount2_req *in = fill_umount2_request(FALSE);
  struct umount2_req *local = fill_umount2_request(FALSE);
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_umount2_request(&nbytes, &iov_count, in->target, in->flags);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_umount2_response(&resp_hd, &iov_count, &nbytes, in->target, in->flags);
  assert(resp_iov == NULL); 
  assert(compare_string(local->target, in->target));
  assert(local->flags == in->flags);

  free_filled_umount2_request(in, 0);
  free_filled_umount2_request(local, 0);
 
}

void server_test_umount2(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct umount2_req *input = fill_umount2_request(FALSE);
  struct umount2_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_umount2_exec(req_hd, client_arch);
  req = (struct umount2_req *) req_hd;
  /* I test the content of the request */
  assert(compare_string(req->target, input->target));
  assert(req->flags == input->flags);

  /* The syscall doesn't have write pointers, so I do nothing */

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_umount2_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_umount2_request(input, 0);
 
}
void client_test_uname(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct uname_req *in = fill_uname_request();
  struct uname_req *local = fill_uname_request();
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_uname_request(&nbytes, &iov_count, in->buf);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_uname_response(&resp_hd, &iov_count, &nbytes, in->buf);
  assert(resp_iov != NULL); 
  ret = readv(fd, resp_iov, iov_count);
  assert(ret == nbytes);
  free(resp_iov);
  /* I fill the 'local' request, in this way I can compare this local copy with
   * the remote one 'in' */
  uname_fill_write_pointers(local->buf);
  assert(compare_struct_utsname(local->buf, in->buf));

  free_filled_uname_request(in, 0);
  free_filled_uname_request(local, 0);
 
}

void server_test_uname(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct uname_req *input = fill_uname_request();
  struct uname_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_uname_exec(req_hd, client_arch);
  req = (struct uname_req *) req_hd;
  /* I test the content of the request */

  /* I simulate the execution of the system call, calling
   * a function that fills the write pointer of the request. */
  ret = uname_fill_write_pointers(req->buf);

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_uname_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_uname_request(input, 0);
 
}
void client_test_unlink(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct unlink_req *in = fill_unlink_request(FALSE);
  struct unlink_req *local = fill_unlink_request(FALSE);
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_unlink_request(&nbytes, &iov_count, in->pathname);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_unlink_response(&resp_hd, &iov_count, &nbytes, in->pathname);
  assert(resp_iov == NULL); 
  assert(compare_string(local->pathname, in->pathname));

  free_filled_unlink_request(in, 0);
  free_filled_unlink_request(local, 0);
 
}

void server_test_unlink(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct unlink_req *input = fill_unlink_request(FALSE);
  struct unlink_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_unlink_exec(req_hd, client_arch);
  req = (struct unlink_req *) req_hd;
  /* I test the content of the request */
  assert(compare_string(req->pathname, input->pathname));

  /* The syscall doesn't have write pointers, so I do nothing */

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_unlink_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_unlink_request(input, 0);
 
}
void client_test_utime(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct utime_req *in = fill_utime_request(FALSE, FALSE);
  struct utime_req *local = fill_utime_request(FALSE, FALSE);
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_utime_request(&nbytes, &iov_count, in->filename, in->buf);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_utime_response(&resp_hd, &iov_count, &nbytes, in->filename, in->buf);
  assert(resp_iov == NULL); 
  assert(compare_string(local->filename, in->filename));
  assert(compare_struct_utimbuf(local->buf, in->buf));

  free_filled_utime_request(in, 0);
  free_filled_utime_request(local, 0);
 
}

void server_test_utime(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct utime_req *input = fill_utime_request(FALSE, FALSE);
  struct utime_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_utime_exec(req_hd, client_arch);
  req = (struct utime_req *) req_hd;
  /* I test the content of the request */
  assert(compare_string(req->filename, input->filename));
  assert(compare_struct_utimbuf(req->buf, input->buf));

  /* The syscall doesn't have write pointers, so I do nothing */

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_utime_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_utime_request(input, 0);
 
}
void client_test_utimes(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct utimes_req *in = fill_utimes_request(FALSE);
  struct utimes_req *local = fill_utimes_request(FALSE);
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_utimes_request(&nbytes, &iov_count, in->filename, in->tv);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_utimes_response(&resp_hd, &iov_count, &nbytes, in->filename, in->tv);
  assert(resp_iov == NULL); 
  assert(compare_string(local->filename, in->filename));
  assert(compare_struct_timeval(&local->tv[0], &in->tv[0]));
  assert(compare_struct_timeval(&local->tv[1], &in->tv[1]));

  free_filled_utimes_request(in, 0);
  free_filled_utimes_request(local, 0);
 
}

void server_test_utimes(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct utimes_req *input = fill_utimes_request(FALSE);
  struct utimes_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_utimes_exec(req_hd, client_arch);
  req = (struct utimes_req *) req_hd;
  /* I test the content of the request */
  assert(compare_string(req->filename, input->filename));
  assert(compare_struct_timeval(&req->tv[0], &input->tv[0]));
  assert(compare_struct_timeval(&req->tv[1], &input->tv[1]));

  /* The syscall doesn't have write pointers, so I do nothing */

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_utimes_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_utimes_request(input, 0);
 
}
void client_test_write(int fd) {
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct write_req *in = fill_write_request(FALSE);
  struct write_req *local = fill_write_request(FALSE);
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_write_request(&nbytes, &iov_count, in->fd, in->buf, in->count);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_write_response(&resp_hd, &iov_count, &nbytes, in->fd, in->buf, in->count);
  assert(resp_iov == NULL); 
  assert(local->fd == in->fd);
  assert(compare_mem(local->buf, in->buf, in->count));
  assert(local->count == in->count);

  free_filled_write_request(in, 0);
  free_filled_write_request(local, 0);
 
}

void server_test_write(int fd, enum arch server_arch, enum arch client_arch) {
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct write_req *input = fill_write_request(FALSE);
  struct write_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_write_exec(req_hd, client_arch);
  req = (struct write_req *) req_hd;
  /* I test the content of the request */
  assert(req->fd == input->fd);
  assert(compare_mem(req->buf, input->buf, input->count));
  assert(req->count == input->count);

  /* The syscall doesn't have write pointers, so I do nothing */

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_write_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_write_request(input, 0);
 
}

/*******************************************************************/
/* Public test functions                                           */
/*******************************************************************/
void test_syscall_exec_client(int fd, enum arch myarch, enum arch sarch) {
  if(sarch != ACONV_X86_64) 
    client_test__llseek(fd);
  client_test_accept(fd);
  client_test_access(fd);
  client_test_adjtimex(fd);
  client_test_bind(fd);
  client_test_chdir(fd);
  client_test_chmod(fd);
  client_test_chown(fd);
  if(sarch != ACONV_PPC && sarch != ACONV_X86_64) 
    client_test_chown32(fd);
  client_test_clock_getres(fd);
  client_test_clock_gettime(fd);
  client_test_clock_settime(fd);
  client_test_close(fd);
  client_test_connect(fd);
  client_test_dup(fd);
  client_test_dup2(fd);
  client_test_fchdir(fd);
  client_test_fchmod(fd);
  client_test_fchown(fd);
  if(sarch != ACONV_PPC && sarch != ACONV_X86_64) 
    client_test_fchown32(fd);
  client_test_fdatasync(fd);
  client_test_fgetxattr(fd);
  client_test_fstat64(fd);
  client_test_fstatfs64(fd);
  client_test_fsync(fd);
  client_test_ftruncate64(fd);
  client_test_getdents64(fd);
  client_test_getpeername(fd);
  client_test_getsockname(fd);
  client_test_getsockopt(fd);
  client_test_gettimeofday(fd);
  client_test_getxattr(fd);
  client_test_lchown(fd);
  if(sarch != ACONV_PPC && sarch != ACONV_X86_64) 
    client_test_lchown32(fd);
  client_test_lgetxattr(fd);
  client_test_link(fd);
  client_test_listen(fd);
  client_test_lseek(fd);
  client_test_lstat64(fd);
  client_test_mkdir(fd);
  client_test_mount(fd);
  client_test_open(fd);
  client_test_pread64(fd);
  client_test_pwrite64(fd);
  client_test_read(fd);
  client_test_readlink(fd);
  if(sarch != ACONV_X86_64) 
    client_test_recv(fd);
  client_test_recvfrom(fd);
  client_test_rename(fd);
  client_test_rmdir(fd);
  if(sarch != ACONV_X86_64) 
    client_test_send(fd);
  client_test_sendto(fd);
  client_test_setdomainname(fd);
  client_test_sethostname(fd);
  client_test_setsockopt(fd);
  client_test_settimeofday(fd);
  client_test_shutdown(fd);
  client_test_socket(fd);
  client_test_stat64(fd);
  client_test_statfs64(fd);
  client_test_symlink(fd);
  client_test_truncate64(fd);
  client_test_umount2(fd);
  client_test_uname(fd);
  client_test_unlink(fd);
  client_test_utime(fd);
  client_test_utimes(fd);
  client_test_write(fd);
}

void test_syscall_exec_server(int fd, enum arch carch, enum arch myarch) {
  server_test__llseek(fd, myarch, carch);
  server_test_accept(fd, myarch, carch);
  server_test_access(fd, myarch, carch);
  server_test_adjtimex(fd, myarch, carch);
  server_test_bind(fd, myarch, carch);
  server_test_chdir(fd, myarch, carch);
  server_test_chmod(fd, myarch, carch);
  server_test_chown(fd, myarch, carch);
  server_test_chown32(fd, myarch, carch);
  server_test_clock_getres(fd, myarch, carch);
  server_test_clock_gettime(fd, myarch, carch);
  server_test_clock_settime(fd, myarch, carch);
  server_test_close(fd, myarch, carch);
  server_test_connect(fd, myarch, carch);
  server_test_dup(fd, myarch, carch);
  server_test_dup2(fd, myarch, carch);
  server_test_fchdir(fd, myarch, carch);
  server_test_fchmod(fd, myarch, carch);
  server_test_fchown(fd, myarch, carch);
  server_test_fchown32(fd, myarch, carch);
  server_test_fdatasync(fd, myarch, carch);
  server_test_fgetxattr(fd, myarch, carch);
  server_test_fstat64(fd, myarch, carch);
  server_test_fstatfs64(fd, myarch, carch);
  server_test_fsync(fd, myarch, carch);
  server_test_ftruncate64(fd, myarch, carch);
  server_test_getdents64(fd, myarch, carch);
  server_test_getpeername(fd, myarch, carch);
  server_test_getsockname(fd, myarch, carch);
  server_test_getsockopt(fd, myarch, carch);
  server_test_gettimeofday(fd, myarch, carch);
  server_test_getxattr(fd, myarch, carch);
  server_test_lchown(fd, myarch, carch);
  server_test_lchown32(fd, myarch, carch);
  server_test_lgetxattr(fd, myarch, carch);
  server_test_link(fd, myarch, carch);
  server_test_listen(fd, myarch, carch);
  server_test_lseek(fd, myarch, carch);
  server_test_lstat64(fd, myarch, carch);
  server_test_mkdir(fd, myarch, carch);
  server_test_mount(fd, myarch, carch);
  server_test_open(fd, myarch, carch);
  server_test_pread64(fd, myarch, carch);
  server_test_pwrite64(fd, myarch, carch);
  server_test_read(fd, myarch, carch);
  server_test_readlink(fd, myarch, carch);
  server_test_recv(fd, myarch, carch);
  server_test_recvfrom(fd, myarch, carch);
  server_test_rename(fd, myarch, carch);
  server_test_rmdir(fd, myarch, carch);
  server_test_send(fd, myarch, carch);
  server_test_sendto(fd, myarch, carch);
  server_test_setdomainname(fd, myarch, carch);
  server_test_sethostname(fd, myarch, carch);
  server_test_setsockopt(fd, myarch, carch);
  server_test_settimeofday(fd, myarch, carch);
  server_test_shutdown(fd, myarch, carch);
  server_test_socket(fd, myarch, carch);
  server_test_stat64(fd, myarch, carch);
  server_test_statfs64(fd, myarch, carch);
  server_test_symlink(fd, myarch, carch);
  server_test_truncate64(fd, myarch, carch);
  server_test_umount2(fd, myarch, carch);
  server_test_uname(fd, myarch, carch);
  server_test_unlink(fd, myarch, carch);
  server_test_utime(fd, myarch, carch);
  server_test_utimes(fd, myarch, carch);
  server_test_write(fd, myarch, carch);
}
