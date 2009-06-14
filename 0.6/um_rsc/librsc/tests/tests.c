/*   
 *   This is part of Remote System Call (RSC) Library.
 *
 *   tests.c: functions grouping all the tests to do
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
#include <arpa/inet.h>
#include <unistd.h>
#include "rsc_client.h"
#include "rsc_server.h"
#include "tests.h"
#include "aconv.h"

static enum arch test_init() {
  enum arch a;

  a = aconv_get_host_arch();
  assert(a != ACONV_ARCH_ERROR);
# if defined __x86_64__
  assert(a == ACONV_X86_64);
# elif defined __i386__
  assert(a == ACONV_X86);
# elif defined __powerpc__
  if(sizeof(long) == 8)
    assert(a == ACONV_PPC_64);
  else
    assert(a == ACONV_PPC);
# elif defined __powerpc64__
  assert(a == ACONV_PPC_64);
# endif
  return a;
}

void *test_client(void *fdp) {
  enum arch myarch, sarch, buf;
  int ret, fd = *(int *)fdp;
  /*** INIT ***/
  myarch = test_init();
  /* Send my arch to server */
  buf = htonl(myarch);
  assert(write(fd, &buf, sizeof(myarch)) == sizeof(myarch));
  /* Read the server arch */
  assert(read(fd, &buf, sizeof(sarch)) == sizeof(sarch));
  sarch = ntohl(buf);
  fprintf(stderr, "Client: my arch = %s, server arch = %s\n", aconv_arch2str(myarch), aconv_arch2str(sarch));
  ret = rscc_init(fd, -1, NULL, myarch, sarch);
  assert(ret == 0);
 
  /*** TESTS ***/
  fprintf(stderr, "test_list... "); fflush(stderr);
  test_list();
  fprintf(stderr, "done\n"); fprintf(stderr, "test_type_equality... "); fflush(stderr);
  test_type_equality();
  fprintf(stderr, "done\n"); fprintf(stderr, "test_ioctl_mngmt... "); fflush(stderr);
  test_ioctl_mngmt_client(fd);
  fprintf(stderr, "done\n"); fprintf(stderr, "test_libaconv... "); fflush(stderr);
  test_libaconv_client(fd, myarch, sarch);
  fprintf(stderr, "done\n"); fprintf(stderr, "test_syscall_exec... "); fflush(stderr);
  test_syscall_exec_client(fd, myarch, sarch);
  fprintf(stderr, "done\n");

  return NULL;
}
void *test_server(void *fdp) {
  int ret, fd = *(int *)fdp;
  enum arch myarch, carch, buf;
  /*** INIT ***/
  myarch = test_init();
  /* Read the client arch */
  assert(read(fd, &buf, sizeof(carch)) == sizeof(carch));
  carch = ntohl(buf);
  /* Send my arch to client */
  buf = htonl(myarch);
  assert(write(fd, &buf, sizeof(myarch)) == sizeof(myarch));
  fprintf(stderr, "Server: my arch = %s, client arch = %s\n", aconv_arch2str(myarch), aconv_arch2str(carch));
  ret = rscs_init(myarch);
  assert(ret == 0);

  /*** TESTS ***/
  fprintf(stderr, "test_list... "); fflush(stderr);
  test_list();
  fprintf(stderr, "done\n"); fprintf(stderr, "test_type_equality... "); fflush(stderr);
  test_type_equality();
  fprintf(stderr, "done\n"); fprintf(stderr, "test_ioctl_mngmt... "); fflush(stderr);
  test_ioctl_mngmt_server(fd);
  fprintf(stderr, "done\n"); fprintf(stderr, "test_libaconv... "); fflush(stderr);
  test_libaconv_server(fd, carch, myarch);
  fprintf(stderr, "done\n"); fprintf(stderr, "test_syscall_exec... "); fflush(stderr);
  test_syscall_exec_server(fd, carch, myarch);
  fprintf(stderr, "done\n");
  
  return NULL;
}

