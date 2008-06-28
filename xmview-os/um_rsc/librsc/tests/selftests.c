/*   
 *   This is part of Remote System Call (RSC) Library.
 *
 *   selftests.c: program used to execute both client and server tests on
 *                the same machine
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
#include <assert.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "tests.h"

void test_aconv(void) {
  pthread_t server_thread;
  int serverfd, clientfd, ret;
  int fd[2];
  
  /* I create the client and server fds */
  ret = socketpair(PF_UNIX, SOCK_STREAM, 0, fd);
  assert(ret == 0);
  clientfd = fd[0];
  serverfd = fd[1];

  pthread_create(&server_thread, NULL, test_server, &serverfd);
  test_client(&clientfd);

  pthread_join(server_thread, NULL);
}

int main(void) {
  test_aconv();
  return 0;
}
