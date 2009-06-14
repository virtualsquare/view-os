/*   
 *   This is part of Remote System Call (RSC) Library.
 *
 *   server.c: server program used by the tests
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
#include "tests.h"
#include "client_server.h"

static int server_port;

void test_aconv(void) {
  int fd;
  fd = setup_server(server_port);
  assert(fd != -1);
  test_server(&fd);
}

int main(int argc, char *argv[]) {
  if(argc != 1 && argc > 2) {
    fprintf(stderr, "USAGE: %s [PORT]\n", argv[0]);
    exit(-1);
  }
  server_port = 10000;
  if(argc >= 2) {
    server_port = atoi(argv[1]);
  }
   test_aconv();

  return 0;
}
