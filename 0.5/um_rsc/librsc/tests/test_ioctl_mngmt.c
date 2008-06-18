/*   
 *   This is part of Remote System Call (RSC) Library.
 *
 *   test_ioctl_mngmt.c: ioctl management tests
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
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include "rsc_server.h"
#include "rsc_client.h"
#include "test_rsc_client.h"
#include "test_rsc_server.h"

/********************************************************************/
/* Cache test                                                       */
/********************************************************************/
static void test_cache(void)
{
  struct ioctl_cache *c;
  u_int32_t res;
  int size = 3;
  c = ioctl_cache_init(size);
  assert(!(c == NULL));
  assert(!(c->first != NULL));
  assert(!(c->last != NULL));
  assert(!(c->size != size));
  assert(!(c->nentry != 0));

  /* Add element 1 */
  ioctl_cache_add(c, 10, 11);
  assert(!(c->first == NULL));
  assert(!(c->first->next != NULL));
  assert(!(c->first->prev != NULL));
  assert(!(c->first->request != 10));
  assert(!(c->first->size_type != 11));
  assert(!(c->nentry != 1));
  assert(!(c->size != size));

  
  /* Add element 2 */
  ioctl_cache_add(c, 20, 22);
  assert(!(c->first == NULL));
  assert(!(c->first->next == NULL));
  assert(!(c->first->prev != NULL));
  assert(!(c->first->request != 20));
  assert(!(c->first->size_type != 22));
  assert(!(c->nentry != 2));
  assert(!(c->size != size));

  assert(!(c->first->next->request != 10));
  assert(!(c->first->next->size_type != 11));
  assert(!(c->first->next->prev != c->first));
  /* Add element 2 */
  ioctl_cache_add(c, 30, 33);
  assert(!(c->first == NULL));
  assert(!(c->first->next == NULL));
  assert(!(c->first->prev != NULL));
  assert(!(c->first->request != 30));
  assert(!(c->first->size_type != 33));
  assert(!(c->nentry != 3));
  assert(!(c->size != size));

  assert(!(c->first->next->request != 20));
  assert(!(c->first->next->size_type != 22));
  assert(!(c->first->next->prev != c->first));

  assert(!(c->first->next->next->request != 10));
  assert(!(c->first->next->next->size_type != 11));
  assert(!(c->first->next->next->prev != c->first->next));
  
  assert(!(c->last->request != 10));
  assert(!(c->last->size_type != 11));
  assert(!(c->last->prev != c->first->next));

  /* Now the queue is full */
  ioctl_cache_add(c, 40, 44);
  assert(!(c->first == NULL));
  assert(!(c->first->next == NULL));
  assert(!(c->first->prev != NULL));
  assert(!(c->first->request != 40));
  assert(!(c->first->size_type != 44));
  assert(!(c->nentry != 3));
  assert(!(c->size != size));
  
  assert(!(c->first->next->request != 30));
  assert(!(c->first->next->size_type != 33));
  assert(!(c->first->next->prev != c->first));

  assert(!(c->first->next->next->request != 20));
  assert(!(c->first->next->next->size_type != 22));
  assert(!(c->first->next->next->prev != c->first->next));

  /* Search */
  res = ioctl_cache_search(c, 20);
  assert(!(res != 22));
  
  res = ioctl_cache_search(c, 30);
  assert(!(res != 33));
  
  res = ioctl_cache_search(c, 40);
  assert(!(res != 44));
  
  res = ioctl_cache_search(c, 50);
  assert(!(res != 0));

}


/********************************************************************/
/* Query test                                                       */
/********************************************************************/
static void test_server_query(int fd) {
  int ret, i;
  struct ioctl_req_header req;
  struct ioctl_resp_header *resp;

  for(i = 0; i < 4; i++) {
    ret = read(fd, &req, sizeof(struct ioctl_req_header));
    assert(!(ret != sizeof(struct ioctl_req_header)));
    req.req_size = ntohl(req.req_size);
    resp = rscs_manage_ioctl_request(&req);
    ret = write(fd, resp, sizeof(struct ioctl_resp_header));
    assert(ret == sizeof(struct ioctl_resp_header));
  }
}

static void test_client_query(int fd)
{
  int res;

  /* Here there is the client code */
  res = rscc_check_ioctl_request(100);
  assert(!(res == 0));
  assert(!((res & IOCTL_R) != IOCTL_R));
  assert(!((res & IOCTL_LENMASK) != sizeof(char)));
  
  res = rscc_check_ioctl_request(101);
  assert(!(res == 0));
  assert(!((res & IOCTL_W) != IOCTL_W));
  assert(!((res & IOCTL_LENMASK) != sizeof(int)));
  
  res = rscc_check_ioctl_request(102);
  assert(!(res == 0));
  assert(!((res & (IOCTL_R | IOCTL_W)) != (IOCTL_R | IOCTL_W)));
  assert(!((res & IOCTL_LENMASK) != sizeof(long long)));

  /* I query for a request that doesn't exists */
  res = rscc_check_ioctl_request(123);
  assert(!(res != IOCTL_UNMANAGED));

}


/****************************************************/
/* Library functions                                */
/****************************************************/
void test_ioctl_mngmt_client(int fd)
{
  test_cache();
  
  test_client_query(fd);
}

void test_ioctl_mngmt_server(int fd)
{
  test_cache();
  
  /* I register dome fake ioctl requests */
  rscs_ioctl_register_request(100, IOCTL_R, sizeof(char));
  rscs_ioctl_register_request(101, IOCTL_W, sizeof(int));
  rscs_ioctl_register_request(102, IOCTL_R | IOCTL_W, sizeof(long long));
  test_server_query(fd);
}
