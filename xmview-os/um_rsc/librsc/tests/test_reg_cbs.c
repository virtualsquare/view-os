/*   
 *   This is part of Remote System Call (RSC) Library.
 *
 *   test_reg_cbs.c: callback registration data structure tests
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
#include "rsc_client.h"
#include "registered_callbacks.h"

struct reg_cbs *reg_cbs_add, *reg_cbs_del;

/********************************************************************/
/* Init test                                                        */
/********************************************************************/
static void test_init()
{
  struct reg_cbs *p;
  int i;
  p = init_reg_cb();
  assert(!(p == NULL));
  
  assert(!(p->nentry != 0));
  assert(!(p->size != REG_CB_INITIAL_SIZE));
  for(i = 0; i < p->size; i++) {
    assert(!(p->v[i].fd  != -1));
    assert(!(p->v[i].how != -1));
    assert(!(p->v[i].cb  != NULL));
    assert(!(p->v[i].arg != NULL));
  }
  
  free(p->v); free(p);
}

/********************************************************************/
/* Add test                                                         */
/********************************************************************/
static void test_entry(struct reg_cbs *p, int i, int fd, int how, void (* cb)(), void *arg) {
  assert(!(p->v[i].fd != fd));
  assert(!(p->v[i].how != how));
  assert(!(p->v[i].cb != cb));
  assert(!(p->v[i].arg != arg));
  assert(!(p->v[i].ack != ACK_NOT_INIT));
}

static void test_add()
{
  int i, ret;
  /* I fill the array and for each entry I controll its arguments */
  for(i = 0; i < reg_cbs_add->size; i++) {
    ret = reg_cb_add(reg_cbs_add, NULL, NULL, i+1, i+2);
    assert(!(ret != i));
    test_entry(reg_cbs_add, i, i+1, i+2, 0, NULL);

    assert(!(reg_cbs_add->nentry != i+1));
  }
  assert(!(reg_cbs_add->nentry != i));
  
  /* I add another entry to test the reallocation of the array */
  reg_cb_add(reg_cbs_add, NULL, NULL, 100, 200);
  
  /* I test the new entry */
  test_entry(reg_cbs_add, 10, 100, 200, NULL, NULL);

  /* and the new size, nfds */
  assert(!(reg_cbs_add->size != 20));
  assert(!(reg_cbs_add->nentry != 11));

  /* I test the newly creted empty entries */
  for(i = reg_cbs_add->nentry; i < reg_cbs_add->size; i++)
    test_entry(reg_cbs_add, i, -1, -1, NULL, NULL);

}

static void add_setup(void) {
  reg_cbs_add = init_reg_cb();
  assert(!(reg_cbs_add == NULL));
}
static void add_teardown(void) {
  free(reg_cbs_add->v); free(reg_cbs_add);
}

/********************************************************************/
/* Del test                                                         */
/********************************************************************/
static void test_del()
{
  reg_cb_del(reg_cbs_del, 3);
  test_entry(reg_cbs_del, 3, -1, -1, NULL, NULL);
  assert(!(reg_cbs_del->nentry != 9));

  reg_cb_del(reg_cbs_del, 5);
  test_entry(reg_cbs_del, 5, -1, -1, NULL, NULL);
  assert(!(reg_cbs_del->nentry != 8));
  
  reg_cb_add(reg_cbs_del, NULL, NULL, 66, 77);
  test_entry(reg_cbs_del, 3, 66, 77, NULL, NULL);
  assert(!(reg_cbs_del->nentry != 9));
  
}


static void del_setup(void) {
  int i;
  reg_cbs_del = init_reg_cb();
  assert(!(reg_cbs_del == NULL));
  /* I fill the array and for each entry I controll its arguments */
  for(i = 0; i < reg_cbs_del->size; i++) {
    reg_cb_add(reg_cbs_del, NULL, NULL, i+1, i+2);
  }
}
static void del_teardown(void) {
  free(reg_cbs_del->v); free(reg_cbs_del);
}

/****************************************************/
/* Library functions                                */
/****************************************************/
void test_reg_cbs(void) {
  test_init();

  add_setup();
  test_add();
  add_teardown();

  del_setup();
  test_del();
  del_teardown();
}

