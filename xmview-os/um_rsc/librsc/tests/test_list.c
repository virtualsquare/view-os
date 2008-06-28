/*   
 *   This is part of Remote System Call (RSC) Library.
 *
 *   test_list.c: List data structure tests
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
#include "generic_list.h"

int initial_size;
struct list *list_a, *list_d;

/********************************************************************/
/* Init test                                                        */
/********************************************************************/
static void test_init(void)
{
  struct list *l;
  l = init_list(100);
  assert(!(l == NULL));
  
  assert(!(l->nentry != 0));
  assert(!(l->size != 100));
  
  free(l->v); free(l);
}

/********************************************************************/
/* Add test                                                         */
/********************************************************************/
static void test_entry(struct list *l, int i, int *num) {
  assert(!(l->v[i] != num));
  
  if(num != NULL)
    assert(!(*((int *)l->v[i]) != *num));
}

static void test_add(void)
{
  int i, *num;
  /* I fill the array and for each entry I controll its arguments */
  for(i = 0; i < list_a->size; i++) {
    num = calloc(1, sizeof(int));
    assert(!(num == NULL));
    *num = i+1; 
    list_add(list_a, num);
    test_entry(list_a, i, num);

    assert(!(list_a->nentry != i+1));
  }
  assert(!(list_a->nentry != i));
  
  /* I add another entry to test the reallocation of the array */
  num = calloc(1, sizeof(int));
  assert(!(num == NULL));
  *num = 1234;
  list_add(list_a, num);
  
  /* I test the new entry */
  test_entry(list_a, initial_size, num);

  /* and the new size, nfds */
  assert(!(list_a->size != initial_size*2));
  assert(!(list_a->nentry != initial_size+1));

  /* I test the newly created empty entries */
  for(i = list_a->nentry; i < list_a->size; i++)
    assert(!(list_a->v[i] != NULL));

}

static void add_setup(void) {
  initial_size = 10;
  list_a = init_list(initial_size);
  assert(!(list_a == NULL));
}
static void add_teardown(void) {
  free(list_a->v); free(list_a);
}

/********************************************************************/
/* Del/Search test                                                  */
/********************************************************************/
static void test_del(void)
{
  int *num;
  num = list_del(list_d, 3);
  test_entry(list_d, 3, NULL);
  assert(!(*num != 3));
  free(num);
  assert(!(list_d->nentry != initial_size - 1));


  num = list_del(list_d, 5);
  test_entry(list_d, 5, NULL);
  assert(!(*num != 5));
  free(num);
  assert(!(list_d->nentry != initial_size - 2));
  
  num = calloc(1, sizeof(int));
  list_add(list_d, num);
  test_entry(list_d, 3, num);
  assert(!(list_d->nentry != initial_size - 1));
  free(num);
  
}

static int compare_int(void *a, void *b) {
  return (*(int *)a == *(int *)b);
}

static void test_search(void)
{
  int *num, val, i;
  val = 5;
  i = list_search(list_d, compare_int, &val);
  assert(!(i != 5));
  num = list_getel(list_d, i);
  assert(!(num != list_d->v[5]));
  assert(!(*num != 5));

  /* Now I delete it and search again */
  list_del(list_d, 5);
  assert(!(list_d->v[5] != NULL));
  i = list_search(list_d, compare_int, &val);
  assert(!(i != -1));
  num = list_getel(list_d, i);
  assert(!(num != NULL));

  /* Now I try to get an element with negative or too big index */
  num = list_getel(list_d, -1);
  assert(!(num != NULL));
  free(num);
  num = list_getel(list_d, -2);
  assert(!(num != NULL));
  free(num);
  num = list_getel(list_d, 12345);
  assert(!(num != NULL));
  free(num);


}

static void del_setup(void) {
  int i, *num;
  initial_size = 10;
  list_d = init_list(initial_size);
  assert(!(list_d == NULL));
  /* I fill the array and for each entry I control its arguments */
  for(i = 0; i < list_d->size; i++) {
    num = calloc(1, sizeof(int));
    assert(!(num == NULL));
    *num = i;
    list_add(list_d, num);
  }
}
static void del_teardown(void) {
  free(list_d->v); free(list_d);
}

/****************************************************/
/* Library functions                                */
/****************************************************/
void test_list(void) {
  test_init();

  add_setup();
  test_add();
  add_teardown();

  del_setup();
  test_del();
  del_teardown();
}
