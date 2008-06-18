/*   
 *   This is part of Remote System Call (RSC) Library.
 *
 *   generic_list.c: List data structure 
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
#include <assert.h>
#include "generic_list.h"

struct list *init_list(int initial_size) {
  struct list *l;
  l = calloc(1, sizeof(struct list));
  if(l == NULL) 
    return NULL;
  l->v = calloc(initial_size, sizeof(void *));
  if(l->v == NULL) {
    free(l);
    return NULL;
  }
  
  l->size = initial_size;
  l->nentry = 0;

  return l;
}

void teardown_list(struct list *l, void (free_el)(void *element) ) {
  int i;
  for(i = 0; l->nentry && i < l->size; i++) {
    if(l->v[i] != NULL)
      free_el(l->v[i]);
  }
  free(l->v);

  free(l);
}

void list_add(struct list *l, void *element) {
  int i, empty_i = -1;
  /* I have to enlarge the array */
  if(l->nentry >= l->size) {
    l->size *= 2;
    l->v = realloc(l->v,  l->size * sizeof(void *));
    assert(l->v != NULL);
    empty_i = l->nentry;
  } else if(l->nentry == 0) {
    empty_i = 0;
  } else {
    for(i = 0; (i < l->size) && (l->v[i] != NULL); i++);
    empty_i = i;
  }
 
  l->v[empty_i]  = element;
  l->nentry += 1;
}

void *list_del(struct list *l, int i) {
  void *ret;
  if(i < 0 || i >= l->size)
    return NULL;
  ret = l->v[i];
  l->v[i] = NULL;
  l->nentry -= 1;

  return ret;
}

/* Search inside le list 'l'. The function 'compare' is used to 
 * test non-NULL entries. The argument 'arg' is an opaque argument
 * passed to 'compare' function. 
 * On success the index of the element is returned, -1 otherwise. */
int list_search(struct list *l, int (compare)(void *element, void *arg), void *arg) 
{
  int i;
  if(l->nentry == 0)
    return -1;
  for(i = 0; i < l->size; i++) {
    if(l->v[i] != NULL && compare(l->v[i], arg))
      return i;
  }

  return -1;
}


#ifdef RSCDEBUG
#include <stdio.h>

void print_list(struct list *l, void (* print_list_element)(void *element)) {
  int i;
  fprintf(stderr, "List: nentry = %d, size = %d:\n", l->nentry, l->size);
  for(i = 0; i < l->size; i++){
    fprintf(stderr, "\t %d. ", i);
    if(l->v[i] != NULL) 
      print_list_element(l->v[i]);
     else 
      fprintf(stderr, "EMPTY");
    fprintf(stderr, "\n");
  }
}
#endif
