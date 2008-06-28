/*   
 *   This is part of Remote System Call (RSC) Library.
 *
 *   registered_callbacks.c: data structure and functions for 
 *                           registered callback management
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
#include "rsc_client.h"
#include "registered_callbacks.h"


static void init_empty_entry(struct reg_cbs *p, int i) {
  p->v[i].fd  = -1; 
  p->v[i].how = -1; 
  p->v[i].cb  = NULL; 
  p->v[i].arg = NULL; 
  p->v[i].ack = ACK_NOT_INIT; 
  p->v[i].cb_executed = 0; 

}

struct reg_cbs *init_reg_cb() {
  int i;
  struct reg_cbs *p;
  p = calloc(1, sizeof(struct reg_cbs));
  if(p == NULL) 
    return NULL;
  p->v = calloc(REG_CB_INITIAL_SIZE, sizeof(struct reg_cb));
  if(p->v == NULL) {
    free(p);
    return NULL;
  }
  
  p->size = REG_CB_INITIAL_SIZE;
  p->nentry = 0;
  for(i = 0; i < p->size; i++) {
    init_empty_entry(p, i);
  }

  return p;
}

int reg_cb_add(struct reg_cbs *p, void (* cb)(), void *arg, int fd, int how) {
  int empty_i = -1;
  /* I have to enlarge the array */
  if(p->nentry >= p->size) {
    int i;
    p->size += REG_CB_INITIAL_SIZE;
    p->v    = realloc(p->v,  p->size * sizeof(struct reg_cb));
    assert(p->v != NULL);
    /* I init the new entries created */
    for(i = p->nentry; i < p->size; i++) {
      init_empty_entry(p, i);
    }
    empty_i = p->nentry;
  } else {
    int i;
    for(i = 0; i < p->size; i++)
      if(p->v[i].fd == -1) {
        empty_i = i;
        break;
      }
  }
 
  assert(empty_i != -1);
  p->v[empty_i].fd  = fd;
  p->v[empty_i].how = how;
  p->v[empty_i].cb  = cb;
  p->v[empty_i].arg = arg;
  p->v[empty_i].ack = ACK_NOT_INIT;

  p->nentry += 1;
  return empty_i;
}

void reg_cb_del(struct reg_cbs *p, int i) {
  if(i < 0 || i >= p->size)
    return;
  init_empty_entry(p, i);
  p->nentry -= 1;
}


#ifdef RSCDEBUG
#include <stdio.h>
void print_regcb_entry(struct reg_cbs *rc, int i) {
  if(i < 0 || i > rc->size)
    return;
  if(rc->v[i].fd == -1)
    fprintf(stderr, "EMPTY");
  else
    fprintf(stderr, "FD = %d; HOW = %d; CB = %p; ARG = %p; ACK = %d; CB EXECUTED = %d",
        rc->v[i].fd, rc->v[i].how, rc->v[i].cb, rc->v[i].arg, rc->v[i].ack, rc->v[i].cb_executed);
}

void print_regcbs(struct reg_cbs *rc) {
  int i;
  fprintf(stderr, "Registered callbacks: nentry = %d, size = %d:\n", rc->nentry, rc->size);
  for(i = 0; i < rc->size; i++){
    fprintf(stderr, "\t%d. ", i);
    print_regcb_entry(rc, i);
    fprintf(stderr, "\n");

  }
}
#endif
