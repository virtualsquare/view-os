/*   
 *   This is part of Remote System Call (RSC) Library.
 *
 *   generic_list.h: list data structure header
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

#ifndef __GENERIC_LIST_HEADER__
#define __GENERIC_LIST_HEADER__

struct list {
  void **v;
  int size;
  int nentry;
};

struct list *init_list(int initial_size);
void teardown_list(struct list *l, void (free_el)(void *element) );
void list_add(struct list *l, void *element);
void *list_del(struct list *l, int i);
int list_search(struct list *l, int (compare)(void *element, void *arg), void *arg);
#define list_getel(list, index)   ( ((index) < 0 || (index) > (list)->size )? NULL : ((list)->v[(index)]) )

#ifdef RSCDEBUG
# define PRINT_LIST(list, print_list_element) print_list(list, print_list_element)
void print_list(struct list *l, void (* print_list_element)(void *element));
#else
# define PRINT_LIST(list, print_list_element)
#endif
#endif /* __GENERIC_LIST_HEADER__ */
