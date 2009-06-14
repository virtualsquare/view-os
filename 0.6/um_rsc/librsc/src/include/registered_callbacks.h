/*   
 *   This is part of Remote System Call (RSC) Library.
 *
 *   registered_callbacks.h: header of registered callback 
 *                           data structure management
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

#ifndef __REGISTERED_CALLBACKS_HEADER__
#define __REGISTERED_CALLBACKS_HEADER__
#include "rsc_messages.h"
#define   REG_CB_INITIAL_SIZE   10



struct reg_cbs *init_reg_cb();
int reg_cb_add(struct reg_cbs *p, void (* cb)(), void *arg, int fd, int how);
void reg_cb_del(struct reg_cbs *p, int i);

#ifdef RSCDEBUG
# define PRINT_REGCB(reg_cbs, i) print_regcb_entry(reg_cbs, i)
# define PRINT_REGCBS(reg_cbs)   print_regcbs(reg_cbs)
void print_regcb_entry(struct reg_cbs *rc, int i);
void print_regcbs(struct reg_cbs *rc);

#else
# define PRINT_REGCB(reg_cbs, i)
# define PRINT_REGCBS(reg_cbs)
#endif
#endif /* __REGISTERED_CALLBACKS_HEADER__ */
