/*   
 *   This is part of Remote System Call (RSC) Library.
 *
 *   event_sub.c: client and server local functions for event subscription
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
#ifndef __EVENT_SUB_H__
#define __EVENT_SUB_H__
struct reg_cbs *rscc_es_init(int event_sub_fd);
void rscs_es_init();
#endif /* __EVENT_SUB_H__ */
