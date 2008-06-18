/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   UMMISC: Virtual Miscellanea in Userspace (function mgmt)
 *    Copyright (C) 2007  Renzo Davoli <renzo@cs.unibo.it>
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
#ifndef _UMMISCFUN_H
#define _UMMISCFUN_H
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/select.h>

void setscset(void *dlhandle,fd_set *scs);
void initmuscno(struct service *s);
void finimuscno(void);
#endif
