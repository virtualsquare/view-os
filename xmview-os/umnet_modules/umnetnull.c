/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   UMMISCNONE: Virtual Null Network
 *    Copyright (C) 2008  Renzo Davoli <renzo@cs.unibo.it>
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include "umnet.h"

int umnetnull_msocket (int domain, int type, int protocol, 
		struct umnet *nethandle){
	errno=EAFNOSUPPORT;
	return -1;
}

int umnetnull_init (char *source, char *mountpoint, unsigned long flags, char *args, struct umnet *nethandle) {
	return 0;
}

int umnetnull_fini (struct umnet *nethandle){
	return 0;
}

struct umnet_operations umnet_ops={
  .msocket=umnetnull_msocket,
  .init=umnetnull_init,
  .fini=umnetnull_fini,
};
