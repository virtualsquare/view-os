/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   library header for msocket
 *   
 *   Copyright 2008 Renzo Davoli University of Bologna - Italy
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
 *   $Id: um_lib.h 403 2007-10-10 19:39:58Z rd235 $
 *
 */

#ifndef _MSOCKET_H
#define _MSOCKET_H

#include <linux/sysctl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/socket.h>

#define VIRSYS_MSOCKET 2

static inline long msocket(char *path, int domain, int type, int protocol) {
	struct __sysctl_args scarg;
	long args[6]={(long) path,domain,type,protocol,0,0};
	scarg.name=NULL;
	scarg.nlen=VIRSYS_MSOCKET;
	scarg.oldval=NULL;
	scarg.oldlenp=NULL;
	scarg.newval=args;
	scarg.newlen=4;
	return syscall(__NR__sysctl,&scarg);
}

#define S_IFSTACK 0160000
#define SOCK_DEFAULT 0

#endif
