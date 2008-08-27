/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   uid16to32.h: remap for 16to32 functions.
 *   
 *   Copyright 2006 Renzo Davoli University of Bologna - Italy
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
 *   $Id$
 *
 */   
#ifndef _UID16TO32_H
#define _UID16TO32_H

#define id16to32(id) ((id) == (unsigned short int) -1 ? (unsigned int) -1 : (id))
#define id32to16(id) ((id) == (unsigned int) -1 ? (unsigned short int) -1 : (id))

#ifndef __NR_chown32
#define __NR_chown32 __NR_chown
#endif
#ifndef __NR_lchown32
#define __NR_lchown32 __NR_lchown
#endif
#ifndef __NR_fchown32
#define __NR_fchown32 __NR_fchown
#endif
#ifndef __NR_getuid32
#define __NR_getuid32 __NR_getuid
#endif
#ifndef __NR_getgid32
#define __NR_getgid32 __NR_getgid
#endif
#ifndef __NR_geteuid32
#define __NR_geteuid32 __NR_geteuid
#endif
#ifndef __NR_setreuid32
#define __NR_setreuid32 __NR_setreuid
#endif
#ifndef __NR_setregid32
#define __NR_setregid32 __NR_setregid
#endif
#ifndef __NR_getgroups32
#define __NR_getgroups32 __NR_getgroups
#endif
#ifndef __NR_getresuid32
#define __NR_getresuid32 __NR_getresuid
#endif
#ifndef __NR_getresgid32
#define __NR_getresgid32 __NR_getresgid
#endif
#ifndef __NR_setresuid32
#define __NR_setresuid32 __NR_setresuid
#endif
#ifndef __NR_setresgid32
#define __NR_setresgid32 __NR_setresgid
#endif
#ifndef __NR_setuid32
#define __NR_setuid32 __NR_setuid
#endif
#ifndef __NR_setgid32
#define __NR_setgid32 __NR_setgid
#endif
#ifndef __NR_setfsuid32
#define __NR_setfsuid32 __NR_setfsuid
#endif
#ifndef __NR_setfsuid32
#define __NR_setfsuid32 __NR_setfsuid
#endif

#endif
