/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   real_syscalls: MACRO lib to avoid pure_libc mgmt of internal umview calls
 *   
 *   Copyright 2005 Andrea Gasparini University of Bologna - Italy
 *   
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 *   $Id$
 *
 */
#ifndef __REAL_SYSCALLS_H
#define  __REAL_SYSCALLS_H

#include<unistd.h>
#include<sys/syscall.h>
#define read(f,b,c) syscall(__NR_read,(f),(b),(c))
#define write(f,b,c) syscall(__NR_write,(f),(b),(c))
#define select(n,r,w,e,t) syscall(__NR__newselect,(n),(r),(w),(e),(t))
#define waitpid(p,s,o) syscall(__NR_waitpid,(p),(s),(o))
#define lstat64(p,b) syscall(__NR_lstat64,(p),(b))
#define readlink(p,b,sz) syscall(__NR_readlink,(p),(b),(sz))
#define execve(f,a,e) syscall(__NR_execve,(f),(a),(e))
#define fcntl(f,c,a) syscall(__NR_fcntl,(f),(c),(a))
#define umask(m) syscall(__NR_umask,(m))
#define pipe(v) syscall(__NR_pipe,(v))
#define access(p,m) syscall(__NR_access,(p),(m))

#endif //__REAL_SYSCALLS_H
