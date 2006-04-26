/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   nested_headers: headers of all nesting code
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
#ifndef __NESTED_HEADERS_H
#define  __NESTED_HEADERS_H
#if 0
#include<unistd.h>
#include<sys/syscall.h>
#define read(f,b,c) syscall(__NR_read,(f),(b),(c))
#define write(f,b,c) syscall(__NR_write,(f),(b),(c))
#define select(n,r,w,e,t) syscall(__NR__newselect,(n),(r),(w),(e),(t))
#define waitpid(p,s,o) syscall(__NR_waitpid,(p),(s),(o))
#endif

// nested_core stuff
long nested_syscall(int syscallno,...);
//extern epoch_t saved_epoch;

// nested_syscalls stuff...
#ifdef NESTING_TEST
extern unsigned char nested_inside_mod;
extern unsigned char nested_service_code;
#define enter_module(CODE) ({ nested_inside_mod=1; nested_service_code=(CODE);})
#define exit_module() ({ nested_inside_mod=0; nested_service_code=UM_NONE;})
#else
#define enter_module(CODE) 
#define exit_module() 
#endif


#endif //__NESTED_HEADERS_H
