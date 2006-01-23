/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   library for user level access to um-ViewOS service mgmt
 *   
 *   Copyright 2005 Renzo Davoli University of Bologna - Italy
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
#include <sys/syscall.h>
#include <unistd.h>


#define BASEUSB 4096

#if defined(__i386__)
static short _i386_sc_remap[]={251,222,17,31,32,35,44,53,56,58,98,112,127,130,137,167};
#define UMSERVICE (_i386_sc_remap[0])
#elif defined(__powerpc__) && !defined(__powerpc64)
#define UMSERVICE  BASEUSB+0
#elif defined(__x86_64__)
// ATTENTION: this define is only for compile correctly, it will not work, if 
// it's used in any of um_cmd
#define UMSERVICE 0
#endif

#define ADD_SERVICE 0
#define DEL_SERVICE 1
#define MOV_SERVICE 2
#define LIST_SERVICE 3
#define NAME_SERVICE 4
#define LOCK_SERVICE 5

int um_add_service(int position,char *path)
{
	return syscall(UMSERVICE,ADD_SERVICE,position,path);
}

int um_del_service(int code)
{
	return syscall(UMSERVICE,DEL_SERVICE,code);
}

int um_mov_service(int code, int position)
{
	return syscall(UMSERVICE,MOV_SERVICE,code,position);
}

int um_list_service(char *buf, int len)
{
	return syscall(UMSERVICE,LIST_SERVICE,buf,len);
}


int um_name_service(int code, char *buf, int len)
{
	return syscall(UMSERVICE,NAME_SERVICE,code,buf,len);
}

int um_lock_service(int invisible)
{
	return syscall(UMSERVICE,LOCK_SERVICE,invisible);
}
