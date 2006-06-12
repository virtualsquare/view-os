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
#include <linux/sysctl.h>

#define VIRUMSERVICE 1

#define ADD_SERVICE 0
#define DEL_SERVICE 1
#define MOV_SERVICE 2
#define LIST_SERVICE 3
#define NAME_SERVICE 4
#define LOCK_SERVICE 5


static long int_virnsyscall(long virscno,int n,long arg1,long arg2,long arg3,long arg4,long arg5,long arg6) {
	struct __sysctl_args scarg;
	long args[6]={arg1,arg2,arg3,arg4,arg5,arg6};
	scarg.name=NULL;
	scarg.nlen=virscno;
	scarg.oldval=NULL;
	scarg.oldlenp=NULL;
	scarg.newval=args;
	scarg.newlen=n;
	return syscall(__NR__sysctl,&scarg);
}

long (*virnsyscall)() = int_virnsyscall;
#define virsyscall2(virscno,a1,a2) virnsyscall(virscno,2,(a1),(a2),0,0,0,0);
#define virsyscall3(virscno,a1,a2,a3) virnsyscall(virscno,3,(a1),(a2),(a3),0,0,0);
#define virsyscall4(virscno,a1,a2,a3,a4) virnsyscall(virscno,4,(a1),(a2),(a3),(a4),0,0);


int um_add_service(int position,char *path)
{
	return virsyscall3(VIRUMSERVICE,ADD_SERVICE,position,path);
}

int um_del_service(int code)
{
	return virsyscall2(VIRUMSERVICE,DEL_SERVICE,code);
}

int um_mov_service(int code, int position)
{
	return virsyscall3(VIRUMSERVICE,MOV_SERVICE,code,position);
}

int um_list_service(char *buf, int len)
{
	return virsyscall3(VIRUMSERVICE,LIST_SERVICE,buf,len);
}

int um_name_service(int code, char *buf, int len)
{
	return virsyscall4(VIRUMSERVICE,NAME_SERVICE,code,buf,len);
}

int um_lock_service(int invisible)
{
	return virsyscall2(VIRUMSERVICE,LOCK_SERVICE,invisible);
}
