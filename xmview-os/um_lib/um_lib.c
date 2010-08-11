/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   library for user level access to um-ViewOS service mgmt
 *   
 *   Copyright 2005 Renzo Davoli University of Bologna - Italy
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
#include <sys/syscall.h>
#include <unistd.h>
#include <linux/sysctl.h>
#include <config.h>
#include <um_lib.h>

#ifdef OLDVIRSC
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
#else
static long int_virnsyscall(long virscno,int n,long arg1,long arg2,long arg3,long arg4,long arg5,long arg6) {
	long args[6]={arg1,arg2,arg3,arg4,arg5,arg6};
	return syscall(__NR_pivot_root,NULL,n,virscno,args);
}
#endif

long (*virnsyscall)() = int_virnsyscall;

int um_check_viewos(void)
{
	struct viewinfo info;
	int rv=um_view_getinfo(&info);
	return (rv==0);
}

int um_add_service(char *path,int permanent)
{
	return virsyscall3(VIRUMSERVICE,ADD_SERVICE,path,permanent);
}

int um_del_service(char *name)
{
	return virsyscall2(VIRUMSERVICE,DEL_SERVICE,name);
}

int um_list_service(char *buf, int len)
{
	return virsyscall3(VIRUMSERVICE,LIST_SERVICE,buf,len);
}

int um_name_service(char *name, char *buf, int len)
{
	return virsyscall4(VIRUMSERVICE,NAME_SERVICE,name,buf,len);
}

int um_view_getinfo(struct viewinfo *info)
{
	return virsyscall2(VIRUMSERVICE,VIEWOS_GETINFO,info);
}

int um_setviewname(char *name)
{
	return virsyscall2(VIRUMSERVICE,VIEWOS_SETVIEWNAME,name);
}

int um_killall(int signo)
{
	return virsyscall2(VIRUMSERVICE,VIEWOS_KILLALL,signo);
}

int um_attach(int pid)
{
	return virsyscall2(VIRUMSERVICE,VIEWOS_ATTACH,pid);
}

int um_fsalias(char *alias,char *filesystemname)
{
	  return virsyscall3(VIRUMSERVICE,VIEWOS_FSALIAS,alias,filesystemname);
}
