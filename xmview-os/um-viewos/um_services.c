/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   um_services: system call access to services mgmt
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
#include <assert.h>
#include <string.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <asm/ptrace.h>
#include <asm/unistd.h>
#include <linux/net.h>
#include <limits.h>
#include <dlfcn.h>
#include <errno.h>
#include "defs.h"
#include "services.h"
#include "utils.h"

#define ADD_SERVICE 0
#define DEL_SERVICE 1
#define MOV_SERVICE 2
#define LIST_SERVICE 3
#define NAME_SERVICE 4
#define LOCK_SERVICE 5

void *open_dllib(char *name)
{
	char *args;
	for (args=name;*args != 0 && *args != ',';args++)
		;
	if (*args == ',') {
		*args = 0;
		args++;
	}
	void *handle=dlopen(name,RTLD_LAZY|RTLD_GLOBAL);
	if (handle != NULL) {
		void (*pinit)() = dlsym(handle,"_um_mod_init");
		if (pinit != NULL) {
			pinit(args);
		}
	}
	return handle;
}

int dsys_um_service(int sc_number,int inout,struct pcb *pc)
{
	//printf("dsys_um_service pid %d call %d\n",pc->pid,sc_number);
	if (inout == IN) {
		int arg1,arg2,arg3;
		char buf[PATH_MAX];
		pc->arg0=getargn(0,pc);
		switch (pc->arg0) {
			case ADD_SERVICE:
				arg1=getargn(1,pc);
				arg2=getargn(2,pc);
				if (umovestr(pc->pid,arg2,PATH_MAX,buf) == 0) {
					//if (access(buf,R_OK) != 0) {
					//	pc->retval=-1;
					//	pc->erno=errno;
					//} else {
						void *handle=open_dllib(buf);
						if (handle==NULL) {
							pc->retval= -1;
							pc->erno=EINVAL;
						} else {
							if ((pc->retval=set_handle_new_service(handle,arg1)) != 0) {
								dlclose(handle);
								pc->erno=errno;
							}
						}
					//}
				} else {
					pc->retval= -1;
					pc->erno=ENOSYS;
				}
				break;
			case DEL_SERVICE:
				arg1=getargn(1,pc) & 0xff;
				pc->retval=del_service(arg1);
				{void * handle=get_handle_service(arg1);
					if (handle!= NULL) {
						dlclose(handle);
					}
				}
				pc->erno=errno;
				break;
			case MOV_SERVICE:
				arg1=getargn(1,pc) & 0xff;
				arg2=getargn(2,pc);
				pc->retval=mov_service(arg1,arg2);
				pc->erno=errno;
				break;
			case LIST_SERVICE:
				arg1=getargn(1,pc);
				arg2=getargn(2,pc);
				if (arg2>PATH_MAX) arg2=PATH_MAX;
				pc->retval=list_services((unsigned char *)buf,arg2);
				pc->erno=errno;
				if (pc->retval > 0)
					ustoren(pc->pid,arg1,pc->retval,buf);
				break;
			case NAME_SERVICE:
				arg1=getargn(1,pc) & 0xff;
				arg2=getargn(2,pc);
				arg3=getargn(3,pc);
				if (arg3>PATH_MAX) arg3=PATH_MAX;
				pc->retval=name_service(arg1,buf,arg3);
				pc->erno=errno;
				if (pc->retval == 0)
					ustorestr(pc->pid,arg2,arg3,buf);
				break;
			case LOCK_SERVICE:
				arg1=getargn(1,pc);
				if (arg1)
					invisible_services();
				else
					lock_services();
				pc->retval=0;
				pc->erno=0;
				break;
			default:
				pc->retval = -1;
				pc->erno = ENOSYS;
		}
		return SC_FAKE;
	} else {
		putrv(pc->retval,pc);
		puterrno(pc->erno,pc);
		return STD_BEHAVIOR;
	}
}



