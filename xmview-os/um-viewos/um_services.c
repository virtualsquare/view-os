/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   um_services: system call access to services mgmt
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
#include <assert.h>
#include <string.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/utsname.h>
#include <asm/ptrace.h>
#include <asm/unistd.h>
#include <linux/net.h>
#include <limits.h>
#include <dlfcn.h>
#include <pthread.h>
#include <errno.h>
#include <config.h>
#include "defs.h"
#include "sctab.h"
#include "services.h"
#include "utils.h"
#include "modutils.h"
#include "gdebug.h"

void *open_dllib(char *name)
{
	char *args;
	void *handle;
	for (args=name;*args != 0 && *args != ',';args++)
		;
	if (*args == ',') {
		*args = 0;
		args++;
	}
	handle=openmodule(name,RTLD_LAZY|RTLD_GLOBAL);
	if (handle != NULL) {
		void (*pinit)() = dlsym(handle,"_um_mod_init");
		if (pinit != NULL) {
			pinit(args);
		}
	}
	return handle;
}

#if 0
// umview internal use only, not in syscall management.
// because it doesn't update pc->errno
// FIXME: should be moved from this file.
int um_add_service(char* path,int position){
	void *handle=open_dllib(path);
	if (handle==NULL) {
			return  -1;
	} else {
			if ( set_handle_new_service(handle,position) != 0) {
					dlclose(handle);
			}
	}
	return 0;
}
#endif

int wrap_in_umservice(int sc_number,struct pcb *pc,
		    service_t sercode, sysfun um_syscall)
{
	char buf[PATH_MAX];
	switch (pc->sockregs[0]) {
		case ADD_SERVICE:
			if (umovestr(pc,pc->sockregs[2],PATH_MAX,buf) == 0) {
				//if (access(buf,R_OK) != 0) {
				//	pc->retval=-1;
				//	pc->erno=errno;
				//} else {
				void *handle=open_dllib(buf);
				if (handle==NULL) {
					pc->retval= -1;
					pc->erno=EINVAL;
				} else {
					if ((pc->retval=set_handle_new_service(handle,pc->sockregs[1])) != 0) {
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
			pc->retval=del_service(pc->sockregs[1] & 0xff);
			{void * handle=get_handle_service(pc->sockregs[1] & 0xff);
				if (handle!= NULL) {
					dlclose(handle);
				}
			}
			pc->erno=errno;
			break;
		case MOV_SERVICE:
			pc->retval=mov_service(pc->sockregs[1] & 0xff,pc->sockregs[2]);
			pc->erno=errno;
			break;
		case LIST_SERVICE:
			if (pc->sockregs[2]>PATH_MAX) pc->sockregs[2]=PATH_MAX;
			pc->retval=list_services((unsigned char *)buf,pc->sockregs[2]);
			pc->erno=errno;
			if (pc->retval > 0)
				ustoren(pc,pc->sockregs[1],pc->retval,buf);
			break;
		case NAME_SERVICE:
			if (pc->sockregs[3]>PATH_MAX) pc->sockregs[3]=PATH_MAX;
			pc->retval=name_service(pc->sockregs[1] & 0xff,buf,pc->sockregs[3]);
			pc->erno=errno;
			if (pc->retval == 0)
				ustorestr(pc,pc->sockregs[2],pc->sockregs[3],buf);
			break;
		case LOCK_SERVICE:
			if (pc->sockregs[1])
				invisible_services();
			else
				lock_services();
			pc->retval=0;
			pc->erno=0;
			break;
		case RECURSIVE_UMVIEW:
			if (pcb_newfork(pc) >= 0) {
				pc->retval=0;
				pc->erno = 0;
			} else {
				pc->retval= -1;
				pc->erno = ENOMEM;
			}
			break;
		case UMVIEW_GETINFO:
			{
				struct viewinfo vi;
				memset (&vi,0,sizeof(struct viewinfo));
				pcb_getviewinfo(pc,&vi);
				ustoren(pc,pc->sockregs[1],sizeof(struct viewinfo),&vi);
				pc->retval=0;
				pc->erno = 0;
			}
			break;
		case UMVIEW_SETVIEWNAME: 
			{
				char name[_UTSNAME_LENGTH];
				umovestr(pc,pc->sockregs[1],_UTSNAME_LENGTH,name);
				name[_UTSNAME_LENGTH]=0;
				pcb_setviewname(pc,name);
				pc->retval=0;
				pc->erno = 0;
			}
			break;
		default:
			pc->retval = -1;
			pc->erno = ENOSYS;
	}
	return SC_FAKE;
}

int wrap_out_umservice(int sc_number,struct pcb *pc)
{
	putrv(pc->retval,pc);
	puterrno(pc->erno,pc);
	return STD_BEHAVIOR;
}

