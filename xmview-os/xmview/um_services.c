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
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/utsname.h>
#include <sys/param.h>
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
#include "hashtab.h"
#include "capture.h"
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

static inline void fs_add_alias(char *fsalias,char *fsname)
{
	struct ht_elem *hte=ht_check(CHECKFSALIAS,fsalias,NULL,0);
	if (hte) {
		free(hte->private_data);
		if (*fsname==0)
			ht_tab_del(hte);
		else 
			hte->private_data=strdup(fsname);
	} else {
		if (*fsname!=0)
			ht_tab_add(CHECKFSALIAS,fsalias,strlen(fsalias),NULL,NULL,strdup(fsname));
	}
}

static char *rec_fs_alias(char *fsalias,int depth) {
	struct ht_elem *hte=ht_check(CHECKFSALIAS,fsalias,NULL,0);
	if (hte) {
		if (depth > MAXSYMLINKS) 
			return fsalias;
		else
			return rec_fs_alias(hte->private_data,depth+1);
	} else
		return fsalias;
}

char *fs_alias(char *fsalias) {
	return rec_fs_alias(fsalias,0);
}

int wrap_in_umservice(int sc_number,struct pcb *pc,
		    struct ht_elem *hte, sysfun um_syscall)
{
	char buf[PATH_MAX];
	switch (pc->sysargs[0]) {
		case ADD_SERVICE:
			if (umovestr(pc,pc->sysargs[2],PATH_MAX,buf) == 0) {
				//if (access(buf,R_OK) != 0) {
				//	pc->retval=-1;
				//	pc->erno=errno;
				//} else {
				void *handle=open_dllib(buf);
				if (handle==NULL) {
					pc->retval= -1;
					pc->erno=EINVAL;
				} else {
					if ((pc->retval=set_handle_new_service(handle,pc->sysargs[1])) != 0) {
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
			pc->retval=del_service(pc->sysargs[1] & 0xff);
			{void * handle=get_handle_service(pc->sysargs[1] & 0xff);
				if (handle!= NULL) {
					dlclose(handle);
				}
			}
			pc->erno=errno;
			break;
		case MOV_SERVICE:
			pc->retval=mov_service(pc->sysargs[1] & 0xff,pc->sysargs[2]);
			pc->erno=errno;
			break;
		case LIST_SERVICE:
			if (pc->sysargs[2]>PATH_MAX) pc->sysargs[2]=PATH_MAX;
			pc->retval=list_services((unsigned char *)buf,pc->sysargs[2]);
			pc->erno=errno;
			if (pc->retval > 0)
				ustoren(pc,pc->sysargs[1],pc->retval,buf);
			break;
		case NAME_SERVICE:
			if (pc->sysargs[3]>PATH_MAX) pc->sysargs[3]=PATH_MAX;
			pc->retval=name_service(pc->sysargs[1] & 0xff,buf,pc->sysargs[3]);
			pc->erno=errno;
			if (pc->retval == 0)
				ustorestr(pc,pc->sysargs[2],pc->sysargs[3],buf);
			break;
		case LOCK_SERVICE:
			if (pc->sysargs[1])
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
				ustoren(pc,pc->sysargs[1],sizeof(struct viewinfo),&vi);
				pc->retval=0;
				pc->erno = 0;
			}
			break;
		case UMVIEW_SETVIEWNAME: 
			{
				char name[_UTSNAME_LENGTH];
				umovestr(pc,pc->sysargs[1],_UTSNAME_LENGTH,name);
				name[_UTSNAME_LENGTH-1]=0;
				pcb_setviewname(pc,name);
				pc->retval=0;
				pc->erno = 0;
			}
			break; 
		case UMVIEW_KILLALL: 
			killall(pc,pc->sysargs[1]);
			pc->retval=0;
			pc->erno = 0;
			break;
		case UMVIEW_ATTACH:
			pc->retval=capture_attach(pc,pc->sysargs[1]);
			if (pc->retval < 0) {
				pc->erno = - pc->retval;
				pc->retval = -1;
			}
			break;
		case UMVIEW_FSALIAS:
			{
				char fsalias[256];
				char fsname[256];
				umovestr(pc,pc->sysargs[1],256,fsalias);
				umovestr(pc,pc->sysargs[2],256,fsname);
				fs_add_alias(fsalias,fsname);
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
	return SC_MODICALL;
}

