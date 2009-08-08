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
#include "gdebug.h"

static inline void add_alias(int type,char *alias,char *fsname)
{
	struct ht_elem *hte=ht_check(type,alias,NULL,0);
	if (hte) {
		free(ht_get_private_data(hte));
		if (*fsname==0)
			ht_tab_del(hte);
		else 
			ht_set_private_data(hte,strdup(fsname));
	} else {
		if (*fsname!=0)
			ht_tab_add(type,alias,strlen(alias),NULL,NULL,strdup(fsname));
	}
}

static char *rec_alias(int type,char *alias,int depth) {
	struct ht_elem *hte=ht_check(type,alias,NULL,0);
	if (hte) {
		if (depth > MAXSYMLINKS) 
			return alias;
		else
			return rec_alias(type,ht_get_private_data(hte),depth+1);
	} else
		return alias;
}

char *get_alias(int type,char *alias) {
	return rec_alias(type,alias,0);
}

int wrap_in_umservice(int sc_number,struct pcb *pc,
		    struct ht_elem *hte, sysfun um_syscall)
{
	char buf[PATH_MAX];
	switch (pc->sysargs[0]) {
		case ADD_SERVICE:
			if (umovestr(pc,pc->sysargs[1],PATH_MAX,buf) == 0) {
				int permanent=pc->sysargs[2];
				if (add_service(buf,permanent) < 0)
				{
					pc->retval=-1;
					pc->erno=errno;
				}
			} else {
				pc->retval= -1;
				pc->erno=EINVAL;
			}
			break;
		case DEL_SERVICE:
			if (umovestr(pc,pc->sysargs[1],PATH_MAX,buf) == 0) {
				if ((pc->retval=del_service(buf)) != 0) {
					pc->erno=errno;
				}
			}	else {
				pc->retval= -1;
				pc->erno=EINVAL;
			}
			break;
		case LIST_SERVICE:
			if (pc->sysargs[2]>PATH_MAX) pc->sysargs[2]=PATH_MAX;
			pc->retval=list_services(buf,pc->sysargs[2]);
			pc->erno=errno;
			if (pc->retval > 0)
				ustorestr(pc,pc->sysargs[1],pc->retval,buf);
			break;
		case NAME_SERVICE:
			if (umovestr(pc,pc->sysargs[1],PATH_MAX,buf) == 0) {
				if (pc->sysargs[3]>PATH_MAX) pc->sysargs[3]=PATH_MAX;
				/* buf can be reused both for name and description */
				pc->retval=name_service(buf,buf,pc->sysargs[3]);
				pc->erno=errno;
				if (pc->retval == 0)
					ustorestr(pc,pc->sysargs[2],pc->sysargs[3],buf);
				} else {
					pc->retval= -1;
					pc->erno=EINVAL;
				}
				break;
				case RECURSIVE_VIEWOS:
				if (pcb_newfork(pc) >= 0) {
				pc->retval=0;
				pc->erno = 0;
			} else {
				pc->retval= -1;
				pc->erno = ENOMEM;
			}
			break;
		case VIEWOS_GETINFO:
			{
				struct viewinfo vi;
				memset (&vi,0,sizeof(struct viewinfo));
				pcb_getviewinfo(pc,&vi);
				ustoren(pc,pc->sysargs[1],sizeof(struct viewinfo),&vi);
				pc->retval=0;
				pc->erno = 0;
			}
			break;
		case VIEWOS_SETVIEWNAME: 
			{
				char name[_UTSNAME_LENGTH];
				umovestr(pc,pc->sysargs[1],_UTSNAME_LENGTH,name);
				name[_UTSNAME_LENGTH-1]=0;
				pcb_setviewname(pc,name);
				pc->retval=0;
				pc->erno = 0;
			}
			break; 
		case VIEWOS_KILLALL: 
			killall(pc,pc->sysargs[1]);
			pc->retval=0;
			pc->erno = 0;
			break;
		case VIEWOS_ATTACH:
			pc->retval=capture_attach(pc,pc->sysargs[1]);
			if (pc->retval < 0) {
				pc->erno = - pc->retval;
				pc->retval = -1;
			}
			break;
		case VIEWOS_FSALIAS:
			{
				char fsalias[256];
				char fsname[256];
				umovestr(pc,pc->sysargs[1],256,fsalias);
				umovestr(pc,pc->sysargs[2],256,fsname);
				add_alias(CHECKFSALIAS,fsalias,fsname);
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

