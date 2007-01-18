/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   um_uname.c: system id syscall
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
#include <sys/utsname.h>
#include <linux/utsname.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include <alloca.h>
#include <config.h>
#include "defs.h"
#include "services.h"
#include "utils.h"
#define umNULL ((int) NULL)

int wrap_in_uname(int sc_number,struct pcb *pc,
		    service_t sercode, sysfun um_syscall)
{
	long addr=getargn(0,pc);
	if (addr != umNULL) {
		struct new_utsname buf;
		pc->retval = um_syscall(&buf);
		if (pc->retval >= 0) {
			if(sc_number == __NR_uname)
				ustoren(pc,addr,sizeof(struct new_utsname),&buf);
			else if (sc_number == __NR_olduname)
				ustoren(pc,addr,sizeof(struct old_utsname),&buf);
			else { /*oldolduname*/
				struct oldold_utsname oldbuf;
				memcpy(&oldbuf.sysname,&buf.sysname,8);
				memcpy(&oldbuf.nodename,&buf.nodename,8);
				memcpy(&oldbuf.release,&buf.release,8);
				memcpy(&oldbuf.version,&buf.version,8);
				memcpy(&oldbuf.machine,&buf.machine,8);
				oldbuf.sysname[8]= oldbuf.nodename[8]= oldbuf.release[8]=
					oldbuf.version[8]= oldbuf.machine[8]=0; 
				ustoren(pc,addr,sizeof(struct oldold_utsname),&oldbuf);
			}
		}
	} else { 
		pc->retval = -1;
		pc->erno = EINVAL;
	}
	return SC_FAKE;
}

int wrap_in_gethostname(int sc_number,struct pcb *pc,
		service_t sercode, sysfun um_syscall)
{
	long addr=getargn(0,pc);
	if (addr != umNULL) {
		long size=getargn(1,pc);
		if (size > 0 || size <= HOST_NAME_MAX) {
			char *name;
			struct new_utsname buf;
			pc->retval = um_syscall(&buf);
			if (pc->retval) {
				if (sc_number == __NR_gethostname) 
					name=buf.nodename;
				else /* getdomainname */
					name=buf.domainname;
				if (strlen(name)+1 > size) {
					pc->retval = -1;
					pc->erno=EINVAL;
				} else
					ustorestr(pc,addr,size,name);
			}
		} else {
			pc->retval = -1;
			pc->erno = EINVAL;
		}
	} else { 
		pc->retval = -1;
		pc->erno = EFAULT;
	}
	return SC_FAKE;
}

int wrap_in_sethostname(int sc_number,struct pcb *pc,
		service_t sercode, sysfun um_syscall)
{
	long addr=getargn(0,pc);
	if (addr != umNULL) {
		long size=getargn(1,pc);
		if (size > 0 || size <= HOST_NAME_MAX) {
			char *name=alloca(size);
			umovestr(pc,addr,size,name);
			pc->retval = um_syscall(name,size);
		} else {
			pc->retval = -1;
			pc->erno = EINVAL;
		}
	} else { 
		pc->retval = -1;
		pc->erno = EFAULT;
	}
	return SC_FAKE;
}

