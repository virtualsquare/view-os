/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   
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
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <config.h>
#include "module.h"
#include "gdebug.h"

static struct service s;
VIEWOS_SERVICE(s)

static long addproc(int id, int ppid, int max)
{
	fprintf(stderr, "testmodule add proc %d %d %d\n", id, ppid, max);
	GDEBUG(3, "new process id %d  pid %d   max %d",id,um_mod_getpid(),max);
	return 0;
}

static long delproc(int id)
{
	fprintf(stderr, "testmodule del proc %d\n", id);
	GDEBUG(3, "terminated process id %d  pid %d",id,um_mod_getpid());
	return 0;
}

static long addmodule(char *sender)
{
	fprintf(stderr, "testmodule add module %s\n", sender);
	GDEBUG(3, "new module loaded. %s", sender);
	return 0;
}

static long delmodule(char *sender)
{
	fprintf(stderr, "testmodule del module %s\n", sender);
	GDEBUG(3, "module %s removed", sender);
	return 0;
}


static long ctl(int type, char *sender, va_list ap)
{
	int id, ppid, max;
	char* arg;

	if (type & MC_USER)
	{
		GDEBUG(3, "received user ctl. sender sercode: 0x%02x, ctl: %d\n",
				MC_USERCTL_SERCODE(type), MC_USERCTL_CTL(type));
		
		switch (MC_USERCTL_CTL(type))
		{
			case 42:
				arg = va_arg(ap, char*);
				printk(KERN_NOTICE "service %s is managing open(\"%s\", ...)",
						sender, arg);
				return 0;
			default:
				return -1;
		}
	}
	else
		switch(type)
		{
			case MC_PROC | MC_ADD:
				id = va_arg(ap, int);
				ppid = va_arg(ap, int);
				max = va_arg(ap, int);
				return addproc(id, ppid, max);

			case MC_PROC | MC_REM:
				id = va_arg(ap, int);
				return delproc(id);

			case MC_MODULE | MC_ADD:
				return addmodule(sender);

			case MC_MODULE | MC_REM:
				return delmodule(sender);

			default:
				return -1;
		}
}


static void
__attribute__ ((constructor))
init (void)
{
	printk(KERN_NOTICE "testmodule init");
	fprintf(stderr, "testmodule init\n");
	s.name="test";
	s.description="Test Module";
	s.syscall=(sysfun *)calloc(scmap_scmapsize,sizeof(sysfun));
	s.socket=(sysfun *)calloc(scmap_sockmapsize,sizeof(sysfun));
	s.ctl = ctl;

	MCH_ZERO(&s.ctlhs);
	MCH_SET(MC_PROC, &s.ctlhs);
	MCH_SET(MC_MODULE, &s.ctlhs);
}

static void
__attribute__ ((destructor))
fini (void)
{
	free(s.syscall);
	free(s.socket);
	printk(KERN_NOTICE "testmodule fini");
}
