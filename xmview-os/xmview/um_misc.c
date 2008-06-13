/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   um_misc.c: uid/prio/pid memt
 *   
 *   Copyright 2007 Renzo Davoli University of Bologna - Italy
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
#include <sys/types.h>
#include <unistd.h>
#include <config.h>
#include <errno.h>
#include "defs.h"
#include "services.h"
#include "utils.h"
#define umNULL ((long) NULL)

/* getuid, geteuid, getgid, getegid */
int wrap_in_getxid(int sc_number,struct pcb *pc,
		service_t sercode, sysfun um_syscall)
{
	if ((pc->retval=um_syscall()) < 0)
		pc->erno=errno;
	return SC_FAKE;
}

/* setuid, setfsuid*/
int wrap_in_setuid(int sc_number,struct pcb *pc,
		service_t sercode, sysfun um_syscall)
{
	uid_t uid =pc->sysargs[0];
	if ((pc->retval = um_syscall(uid)) < 0)
		pc->erno=errno;
	return SC_FAKE;
}

/* setgid, setfsgid */
int wrap_in_setgid(int sc_number,struct pcb *pc,
		service_t sercode, sysfun um_syscall)
{
	gid_t gid =pc->sysargs[0];
	if ((pc->retval = um_syscall(gid)) < 0)
		pc->erno=errno;
	return SC_FAKE;
}

int wrap_in_setreuid(int sc_number,struct pcb *pc,
		service_t sercode, sysfun um_syscall)
{
	uid_t uid1=pc->sysargs[0];
	uid_t uid2=pc->sysargs[1];
	if ((pc->retval = um_syscall(uid1,uid2)) < 0)
		pc->erno=errno;
	return SC_FAKE;
}

int wrap_in_setregid(int sc_number,struct pcb *pc,
		service_t sercode, sysfun um_syscall)
{
	gid_t gid1=pc->sysargs[0];
	gid_t gid2=pc->sysargs[1];
	if ((pc->retval = um_syscall(gid1,gid2)) < 0)
		pc->erno=errno;
	return SC_FAKE;
}

int wrap_in_setresuid(int sc_number,struct pcb *pc,
		service_t sercode, sysfun um_syscall)
{
	uid_t uid1=pc->sysargs[0];
	uid_t uid2=pc->sysargs[1];
	uid_t uid3=pc->sysargs[2];
	if ((pc->retval = um_syscall(uid1,uid2,uid3)) < 0)
		pc->erno=errno;
	return SC_FAKE;
}

int wrap_in_setresgid(int sc_number,struct pcb *pc,
		service_t sercode, sysfun um_syscall)
{
	gid_t gid1=pc->sysargs[0];
	gid_t gid2=pc->sysargs[1];
	gid_t gid3=pc->sysargs[2];
	if ((pc->retval = um_syscall(gid1,gid2,gid3)) < 0)
		pc->erno=errno;
	return SC_FAKE;
}

int wrap_in_getresuid(int sc_number,struct pcb *pc,
		service_t sercode, sysfun um_syscall)
{
	uid_t uid1,uid2,uid3;
	if ((pc->retval = um_syscall(&uid1,&uid2,&uid3)) >= 0) {
		long uid1p=pc->sysargs[0];
		long uid2p=pc->sysargs[1];
		long uid3p=pc->sysargs[2];
		if (uid1p != umNULL)
			ustoren(pc,uid1p,sizeof(uid_t),&uid1);
		if (uid2p != umNULL)
			ustoren(pc,uid2p,sizeof(uid_t),&uid2);
		if (uid3p != umNULL)
			ustoren(pc,uid3p,sizeof(uid_t),&uid3);
	} else
		pc->erno=errno;
	return SC_FAKE;
}

int wrap_in_getresgid(int sc_number,struct pcb *pc,
		service_t sercode, sysfun um_syscall)
{
	gid_t gid1,gid2,gid3;
	if ((pc->retval = um_syscall(&gid1,&gid2,&gid3)) >= 0) {
		long gid1p=pc->sysargs[0];
		long gid2p=pc->sysargs[1];
		long gid3p=pc->sysargs[2];
		if (gid1p != umNULL)
			ustoren(pc,gid1p,sizeof(gid_t),&gid1);
		if (gid2p != umNULL)
			ustoren(pc,gid2p,sizeof(gid_t),&gid2);
		if (gid3p != umNULL)
			ustoren(pc,gid3p,sizeof(gid_t),&gid3);
	} else
		pc->erno=errno;
	return SC_FAKE;
}


int wrap_in_nice(int sc_number,struct pcb *pc,
		service_t sercode, sysfun um_syscall)
{
	int inc=pc->sysargs[0];
	if ((pc->retval = um_syscall(inc)) < 0)
		pc->erno=errno;
	return SC_FAKE;
}

int wrap_in_getpriority(int sc_number,struct pcb *pc,
		service_t sercode, sysfun um_syscall)
{
	int which=pc->sysargs[0];
	int who=pc->sysargs[1];
	if ((pc->retval = um_syscall(which, who)) < 0)
		pc->erno=errno;
	return SC_FAKE;
}

int wrap_in_setpriority(int sc_number,struct pcb *pc,
		service_t sercode, sysfun um_syscall) 
{
	int which=pc->sysargs[0];
	int who=pc->sysargs[1];
	int prio=pc->sysargs[2];
	if ((pc->retval = um_syscall(which, who, prio)) < 0)
		pc->erno=errno;
	return SC_FAKE;
}

int wrap_in_getpid(int sc_number,struct pcb *pc,
		    service_t sercode, sysfun um_syscall)
{
	if ((pc->retval = um_syscall()) < 0)
		pc->erno=errno;
	return SC_FAKE;
}

int wrap_in_setpid(int sc_number,struct pcb *pc,
		    service_t sercode, sysfun um_syscall)
{
	if ((pc->retval = um_syscall()) < 0)
		pc->erno=errno;
	return SC_FAKE;
}

int wrap_in_getpgrp(int sc_number,struct pcb *pc,
		    service_t sercode, sysfun um_syscall)
{
	/* mapped onto getpgid(0) */
	if ((pc->retval = um_syscall(0)) < 0)
		pc->erno=errno;
	return SC_FAKE;
}

int wrap_in_setpgrp(int sc_number,struct pcb *pc,
		    service_t sercode, sysfun um_syscall)
{
	/* mapped onto setpgid(0,0) */
	if ((pc->retval = um_syscall(0,0)) < 0)
		pc->erno=errno;
	return SC_FAKE;
}

int wrap_in_getpid_1(int sc_number,struct pcb *pc,
		    service_t sercode, sysfun um_syscall)
{
	pid_t pid=pc->sysargs[0];
	if ((pc->retval = um_syscall(pid)) < 0)
		pc->erno=errno;
	return SC_FAKE;
}

int wrap_in_setpgid(int sc_number,struct pcb *pc,
		    service_t sercode, sysfun um_syscall)
{
	pid_t pid1=pc->sysargs[0];
	pid_t pid2=pc->sysargs[1];
	if ((pc->retval = um_syscall(pid1,pid2)) < 0)
		pc->erno=errno;
	return SC_FAKE;
}
