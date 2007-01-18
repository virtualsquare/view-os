/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   um_time.c: time wrapper
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
#include <sys/time.h>
#include <time.h>
#include <errno.h>
#include <sys/timex.h>
#include <config.h>
#include "defs.h"
#include "services.h"
#include "utils.h"
#define umNULL ((int) NULL)

int wrap_in_time(int sc_number,struct pcb *pc,
		    service_t sercode, sysfun um_syscall)
{
	long addr=getargn(0,pc);
	if (addr != umNULL) {
		struct timeval tv;
		pc->retval = um_syscall(&tv,NULL);
		if (pc->retval >= 0) {
			pc->retval = tv.tv_sec;
			ustoren(pc,addr,4,&(pc->retval));
		}
	}
	else {
		pc->retval = -1;
		pc->erno = EINVAL;
	}
	return SC_FAKE;
}

int wrap_in_gettimeofday(int sc_number,struct pcb *pc,
		    service_t sercode, sysfun um_syscall)
{
	struct timeval tv;
	struct timezone tz;
	long tvp=getargn(0,pc);
	long tzp=getargn(1,pc);
	pc->retval = um_syscall(&tv,&tz);
	if (tvp != umNULL)
		ustoren(pc,tvp,sizeof(struct timeval),&tv);
	if (tzp != umNULL)
		ustoren(pc,tzp,sizeof(struct timezone),&tz);
	return SC_FAKE;
}

int wrap_in_settimeofday(int sc_number,struct pcb *pc,
		    service_t sercode, sysfun um_syscall)
{
	struct timeval tv,*tvx;
	struct timezone tz,*tzx;
	long tvp=getargn(0,pc);
	long tzp=getargn(1,pc);
	if (tvp != umNULL) {
		umoven(pc,tvp,sizeof(struct timeval),&tv);
		tvx=&tv;
	}
	else
		tvx=NULL;
	if (tzp != umNULL) {
		umoven(pc,tzp,sizeof(struct timezone),&tz);
		tzx=&tz;
	}
	else
		tzx=NULL;
	pc->retval = um_syscall(&tv,&tz);
	return SC_FAKE;
}

int wrap_in_adjtimex(int sc_number,struct pcb *pc,
		    service_t sercode, sysfun um_syscall)
{
	struct timex tmx;
	long tmxp=getargn(0,pc);
	if (tmxp != umNULL) {
		umoven(pc,tmxp,sizeof(struct timeval),&tmx);
		pc->retval=um_syscall(&tmx);
		if (pc->retval>= 0) 
			ustoren(pc,tmxp,sizeof(struct timeval),&tmx);
	} else {
		pc->retval = -1;
		pc->erno = EFAULT;
	}
	return SC_FAKE;
}

int wrap_in_clock_gettime(int sc_number,struct pcb *pc,
		    service_t sercode, sysfun um_syscall)
{
	clockid_t clk_id=getargn(0,pc);
	if (clk_id == CLOCK_REALTIME || clk_id == CLOCK_MONOTONIC) {
		long tss=getargn(1,pc);
		struct timespec ts;
		pc->retval=um_syscall(clk_id,&ts);
		if (pc->retval>= 0) 
			ustoren(pc,tss,sizeof(struct timespec),&ts);
		return SC_FAKE;
	}
	else
		return STD_BEHAVIOR;
}

int wrap_in_clock_settime(int sc_number,struct pcb *pc,
		    service_t sercode, sysfun um_syscall)
{
	clockid_t clk_id=getargn(0,pc);
	if (clk_id == CLOCK_REALTIME || clk_id == CLOCK_MONOTONIC) {
		long tss=getargn(1,pc);
		struct timespec ts;
		if (tss != umNULL)
			umoven(pc,tss,sizeof(struct timespec),&ts);
		pc->retval=um_syscall(clk_id,&ts);
		return SC_FAKE;
	}
	else
		return STD_BEHAVIOR;
}

int wrap_in_clock_getres(int sc_number,struct pcb *pc,
		    service_t sercode, sysfun um_syscall)
{
	clockid_t clk_id=getargn(0,pc);
	if (clk_id == CLOCK_REALTIME || clk_id == CLOCK_MONOTONIC) {
		long tss=getargn(1,pc);
		struct timespec ts;
		pc->retval=um_syscall(clk_id,&ts);
		if (pc->retval>= 0) 
			ustoren(pc,tss,sizeof(struct timespec),&ts);
		return SC_FAKE;
	}
	else
		return STD_BEHAVIOR;
}
