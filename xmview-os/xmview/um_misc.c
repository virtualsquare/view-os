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
#include <linux/limits.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>
#include <config.h>
#include <errno.h>
#include <sys/capability.h>
#include <errno.h>
#include "defs.h"
#include "services.h"
#include "hashtab.h"
#include "sctab.h"
#include "utils.h"
#include "capture.h"
#include "uid16to32.h"
#define umNULL ((long) NULL)

static int checksecureuid(struct pcb *pc, uid_t ruid, uid_t euid, uid_t suid, uid_t fsuid)
{
	if (capcheck(CAP_SETUID,pc)) {
		if ((ruid != -1 && ruid != pc->ruid && ruid != pc->suid) ||
				(euid != -1 && euid != pc->ruid && euid != pc->euid && euid != pc->suid) ||
				(suid != -1 && suid != pc->suid) ||
				(fsuid != -1 && fsuid != pc->fsuid))
			return -1;
		else
			return 0;
	} else 
		return 0;
}

static int checksecuregid(struct pcb *pc, gid_t rgid, gid_t egid, gid_t sgid, gid_t fsgid)
{
	if (capcheck(CAP_SETGID,pc))
		return 0;
	else {
		if ((rgid != -1 && rgid != pc->rgid && rgid != pc->sgid) ||
				(egid != -1 && egid != pc->rgid && egid != pc->egid && egid != pc->sgid) ||
				(sgid != -1 && sgid != pc->sgid) ||
				(fsgid != -1 && fsgid != pc->fsgid))
			return -1;
		else
			return 0;
	}
}

/* getuid, geteuid, getgid, getegid */
int wrap_in_getxid(int sc_number,struct pcb *pc,
		struct ht_elem *hte, sysfun um_syscall)
{
	if (hte != NULL) {
		int rv=0;
		switch (sc_number) {
			case __NR_getuid:
#if __NR_getuid != __NR_getuid32
			case __NR_getuid32:
#endif
			case __NR_getgid: 
#if __NR_getgid != __NR_getgid32
			case __NR_getgid32: 
#endif
				rv=um_syscall(&(pc->retval),NULL,NULL); break;
			case __NR_geteuid: 
#if __NR_geteuid != __NR_geteuid32
			case __NR_geteuid32: 
#endif
			case __NR_getegid: 
#if __NR_getegid != __NR_getegid32
			case __NR_getegid32: 
#endif
				rv=um_syscall(NULL,&(pc->retval),NULL); break;
		}
		if (rv < 0) {
			pc->retval=-1;
			pc->erno=errno;
		}
	} else {
		switch (sc_number) {
			case __NR_getuid:
#if __NR_getuid != __NR_getuid32
			case __NR_getuid32:
#endif
			 	pc->retval=pc->ruid; break;
			case __NR_getgid: 
#if __NR_getgid != __NR_getgid32
			case __NR_getgid32: 
#endif
				pc->retval=pc->rgid; break;
			case __NR_geteuid: 
#if __NR_geteuid != __NR_geteuid32
			case __NR_geteuid32: 
#endif
				pc->retval=pc->euid; break;
			case __NR_getegid: 
#if __NR_getegid != __NR_getegid32
			case __NR_getegid32: 
#endif
				pc->retval=pc->egid; break;
		}
		/*printk("%d->%d\n",sc_number,pc->retval);*/
		pc->erno=0;
	}
	return SC_FAKE;
}

int wrap_in_getxid16(int sc_number,struct pcb *pc,
		struct ht_elem *hte, sysfun um_syscall)
{
	wrap_in_getxid(sc_number,pc,hte,um_syscall);
	pc->retval=id32to16(pc->retval);
	return SC_FAKE;
}

/* setuid, setfsuid*/
int wrap_in_setuid(int sc_number,struct pcb *pc,
		struct ht_elem *hte, sysfun um_syscall)
{
	uid_t uid=pc->sysargs[0];
	if (sc_number != __NR_setuid32 &&
			sc_number != __NR_setfsuid32)
		uid=id16to32(uid);
	if (secure) {
		int rv=0;
		switch (sc_number) {
			case __NR_setuid:
#if __NR_setuid != __NR_setuid32
			case __NR_setuid32:
#endif
				rv=checksecureuid(pc,uid,-1,-1,-1);
				break;
			case __NR_setfsuid:
#if __NR_setfsuid != __NR_setfsuid32
			case __NR_setfsuid32:
#endif
				rv=checksecureuid(pc,-1,-1,-1,uid);
		}
		if (rv) {
			pc->retval=-1;
			pc->erno=EPERM;
			return SC_FAKE;
		}
	}
	if (hte != NULL) {
		switch (sc_number) {
			case __NR_setuid:
#if __NR_setuid != __NR_setuid32
			case __NR_setuid32:
#endif
				pc->retval=um_syscall(uid,-1,-1);
				break;
			case __NR_setfsuid:
#if __NR_setfsuid != __NR_setfsuid32
			case __NR_setfsuid32:
#endif
				pc->retval = um_syscall(uid);
				break;
		}
		if (pc->retval < 0)
			pc->erno=errno;
	} else {
		switch (sc_number) {
			case __NR_setuid:
#if __NR_setuid != __NR_setuid32
			case __NR_setuid32:
#endif
				if (pc->euid == 0) 
					pc->ruid=pc->euid=pc->fsuid=uid;
				else
					pc->euid=pc->fsuid=uid;
				break;
			case __NR_setfsuid:
#if __NR_setfsuid != __NR_setfsuid32
			case __NR_setfsuid32:
#endif
				pc->fsuid=uid;
				break;
		}
		pc->erno=pc->retval=0;
	}
	return SC_FAKE;
}

/* setgid, setfsgid */
int wrap_in_setgid(int sc_number,struct pcb *pc,
		struct ht_elem *hte, sysfun um_syscall)
{
	gid_t gid=pc->sysargs[0];
	if (sc_number != __NR_setgid32 &&
			sc_number != __NR_setfsgid32)
		gid=id16to32(gid);
	if (secure) {
		int rv=0;
		switch (sc_number) {
			case __NR_setgid:
#if __NR_setgid != __NR_setgid32
			case __NR_setgid32:
#endif
				rv=checksecuregid(pc,gid,-1,-1,-1);
				break;
			case __NR_setfsgid:
#if __NR_setfsgid != __NR_setfsgid32
			case __NR_setfsgid32:
#endif
				rv=checksecuregid(pc,-1,-1,-1,gid);
		}
		if (rv) {
			pc->retval=-1;
			pc->erno=EPERM;
			return SC_FAKE;
		}
	}
	if (hte != NULL) {
		switch (sc_number) {
			case __NR_setgid:
#if __NR_setgid != __NR_setgid32
			case __NR_setgid32:
#endif
				pc->retval=um_syscall(gid,-1,-1);
				break;
			case __NR_setfsgid:
#if __NR_setfsgid != __NR_setfsgid32
			case __NR_setfsgid32:
#endif
				(pc->retval = um_syscall(gid));
				break;
		}
		if (pc->retval < 0)
			pc->erno=errno;
	} else {
		switch (sc_number) {
			case __NR_setgid:
#if __NR_setgid != __NR_setgid32
			case __NR_setgid32:
#endif
				if (pc->egid == 0)
					pc->rgid=pc->egid=pc->fsgid=gid;
				else
					pc->egid=pc->fsgid=gid;
				break;
			case __NR_setfsgid:
#if __NR_setfsgid != __NR_setfsgid32
			case __NR_setfsgid32:
#endif
				pc->fsgid=gid;
				break;
		}
		pc->erno=pc->retval=0;
	}
	return SC_FAKE;
}

int wrap_in_setreuid(int sc_number,struct pcb *pc,
		struct ht_elem *hte, sysfun um_syscall)
{
	uid_t uid1=pc->sysargs[0];
	uid_t uid2=pc->sysargs[1];
	if (sc_number != __NR_setreuid32) {
		uid1=id16to32(uid1);
		uid2=id16to32(uid2);
	}
	if (secure && checksecureuid(pc,uid1,uid2,-1,-1)) {
			pc->retval=-1;
			pc->erno=EPERM;
			return SC_FAKE;
	}
	if (hte != NULL) {
		if ((pc->retval = um_syscall(uid1,uid2,-1)) < 0)
			pc->erno=errno;
	} else {
		if (uid1 != -1) pc->ruid=uid1;
		if (uid2 != -1) pc->euid=pc->fsuid=uid2;
		pc->erno=pc->retval=0;
	}
	return SC_FAKE;
}

int wrap_in_setregid(int sc_number,struct pcb *pc,
		struct ht_elem *hte, sysfun um_syscall)
{
	gid_t gid1=pc->sysargs[0];
	gid_t gid2=pc->sysargs[1];
	if (sc_number != __NR_setregid32) {
		gid1=id16to32(gid1);
		gid2=id16to32(gid2);
	}
	if (secure && checksecuregid(pc,gid1,gid2,-1,-1)) {
			pc->retval=-1;
			pc->erno=EPERM;
			return SC_FAKE;
	}
	if (hte != NULL) {
		if ((pc->retval = um_syscall(gid1,gid2,-1)) < 0)
			pc->erno=errno;
	} else {
		if (gid1 != -1) pc->rgid=gid1;
		if (gid2 != -1) pc->egid=pc->fsgid=gid2;
		pc->erno=pc->retval=0;
	}
	return SC_FAKE;
}

int wrap_in_setresuid(int sc_number,struct pcb *pc,
		struct ht_elem *hte, sysfun um_syscall)
{
	uid_t uid1=pc->sysargs[0];
	uid_t uid2=pc->sysargs[1];
	uid_t uid3=pc->sysargs[2];
	if (sc_number != __NR_setresuid32) {
		uid1=id16to32(uid1);
		uid2=id16to32(uid2);
		uid3=id16to32(uid3);
	}
	if (secure && checksecureuid(pc,uid1,uid2,uid3,-1)) {
			pc->retval=-1;
			pc->erno=EPERM;
			return SC_FAKE;
	}
	if (hte != NULL) {
		if ((pc->retval = um_syscall(uid1,uid2,uid3)) < 0)
			pc->erno=errno;
	} else {
		if (uid1 != -1) pc->ruid=uid1;
		if (uid2 != -1) pc->euid=pc->fsuid=uid2;
		if (uid3 != -1) pc->suid=uid2;
		pc->erno=pc->retval=0;
	}
	return SC_FAKE;
}

int wrap_in_setresgid(int sc_number,struct pcb *pc,
		struct ht_elem *hte, sysfun um_syscall)
{
	gid_t gid1=pc->sysargs[0];
	gid_t gid2=pc->sysargs[1];
	gid_t gid3=pc->sysargs[2];
	if (sc_number != __NR_setresgid32) {
		gid1=id16to32(gid1);
		gid2=id16to32(gid2);
		gid3=id16to32(gid3);
	}
	if (secure && checksecuregid(pc,gid1,gid2,gid3,-1)) {
			pc->retval=-1;
			pc->erno=EPERM;
			return SC_FAKE;
	}
	if (hte != NULL) {
		if ((pc->retval = um_syscall(gid1,gid2,gid3)) < 0)
			pc->erno=errno;
	} else {
		if (gid1 != -1) pc->rgid=gid1;
		if (gid2 != -1) pc->egid=pc->fsgid=gid2;
		if (gid3 != -1) pc->sgid=gid2;
		pc->erno=pc->retval=0;
	}
	return SC_FAKE;
}

int wrap_in_getresuid(int sc_number,struct pcb *pc,
		struct ht_elem *hte, sysfun um_syscall)
{
	uid_t uid1,uid2,uid3;
	if (hte != NULL) 
		pc->retval = um_syscall(&uid1,&uid2,&uid3);
	else {
		uid1=pc->ruid;
		uid2=pc->euid;
		uid3=pc->suid;
		pc->retval=pc->erno=0;
	}
	if (pc->retval >= 0) {
		long uid1p=pc->sysargs[0];
		long uid2p=pc->sysargs[1];
		long uid3p=pc->sysargs[2];
		if (sc_number != __NR_getresuid32) {
			unsigned short int suid1=id32to16(uid1);
			unsigned short int suid2=id32to16(uid2);
			unsigned short int suid3=id32to16(uid3);
			if (uid1p != umNULL)
				ustoren(pc,uid1p,sizeof(suid1),&suid1);
			if (uid2p != umNULL)
				ustoren(pc,uid2p,sizeof(suid2),&suid2);
			if (uid3p != umNULL)
				ustoren(pc,uid3p,sizeof(suid3),&suid3);
		} else {
			if (uid1p != umNULL)
				ustoren(pc,uid1p,sizeof(uid_t),&uid1);
			if (uid2p != umNULL)
				ustoren(pc,uid2p,sizeof(uid_t),&uid2);
			if (uid3p != umNULL)
				ustoren(pc,uid3p,sizeof(uid_t),&uid3);
		}
	} else
		pc->erno=errno;
	return SC_FAKE;
}

int wrap_in_getresgid(int sc_number,struct pcb *pc,
		struct ht_elem *hte, sysfun um_syscall)
{
	gid_t gid1,gid2,gid3;
	if (hte != NULL) 
		pc->retval = um_syscall(&gid1,&gid2,&gid3);
	else {
		gid1=pc->rgid;
		gid2=pc->egid;
		gid3=pc->sgid;
		pc->retval=pc->erno=0;
	}
	if (pc->retval >= 0) {
		long gid1p=pc->sysargs[0];
		long gid2p=pc->sysargs[1];
		long gid3p=pc->sysargs[2];
		if (sc_number != __NR_getresgid32) {
			unsigned short int sgid1=id32to16(gid1);
			unsigned short int sgid2=id32to16(gid2);
			unsigned short int sgid3=id32to16(gid3);
			if (gid1p != umNULL)
				ustoren(pc,gid1p,sizeof(sgid1),&sgid1);
			if (gid2p != umNULL)
				ustoren(pc,gid2p,sizeof(sgid2),&sgid2);
			if (gid3p != umNULL)
				ustoren(pc,gid3p,sizeof(sgid3),&sgid3);
		} else {
			if (gid1p != umNULL)
				ustoren(pc,gid1p,sizeof(gid_t),&gid1);
			if (gid2p != umNULL)
				ustoren(pc,gid2p,sizeof(gid_t),&gid2);
			if (gid3p != umNULL)
				ustoren(pc,gid3p,sizeof(gid_t),&gid3);
		}
	} else
		pc->erno=errno;
	return SC_FAKE;
}

int wrap_in_nice(int sc_number,struct pcb *pc,
		struct ht_elem *hte, sysfun um_syscall)
{
	int inc=pc->sysargs[0];
	if ((pc->retval = um_syscall(inc)) < 0)
		pc->erno=errno;
	return SC_FAKE;
}

int wrap_in_getpriority(int sc_number,struct pcb *pc,
		struct ht_elem *hte, sysfun um_syscall)
{
	int which=pc->sysargs[0];
	int who=pc->sysargs[1];
	if ((pc->retval = um_syscall(which, who)) < 0)
		pc->erno=errno;
	return SC_FAKE;
}

int wrap_in_setpriority(int sc_number,struct pcb *pc,
		struct ht_elem *hte, sysfun um_syscall) 
{
	int which=pc->sysargs[0];
	int who=pc->sysargs[1];
	int prio=pc->sysargs[2];
	if (secure) {
		if (capcheck(CAP_SYS_NICE,pc)) {
			/* A  process  was located, but its effective user ID did not match
				 either the effective or the real user ID of the caller, and  was
				 not privileged (on Linux: did not have the CAP_SYS_NICE capabil‐
				 ity).*/
			if ((which == PRIO_PROCESS || which == PRIO_PGRP) && who != 0) {
				struct pcb *target=pid2pcb(who);
				if (target != NULL && 
						pc->ruid != target->euid && pc->euid != target->euid) {
					pc->retval=-1;
					pc->erno=EPERM;
				}
			}
		}
	}
	if ((pc->retval = um_syscall(which, who, prio)) < 0)
		pc->erno=errno;
	return SC_FAKE;
}

int wrap_in_getpid(int sc_number,struct pcb *pc,
		    struct ht_elem *hte, sysfun um_syscall)
{
	if ((pc->retval = um_syscall()) < 0)
		pc->erno=errno;
	return SC_FAKE;
}

int wrap_in_setpid(int sc_number,struct pcb *pc,
		    struct ht_elem *hte, sysfun um_syscall)
{
	if ((pc->retval = um_syscall()) < 0)
		pc->erno=errno;
	return SC_FAKE;
}

int wrap_in_getpgrp(int sc_number,struct pcb *pc,
		    struct ht_elem *hte, sysfun um_syscall)
{
	/* mapped onto getpgid(0) */
	if ((pc->retval = um_syscall(0)) < 0)
		pc->erno=errno;
	return SC_FAKE;
}

int wrap_in_setpgrp(int sc_number,struct pcb *pc,
		    struct ht_elem *hte, sysfun um_syscall)
{
	/* mapped onto setpgid(0,0) */
	if ((pc->retval = um_syscall(0,0)) < 0)
		pc->erno=errno;
	return SC_FAKE;
}

int wrap_in_getpid_1(int sc_number,struct pcb *pc,
		    struct ht_elem *hte, sysfun um_syscall)
{
	pid_t pid=pc->sysargs[0];
	if ((pc->retval = um_syscall(pid)) < 0)
		pc->erno=errno;
	return SC_FAKE;
}

int wrap_in_setpgid(int sc_number,struct pcb *pc,
		    struct ht_elem *hte, sysfun um_syscall)
{
	pid_t pid1=pc->sysargs[0];
	pid_t pid2=pc->sysargs[1];
	if ((pc->retval = um_syscall(pid1,pid2)) < 0)
		pc->erno=errno;
	return SC_FAKE;
}

int wrap_in_getgroups(int sc_number,struct pcb *pc,
		        struct ht_elem *hte, sysfun um_syscall)
{
	int size=pc->sysargs[0];
	long plist=pc->sysargs[1];
	if (size == 0) {
		pc->retval = pc->grouplist->size;
		pc->erno = 0;
	} else {
		if (size < pc->grouplist->size) {
			pc->retval = -1;
			pc->erno = EINVAL;
		} else {
			pc->retval = pc->grouplist->size;
#if __NR_getgroups32 != __NR_getgroups
			if (sc_number == __NR_getgroups) {
				int i;
				unsigned short *gid16=alloca(size * sizeof(unsigned short));
				for (i=0;i<size;i++)
					gid16[i]=id32to16(pc->grouplist->list[i]);
				ustoren(pc, plist, pc->retval * sizeof(unsigned short), gid16);
			} else
#endif
				ustoren(pc, plist, pc->retval * sizeof(gid_t), pc->grouplist->list);
			pc->erno=0;
		}
	}
	return SC_FAKE;
}

int wrap_in_setgroups(int sc_number,struct pcb *pc,
		struct ht_elem *hte, sysfun um_syscall)
{
	size_t size=pc->sysargs[0];
	long plist=pc->sysargs[1];
	if (size > NGROUPS_MAX) {
		pc->retval = -1;
		pc->erno = EINVAL;
	} else {
		supgrp_put(pc->grouplist);
		pc->grouplist=supgrp_create(size);
		if (size > 0) {
#if __NR_setgroups32 != __NR_setgroups
			if (sc_number == __NR_setgroups) {
				int i;
				unsigned short *gid16=alloca(size * sizeof(unsigned short));
				umoven(pc, plist, size * sizeof(unsigned short), gid16);
				for (i=0;i<size;i++)
					pc->grouplist->list[i]= id16to32(gid16[i]);
			} else 
#endif
				umoven(pc, plist,  size * sizeof(gid_t), pc->grouplist->list);
		}
		pc->erno=0;
		pc->retval=1;
	}
	return SC_FAKE;
}

#ifdef VIEW_CAPABILITY
int wrap_in_capget(int sc_number,struct pcb *pc,
		struct ht_elem *hte, sysfun um_syscall)
{
	unsigned long hdrp=pc->sysargs[0];
	unsigned long datap=pc->sysargs[1];
	struct __user_cap_header_struct hdr;
	umoven(pc, hdrp, sizeof(struct __user_cap_header), hdr);
	/* XXX TBD */
}

int wrap_in_capset(int sc_number,struct pcb *pc,
		struct ht_elem *hte, sysfun um_syscall)
{
	unsigned long hdrp=pc->sysargs[0];
	unsigned long datap=pc->sysargs[1];
	struct __user_cap_header_struct hdr;
	umoven(pc, hdrp, sizeof(struct __user_cap_header), hdr);
	/* XXX TBD */
}
#endif
