/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   UMMISC: Virtual Miscellanea in Userspace (function mgmt)
 *    Copyright (C) 2007  Renzo Davoli <renzo@cs.unibo.it>
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
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <config.h>
#include <dlfcn.h>
#include "module.h"
#include "libummod.h"
#include "ummisc.h"
#include "ummiscfun.h"

#include <sys/time.h>
#include <time.h>
#include <sys/timex.h>
#include <sys/utsname.h>
#include <sys/types.h>
#include <sys/fsuid.h>
#include <sys/resource.h>

static char *muscno;

struct misc_call {
	int scno;
	char *misccall;
};

struct misc_call misc_calls[]={
	/* time related calls */
	{__NR_gettimeofday,"misc_gettimeofday"},
	{__NR_settimeofday,"misc_settimeofday"},
	{__NR_adjtimex,"misc_adjtimex"},
	{__NR_clock_gettime,"misc_clock_gettime"},
	{__NR_clock_settime,"misc_clock_settime"},
	{__NR_clock_getres,"misc_clock_getres"},

	/* host id */
	{__NR_uname,"misc_uname"},
#ifdef __NR_gethostname
	{__NR_gethostname,"misc_gethostname"},
#endif
	{__NR_sethostname,"misc_sethostname"},
#ifdef __NR_getdomainname
	{__NR_getdomainname,"misc_getdomainname"},
#endif
	{__NR_setdomainname,"misc_setdomainname"},

	/* user mgmt calls */
	{__NR_getuid,"misc_getuid"},
	{__NR_setuid,"misc_setuid"},
	{__NR_geteuid,"misc_geteuid"},
	{__NR_setfsuid,"misc_setfsuid"},
	{__NR_setreuid,"misc_setreuid"},
	{__NR_getresuid,"misc_getresuid"},
	{__NR_setresuid,"misc_setresuid"},
	{__NR_getgid,"misc_getgid"},
	{__NR_setgid,"misc_setgid"},
	{__NR_getegid,"misc_getegid"},
	{__NR_setfsgid,"misc_setfsgid"},
	{__NR_setregid,"misc_setregid"},
	{__NR_getresgid,"misc_getresgid"},
	{__NR_setresgid,"misc_setresgid"},

	/* priority related calls */
	{__NR_nice,"misc_nice"},
	{__NR_getpriority,"misc_getpriority"},
	{__NR_setpriority,"misc_setpriority"},

	/* process id related */
	{__NR_getpid,"misc_getpid"},
	{__NR_getppid,"misc_getppid"},
	{__NR_getpgid,"misc_getpgid"},
	{__NR_setpgid,"misc_setpgid"},
	{__NR_getsid,"misc_getsid"},
	{__NR_setsid,"misc_setsid"}
};

#define NOMISC_CALLS (sizeof(misc_calls) / sizeof (struct misc_call))

sysfun getfun(struct ummisc *mh,int scno) {
	void *dl=misc_getdl(mh);
	assert (dl != NULL);
	return (sysfun)(dlsym(dl,misc_calls[muscno[scno]].misccall));
}

static int umm_gettimeofday(struct timeval *tv, struct timezone *tz) {
	struct ummisc *mh=searchmisc_sc(__NR_gettimeofday);
	assert (mh != NULL);
	return getfun(mh,__NR_gettimeofday)(tv,tz,mh);
}
static int umm_settimeofday(const struct timeval *tv , const struct timezone *tz) {
	struct ummisc *mh=searchmisc_sc(__NR_settimeofday);
	assert (mh != NULL);
	return getfun(mh,__NR_settimeofday)(tv,tz,mh);
}
static int umm_adjtimex(struct timex *buf) {
	struct ummisc *mh=searchmisc_sc(__NR_adjtimex);
	assert (mh != NULL);
	return getfun(mh,__NR_adjtimex)(buf,mh);
}
static int umm_clock_getres(clockid_t clk_id, struct timespec *res) {
	struct ummisc *mh=searchmisc_sc(__NR_clock_getres);
	assert (mh != NULL);
	return getfun(mh,__NR_clock_getres)(clk_id,res,mh);
}
static int umm_clock_gettime(clockid_t clk_id, struct timespec *tp) {
	struct ummisc *mh=searchmisc_sc(__NR_clock_gettime);
	assert (mh != NULL);
	return getfun(mh,__NR_clock_gettime)(clk_id,tp,mh);
}
static int umm_clock_settime(clockid_t clk_id, const struct timespec *tp) {
	struct ummisc *mh=searchmisc_sc(__NR_clock_settime);
	assert (mh != NULL);
	return (getfun(mh,__NR_clock_settime))(clk_id,tp,mh);
}
static int umm_uname(struct utsname *buf) {
	struct ummisc *mh=searchmisc_sc(__NR_uname);
	assert (mh != NULL);
	return getfun(mh,__NR_uname)(buf,mh);
}
#ifdef __NR_gethostname
static int umm_gethostname(char *name, size_t len) {
	struct ummisc *mh=searchmisc_sc(__NR_gethostname);
	assert (mh != NULL);
	return getfun(mh,__NR_gethostname)(name,len,mh);
}
#endif
static int umm_sethostname(const char *name, size_t len) {
	struct ummisc *mh=searchmisc_sc(__NR_sethostname);
	assert (mh != NULL);
	return getfun(mh,__NR_sethostname)(name,len,mh);
}
#ifdef __NR_getdomainname
static int umm_getdomainname(char *name, size_t len) {
	struct ummisc *mh=searchmisc_sc(__NR_getdomainname);
	assert (mh != NULL);
	return getfun(mh,__NR_getdomainname)(name,len,mh);
}
#endif
static int umm_setdomainname(const char *name, size_t len) {
	struct ummisc *mh=searchmisc_sc(__NR_setdomainname);
	assert (mh != NULL);
	return getfun(mh,__NR_setdomainname)(name,len,mh);
}
static uid_t umm_getuid(void) {
	struct ummisc *mh=searchmisc_sc(__NR_getuid);
	assert (mh != NULL);
	return getfun(mh,__NR_getuid)(mh);
}
static int umm_setuid(uid_t uid) {
	struct ummisc *mh=searchmisc_sc(__NR_setuid);
	assert (mh != NULL);
	return getfun(mh,__NR_setuid)(uid,mh);
}
static uid_t umm_geteuid(void) {
	struct ummisc *mh=searchmisc_sc(__NR_geteuid);
	assert (mh != NULL);
	return getfun(mh,__NR_geteuid)(mh);
}
static int umm_setfsuid(uid_t fsuid) {
	struct ummisc *mh=searchmisc_sc(__NR_setfsuid);
	assert (mh != NULL);
	return getfun(mh,__NR_setfsuid)(fsuid,mh);
}
static int umm_setreuid(uid_t ruid, uid_t euid) {
	struct ummisc *mh=searchmisc_sc(__NR_setreuid);
	assert (mh != NULL);
	return getfun(mh,__NR_setreuid)(ruid,euid,mh);
}
static int umm_getresuid(uid_t *ruid, uid_t *euid, uid_t *suid) {
	struct ummisc *mh=searchmisc_sc(__NR_getresuid);
	assert (mh != NULL);
	return getfun(mh,__NR_getresuid)(ruid,euid,suid,mh);
}
static int umm_setresuid(uid_t ruid, uid_t euid, uid_t suid) {
	struct ummisc *mh=searchmisc_sc(__NR_setresuid);
	assert (mh != NULL);
	return getfun(mh,__NR_setresuid)(ruid,euid,suid,mh);
}
static gid_t umm_getgid(void) {
	struct ummisc *mh=searchmisc_sc(__NR_getgid);
	assert (mh != NULL);
	return getfun(mh,__NR_getgid)(mh);
}
static int umm_setgid(gid_t gid) {
	struct ummisc *mh=searchmisc_sc(__NR_setgid);
	assert (mh != NULL);
	return getfun(mh,__NR_setgid)(gid,mh);
}
static gid_t umm_getegid(void) {
	struct ummisc *mh=searchmisc_sc(__NR_geteuid);
	assert (mh != NULL);
	return getfun(mh,__NR_getegid)(mh);
}
static int umm_setfsgid(uid_t fsgid) {
	struct ummisc *mh=searchmisc_sc(__NR_setfsgid);
	assert (mh != NULL);
	return getfun(mh,__NR_getegid)(fsgid,mh);
}
static int umm_setregid(gid_t rgid, gid_t egid) {
	struct ummisc *mh=searchmisc_sc(__NR_setregid);
	assert (mh != NULL);
	return getfun(mh,__NR_setregid)(rgid,egid,mh);
}
static int umm_getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid) {
	struct ummisc *mh=searchmisc_sc(__NR_getresgid);
	assert (mh != NULL);
	return getfun(mh,__NR_getresgid)(rgid,egid,sgid,mh);
}
static int umm_setresgid(gid_t rgid, gid_t egid, gid_t sgid) {
	struct ummisc *mh=searchmisc_sc(__NR_setresgid);
	assert (mh != NULL);
	return getfun(mh,__NR_setresgid)(rgid,egid,sgid,mh);
}
static int umm_nice(int inc) {
	struct ummisc *mh=searchmisc_sc(__NR_nice);
	assert (mh != NULL);
	return getfun(mh,__NR_nice)(inc,mh);
}
static int umm_getpriority(int which, int who) {
	struct ummisc *mh=searchmisc_sc(__NR_getpriority);
	assert (mh != NULL);
	return getfun(mh,__NR_getpriority)(which,who,mh);
}
static int umm_setpriority(int which, int who, int prio) {
	struct ummisc *mh=searchmisc_sc(__NR_setpriority);
	assert (mh != NULL);
	return getfun(mh,__NR_setpriority)(which,who,prio,mh);
}
static pid_t umm_getpid(void) {
	struct ummisc *mh=searchmisc_sc(__NR_getpid);
	assert (mh != NULL);
	return getfun(mh,__NR_getpid)(mh);
}
static pid_t umm_getppid(void) {
	struct ummisc *mh=searchmisc_sc(__NR_getppid);
	assert (mh != NULL);
	return getfun(mh,__NR_getppid)(mh);
}
static int umm_setpgid(pid_t pid, pid_t pgid) {
	struct ummisc *mh=searchmisc_sc(__NR_setpgid);
	assert (mh != NULL);
	return getfun(mh,__NR_setpgid)(pid,pgid,mh);
}
static pid_t umm_getpgid(pid_t pid) {
	struct ummisc *mh=searchmisc_sc(__NR_setpgid);
	assert (mh != NULL);
	return getfun(mh,__NR_getpgid)(pid,mh);
}
static pid_t umm_getsid(pid_t pid) {
	struct ummisc *mh=searchmisc_sc(__NR_getsid);
	assert (mh != NULL);
	return getfun(mh,__NR_getsid)(pid,mh);
}
static pid_t umm_setsid(void) {
	struct ummisc *mh=searchmisc_sc(__NR_setsid);
	assert (mh != NULL);
	return getfun(mh,__NR_setsid)(mh);
}

void setscset(void *dlhandle,fd_set *scs)
{
	register int i;
	FD_ZERO(scs);
	for (i=0;i<NOMISC_CALLS;i++) {
		if (dlsym(dlhandle,misc_calls[i].misccall) != NULL) 
			FD_SET(misc_calls[i].scno,scs);
	}
}

void initmuscno(struct service *s)
{
	int i;
	muscno=malloc(um_mod_nrsyscalls() * sizeof (char));
	assert(muscno);
	for (i=0;i<NOMISC_CALLS;i++) {
		muscno[misc_calls[i].scno]=i;
	}
	SERVICESYSCALL(*s,gettimeofday, umm_gettimeofday);
	SERVICESYSCALL(*s,settimeofday, umm_settimeofday);
	SERVICESYSCALL(*s,adjtimex, umm_adjtimex);
	SERVICESYSCALL(*s,clock_gettime, umm_clock_gettime);
	SERVICESYSCALL(*s,clock_settime, umm_clock_settime);
	SERVICESYSCALL(*s,clock_getres, umm_clock_getres);
	SERVICESYSCALL(*s,uname, umm_uname);
#ifdef __NR_gethostname
	SERVICESYSCALL(*s,gethostname, umm_gethostname);
#endif
	SERVICESYSCALL(*s,sethostname, umm_sethostname);
#ifdef __NR_getdomainname
	SERVICESYSCALL(*s,getdomainname, umm_getdomainname);
#endif
	SERVICESYSCALL(*s,setdomainname,umm_setdomainname);
	SERVICESYSCALL(*s,getuid, umm_getuid);
	SERVICESYSCALL(*s,setuid, umm_setuid);
	SERVICESYSCALL(*s,geteuid, umm_geteuid);
	SERVICESYSCALL(*s,setfsuid, umm_setfsuid);
	SERVICESYSCALL(*s,setreuid, umm_setreuid);
	SERVICESYSCALL(*s,getresuid, umm_getresuid);
	SERVICESYSCALL(*s,setresuid, umm_setresuid);
	SERVICESYSCALL(*s,getgid, umm_getgid);
	SERVICESYSCALL(*s,setgid, umm_setgid);
	SERVICESYSCALL(*s,getegid, umm_getegid);
	SERVICESYSCALL(*s,setfsgid, umm_setfsgid);
	SERVICESYSCALL(*s,setregid, umm_setregid);
	SERVICESYSCALL(*s,getresgid, umm_getresgid);
	SERVICESYSCALL(*s,setresgid, umm_setresgid);
	SERVICESYSCALL(*s,nice, umm_nice);
	SERVICESYSCALL(*s,getpriority, umm_getpriority);
	SERVICESYSCALL(*s,setpriority, umm_setpriority);
	SERVICESYSCALL(*s,getpid, umm_getpid);
	SERVICESYSCALL(*s,getppid, umm_getppid);
	SERVICESYSCALL(*s,getpgid, umm_getpgid);
	SERVICESYSCALL(*s,setpgid, umm_setpgid);
	SERVICESYSCALL(*s,getsid, umm_getsid);
	SERVICESYSCALL(*s,setsid, umm_setsid);
}

void finimuscno(void)
{
	free(muscno);
}
