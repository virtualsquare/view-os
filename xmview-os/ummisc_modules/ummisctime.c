/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   UMMISCTIME: Virtual Time Abstraction
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
#include <time.h>
#include <sys/time.h>
#include <string.h>
#include <assert.h>

#include "ummisc.h"

struct umtimeinfo {
	long double offset;
	double freq;
};

static loff_t gp_time(int op,char *value,int size,struct ummisc *mh,int tag,char *path);

static void ummisc_time_init(char *path, unsigned long flags, char *args,struct ummisc *mh);
static void ummisc_time_fini(struct ummisc *mh);

#define GP_OFFSET 1
#define GP_FREQ 2

struct fsentry fseroot[] = {
	{"offset",NULL,gp_time,GP_OFFSET},
	{"frequency",NULL,gp_time,GP_FREQ},
	{NULL,NULL,NULL,0}};

struct ummisc_operations ummisc_ops = {
	{"root", fseroot, NULL, 0},
	ummisc_time_init,
	ummisc_time_fini
};

static long double umtime(struct umtimeinfo *umt)
{
	struct timespec ts;
	long double now;
	clock_gettime(CLOCK_REALTIME,&ts);
	now=ts.tv_sec + ((long double) ts.tv_nsec) / 1000000000;
	//printk("umtime now %llf\n",now);
	now=now*umt->freq+umt->offset;
	//printk("umtime umnow %llf\n",now);
	return now;
}

static void umsettime(struct umtimeinfo *umt,long double newnow)
{
	struct timespec ts;
	long double now;
	clock_gettime(CLOCK_REALTIME,&ts);
	now=ts.tv_sec + ((long double) ts.tv_nsec) / 1000000000;
	now=now*umt->freq+umt->offset;
	umt->offset += newnow - now;
}

static void setnewfreq(struct umtimeinfo *umt,long double newfreq)
{
	struct timespec ts;
	long double now;
	long double oldtime;
	long double newuncorrected;
	clock_gettime(CLOCK_REALTIME,&ts);
	now=ts.tv_sec + ((long double) ts.tv_nsec) / 1000000000;
	oldtime=now*umt->freq+umt->offset;
	newuncorrected=now*newfreq+umt->offset;
	//printk("setnewfreq %llf %llf %llf %llf\n",
			//newfreq,now,oldtime,newuncorrected);
	umt->offset += (oldtime-newuncorrected);
	umt->freq=newfreq;
}

int misc_gettimeofday(struct timeval *tv, struct timezone *tz,
		struct ummisc *mh) {
	struct umtimeinfo *buf=ummisc_getprivatedata(mh);
	long double now=umtime(buf);
	if (tv) {
		tv->tv_sec = (time_t) now;
		tv->tv_usec = (time_t) ((now - tv->tv_sec) * 1000000);
	}
	return 0;
}

int misc_settimeofday(const struct timeval *tv , const struct timezone *tz,
		struct ummisc *mh) {
	struct umtimeinfo *buf=ummisc_getprivatedata(mh);
	long double newnow;
	if (tv) {
			newnow = tv->tv_sec + ((long double) tv->tv_usec) / 1000000;
			umsettime(buf,newnow);
	}
	return 0;
}

int misc_clock_getres(clockid_t clk_id, struct timespec *res,
		struct ummisc *mh) {
	return clock_getres(clk_id,res);
}

int misc_clock_gettime(clockid_t clk_id, struct timespec *tp,
		struct ummisc *mh) {
	if (clk_id == CLOCK_REALTIME) {
		struct umtimeinfo *buf=ummisc_getprivatedata(mh);
		long double now=umtime(buf);
		if (tp) {
			tp->tv_sec = (time_t) now;
			tp->tv_nsec = (time_t) ((now - tp->tv_sec) * 1000000000);
		}
		return 0;
	}
	else
		return clock_gettime(clk_id,tp);
}

int misc_clock_settime(clockid_t clk_id, const struct timespec *tp,
		struct ummisc *mh) {
	if (clk_id == CLOCK_REALTIME) {
		struct umtimeinfo *buf=ummisc_getprivatedata(mh);
		long double newnow;
		if (tp) {
			newnow = tp->tv_sec + ((long double) tp->tv_nsec) / 1000000000;
			umsettime(buf,newnow);
		}
	} else
		return clock_settime(clk_id,tp);
}

static loff_t gp_time(int op,char *value,int size,struct ummisc *mh,int tag, char *path) {
	struct umtimeinfo *buf=ummisc_getprivatedata(mh);
	loff_t rv=0;
	char *field;
	switch (tag) {
		case GP_OFFSET:
			if (op==UMMISC_GET) {
				snprintf(value,size,"%llf\n",buf->offset);
				rv=strlen(value);
			} else {
				rv=size;
				value[size]=0;
				sscanf(value,"%llf",&buf->offset);
			}
			break;
		case GP_FREQ:
			if (op==UMMISC_GET) {
				snprintf(value,size,"%15.10lf\n",buf->freq);
				rv=strlen(value);
			} else {
				long double newfreq;
				rv=size;
				value[size]=0;
				sscanf(value,"%llf",&newfreq);
				setnewfreq(buf,newfreq);
			}
			break;
	}
}

static void ummisc_time_init(char *path, unsigned long flags, char *args, struct ummisc *mh) {
	struct umtimeinfo *buf;
	buf=calloc(1,sizeof(struct umtimeinfo));
	assert(buf);
	buf->freq=1;
	ummisc_setprivatedata(mh,buf);
	//printk("ummisc_time_init \n");
}

static void ummisc_time_fini(struct ummisc *mh) {
	struct umtimeinfo *buf=ummisc_getprivatedata(mh);
	free(buf);
	//printk("ummisc_time_fini \n");
}

