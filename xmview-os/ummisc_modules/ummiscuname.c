/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   UMMISCUNAME: Virtual System Identification (Uname)
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
#include <sys/utsname.h>
#include <string.h>
#include <assert.h>

#include "ummisc.h"

loff_t gp_uname(int op,char *value,int size,struct ummisc *mh,int tag,char *path);

void ummisc_uname_init(char *path, unsigned long flags, char *args,struct ummisc *mh);
void ummisc_uname_fini(struct ummisc *mh);

#define GP_SYSNAME 1
#define GP_NODENAME 2
#define GP_RELEASE 3
#define GP_VERSION 4
#define GP_MACHINE 5
#define GP_DOMAIN 6

struct fsentry fseroot[] = {
	{"sysname",NULL,gp_uname,GP_SYSNAME},
	{"nodename",NULL,gp_uname,GP_NODENAME},
	{"release",NULL,gp_uname,GP_RELEASE},
	{"version",NULL,gp_uname,GP_VERSION},
	{"machine",NULL,gp_uname,GP_MACHINE},
	{"domainname",NULL,gp_uname,GP_DOMAIN},
	{NULL,NULL,NULL,0}};

struct ummisc_operations ummisc_ops = {
	{"root", fseroot, NULL, 0},
	ummisc_uname_init,
	ummisc_uname_fini
};

int misc_uname(struct utsname *buf, struct ummisc *mh)
{
	//fprint2("DEBUG, misc_uname\n");
	memcpy(buf,ummisc_getprivatedata(mh),sizeof(struct utsname));
	return 0;
}

int misc_sethostname(const char *name, size_t len, struct ummisc *mh)
{
	struct utsname *buf=ummisc_getprivatedata(mh);
	char *field=buf->nodename;
	memset(field,0,_UTSNAME_SYSNAME_LENGTH);
	if (len>_UTSNAME_SYSNAME_LENGTH) len=_UTSNAME_SYSNAME_LENGTH;
	strncpy(field,name,len);
}

int misc_setdomainname(const char *name, size_t len, struct ummisc *mh)
{
	struct utsname *buf=ummisc_getprivatedata(mh);
	char *field=buf->domainname;
	memset(field,0,_UTSNAME_SYSNAME_LENGTH);
	if (len>_UTSNAME_SYSNAME_LENGTH) len=_UTSNAME_SYSNAME_LENGTH;
	strncpy(field,name,len);
}

loff_t gp_uname(int op,char *value,int size,struct ummisc *mh,int tag, char *path) {
	struct utsname *buf=ummisc_getprivatedata(mh);
	char *field;
	switch (tag) {
		case GP_SYSNAME:
			field=buf->sysname; break;
		case GP_NODENAME:
			field=buf->nodename; break;
		case GP_RELEASE:
			field=buf->release; break;
		case GP_VERSION:
			field=buf->version; break;
		case GP_MACHINE:
			field=buf->machine; break;
		case GP_DOMAIN:
			field=buf->domainname; break;
	}
	if (op==UMMISC_GET) {
		snprintf(value,MISCFILESIZE,"%s\n",field);
		return strlen(field);
	} else {
		char *nl;
		value[size]=0;
		memset(field,0,_UTSNAME_SYSNAME_LENGTH);
		if ((nl=strchr(value,'\n')) != NULL)
			*nl=0;
		strncpy(field,value,_UTSNAME_SYSNAME_LENGTH);
		return size;
	}
}

void ummisc_uname_init(char *path, unsigned long flags, char *args, struct ummisc *mh) {
	struct utsname *buf;
	buf=malloc(sizeof(struct utsname));
	assert(buf);
	uname(buf);
	ummisc_setprivatedata(mh,buf);
	//fprint2("ummisc_uname_init \n");
}

void ummisc_uname_fini(struct ummisc *mh) {
	struct utsname *buf=ummisc_getprivatedata(mh);
	free(buf);
	//fprint2("ummisc_uname_fini \n");
}

