/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   umfuse parameters management
 *   
 *   Copyright 2005 Renzo Davoli University of Bologna - Italy
 *   Modified 2005 Paolo Angelelli, Andrea Seraghiti
 *   
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 *   $Id$
 *
 */

/*  UMFUSE ARGS!

mount options for umfuse file systems can include the following:
pre=....
post=....
format=.....
nosource
debug

nosource means that the 'source' field (where fo mount the file system from)
must not be specified when calling the library.

The standard call for the library 'main' is the following:

umfusexxx  -o options source mountpoint

pre are extra parms to be put before -o
post are extra trailing parms

If the main needs a completely different structure format can be used:
the format string is similar to that used in printf.
%O %S %M descriptors are substituted in the call as follows:
%O=-o options
%S=source
%M=mountpoint
*/

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "umfusestd.h"

#define MAXARGS 256
#define PATH_MAX 256

#define FUSEARGDEBUG 1  //"debug"
#define FUSEARGNOSOURCE 2  //"nosource"
#define FUSEARGPRE 3 //"pre"
#define FUSEARGPOST 4 //"post"
#define FUSEARGFMT 5 //"format"
#define FUSEARGSHOWCALL 6 //"format"
#define FUSEFLAGHASSTRING 1
#define FUSEFLAGCOPY 2
static struct fuseargitem {
	char *arg;
	char tag;
	char flags;
} fuseargtab[] = {
	{"debug", FUSEARGDEBUG, 0},
	{"nosource",FUSEARGNOSOURCE, 0},
	{"showcall",FUSEARGSHOWCALL, 0},
	{"pre=", FUSEARGPRE, FUSEFLAGHASSTRING},
	{"post=",FUSEARGPOST, FUSEFLAGHASSTRING},
	{"format=",FUSEARGFMT, FUSEFLAGHASSTRING}
};
#define FUSEARGTABSIZE sizeof(fuseargtab)/sizeof(struct fuseargitem)

static char dasho[]="-o";
static int fuseaddargs(char *fmt, char *source, char *mountpoint, char *opts, char ***pargv, int nargc)
{
	char *s=fmt;
	int newfield=1;
	char quote=0;
	int oldnargc=nargc;
#ifdef DEBUGFUSEARGS
	printf("FMT %s SOURCE %s MOUNTPT %s OPTS %s\n",fmt,source,mountpoint,opts);
#endif
	/* from space-separated fields to argv format*/
	while (s != NULL && *s != 0) {
			switch (*s) {
				case ' ':
					if (quote==0) {
						*s=0;
						if (newfield==0) newfield=1;
					} 
					break;
				case '%':
					switch (*(s+1)) {
						case 'O':if (opts != NULL && *opts != 0) {
								 pargv[0][nargc++]=dasho;
								 pargv[0][nargc++]=opts;
							 }
							 s++; 
							 break;
						case 'S':if (source != NULL) 
								 pargv[0][nargc++]=source;
							 s++;
							 break;
						case 'D':
						case 'M':
							 if (mountpoint != NULL) 
								 pargv[0][nargc++]=mountpoint;
							 s++;
							 break;
					}
					break;
				case '\'':
				case '\"':
					quote=(*s == quote)?0:*s;
				/* roll down */
				default:
				if (newfield) {
					newfield=0;
					if (nargc<MAXARGS)
						pargv[0][nargc++]=s;
				}
				break;
			}
		s++;
	}
	int i;
#ifdef DEBUGFUSEARGS
	for (i=oldnargc;i<nargc;i++)
		printf("fmt->argv %d -> %s\n",i,pargv[0][i]);
#endif
	/* unwrap one quotation layer */
	for (i=oldnargc;i<nargc;i++) {
		char *s,*t;
		quote=0;
		for (s=t=pargv[0][i];*s != 0;s++) {
			if (quote == 0 && *s=='\\' && *(s+1) != 0) {
				*t++=*++s;
			} else if (*s == '\'' || *s == '\"') {
				if (quote==0) {
					quote=*s;
				} else if (quote==*s) {
					quote=0;
				} else
					*t++=*s;
			} else
				*t++=*s;
		}
		*t=0;
	}
#ifdef DEBUGFUSEARGS
	for (i=oldnargc;i<nargc;i++) 
		printf("fmt->argv(unwrapped) %d -> %s\n",i,pargv[0][i]);
#endif
	return nargc;
}

int fuseargs(char* filesystemtype,char *source, char *mountpoint, char *opts, char ***pargv,int *pflags)
{
	char *sepopts[MAXARGS];
	int nsepopts=0;
	char newopts[PATH_MAX];
	char *pre=NULL;
	char *post=NULL;
	char *fmt=NULL;
	char nosource=0;
	char showcall=0;
	int i;
	newopts[0]=0;
	char *s=opts;
	char quote=0,olds;
#ifdef DEBUGFUSEARGS
	printf("fuseargs opts %s\n",s);
#endif
	/* PHASE 1: tokenize options */
	for (quote=0,s=opts,olds=*s;olds != 0 && nsepopts < MAXARGS;s++) {
		sepopts[nsepopts++]=s;
		while (*s != 0 && (*s != ',' || quote != 0))
		{
			if (*s=='\\' && *(s+1)!=0)
				s+=2;
			if (*s=='\'' || *s=='\"') {
				if (*s == quote)
					quote=0;
				else
					if (quote==0)
						quote=*s;
			}
			s++;
		}
		olds=*s;*s=0;
	}
#ifdef DEBUGFUSEARGS
	for (i=0;i<nsepopts;i++)
		printf("separg %d = %s\n",i,sepopts[i]);
#endif
	/* PHASE 2 recognize UMFUSE options */
	for (i=0;i<nsepopts;i++) {
		int j;
		for (j=0; j<FUSEARGTABSIZE && 
				strncmp(sepopts[i],fuseargtab[j].arg,strlen(fuseargtab[j].arg)) != 0; j++)
				;
		switch ((j<FUSEARGTABSIZE)?fuseargtab[j].tag:0) {
			case FUSEARGDEBUG:
#ifdef DEBUGFUSEARGS
				printf("DEBUG\n");
#endif
				*pflags |= FUSE_DEBUG;
				break;
			case FUSEARGNOSOURCE:
				nosource=1;
#ifdef DEBUGFUSEARGS
				printf("NOSOURCE\n");
#endif
				break;
			case FUSEARGSHOWCALL:
				showcall=1;
#ifdef DEBUGFUSEARGS
				printf("SHOWCALL\n");
#endif
				break;
			case FUSEARGPRE:
				pre=sepopts[i]+strlen(fuseargtab[j].arg);
				break;
			case FUSEARGPOST:
				post=sepopts[i]+strlen(fuseargtab[j].arg);
				break;
			case FUSEARGFMT:
				fmt=sepopts[i]+strlen(fuseargtab[j].arg);
				break;
			default:
				{
					int len=PATH_MAX-strlen(newopts);
					if (len < 0) len=0;
					if (*newopts != 0)
						strncat(newopts,",",len--);
					if (len < 0) len=0;
					strncat(newopts,sepopts[i],len);
				}
				break;
		}
	}
	//printf("%s pre %s post %s fmt %s\n",newopts,pre,post,fmt);
	/* PHASE 3 build newargc newargv */
	char *nargv[MAXARGS];
	int nargc=0;
	char **pnargv=nargv;
	nargv[nargc++]=filesystemtype; // argv[0] is filesystemtype
	nargc=fuseaddargs(pre,NULL,NULL,NULL,&pnargv,nargc);
	if (fmt != NULL)
		nargc=fuseaddargs(fmt,source,mountpoint,newopts,&pnargv,nargc);
	else {
		if (*newopts != 0) {
			nargv[nargc++]="-o";
			nargv[nargc++]=newopts;
		}
		if (! nosource && source != NULL && strcmp(source,"NONE") != 0)
			nargv[nargc++]=source;
		if (mountpoint != NULL)
			nargv[nargc++]=mountpoint;
	}
	nargc=fuseaddargs(post,NULL,NULL,NULL,&pnargv,nargc);
	if (showcall) {
		printf("FUSE call:\n");
		for (i=0; i<nargc;i++)
			printf("argv %d = %s\n",i,nargv[i]);
	}
	*pargv = (char **) malloc (nargc * sizeof(char*));
	for (i=0; i<nargc;i++) {
		pargv[0][i]=strdup(nargv[i]);
	}
	return nargc;
}

#ifdef DEBUGFUSEARGS
main(int argc,char *argv[])
{
	int newargc;
	char **newargv;
	int i;
	int flags;
	newargc=fuseargs(argv[0],argv[1],argv[2],argv[3],&newargv,&flags);
	for (i=0;i<newargc;i++)
	{
		printf("arg %d = %s\n",i,newargv[i]);
	}
}
#endif
