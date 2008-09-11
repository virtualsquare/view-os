/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   viewfs parameters management
 *   
 *   Copyright 2005 Renzo Davoli University of Bologna - Italy
 *   Modified 2005 Paolo Angelelli, Andrea Seraghiti
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
 *
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <config.h>
#include "viewfs0args.h"

//#define DEBUGVIEWFSARGS
#define MAXARGS 256

#define VIEWFSARGDEBUG 1  //"debug"
#define VIEWFSEXCEPT 9  //"except"
#define VIEWFSARGMOVE 10 //"move"
#define VIEWFSARGMERGE 11 //"merge"
#define VIEWFSARGCOW 12 //"cow"
#define VIEWFSARGRENEW 13 //"renew"
#define VIEWFSARGMINCOW 14 //"renew"
#define VIEWFSFLAGHASSTRING 1

static struct viewfsargitem {
	char *arg;
	char tag;
	char flags;
} viewfsargtab[] = {
	{"debug", VIEWFSARGDEBUG, 0},
	{"except=",VIEWFSEXCEPT, VIEWFSFLAGHASSTRING},
	{"move", VIEWFSARGMOVE, 0},
	{"merge", VIEWFSARGMERGE, 0},
	{"cow", VIEWFSARGCOW, 0},
	{"renew", VIEWFSARGRENEW, 0},
	{"mincow", VIEWFSARGMINCOW, 0}
};
#define VIEWFSARGTABSIZE sizeof(viewfsargtab)/sizeof(struct viewfsargitem)

int viewfsargs(char *opts,int *pflags,char ***pexceptions)
{
	char *sepopts[MAXARGS];
	char *exceptions[MAXARGS];
	int nsepopts=0;
	int nexceptions=0;
	char *s=opts;
	char quote=0,olds;
	char typeoption=0;
	int i;

	if (opts == NULL)
		return 0;
#ifdef DEBUGVIEWFSARGS
	printf("viewfsargs opts %s\n",s);
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
#ifdef DEBUGVIEWFSARGS
	for (i=0;i<nsepopts;i++)
		printf("separg %d = %s\n",i,sepopts[i]);
#endif

	/* PHASE 2 recognize UMVIEWFS options */
	for (i=0;i<nsepopts;i++) {
		int j;
		for (j=0; j<VIEWFSARGTABSIZE &&
				strncmp(sepopts[i],viewfsargtab[j].arg,strlen(viewfsargtab[j].arg)) != 0; j++)
			;
		switch ((j<VIEWFSARGTABSIZE)?viewfsargtab[j].tag:0) {
			case VIEWFSARGDEBUG:
				*pflags |= VIEWFS_DEBUG;
				break;
			case VIEWFSEXCEPT:
				exceptions[nexceptions]=sepopts[i]+strlen(viewfsargtab[j].arg);
				nexceptions++;
				break;
			case VIEWFSARGMOVE:
				typeoption++;
				*pflags |= VIEWFS_MOVE;
				break;
			case VIEWFSARGMERGE:
				typeoption++;
				*pflags |= VIEWFS_MERGE;
				break;
			case VIEWFSARGCOW:
				typeoption++;
				*pflags |= VIEWFS_MERGE | VIEWFS_COW;
				break;
			case VIEWFSARGMINCOW:
				typeoption++;
				*pflags |= VIEWFS_MERGE | VIEWFS_COW | VIEWFS_MINCOW;
				break;
			case VIEWFSARGRENEW:
				*pflags |= VIEWFS_RENEW;
				break;
			case 0:
				fprint2("viewfs unknown option %s\n",sepopts[i]);
				break;
		}
	}
	if (typeoption>1)
		return -EINVAL;
	  /* PHASE 2B set up exceptions (if there are) */
	if (nexceptions > 0) {
		char **newexceptions=*pexceptions=malloc((nexceptions+1)*sizeof(char *));
		if (newexceptions) {
			int i;
			for (i=0;i<nexceptions;i++)
				newexceptions[i]=strdup(exceptions[i]);
			newexceptions[i]=0;
		}
	}
	return 0;
}

