/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   mstack: default stack choice
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
 *   $Id: um_add_service.c 362 2007-06-08 14:31:54Z rd235 $
 *
 */   
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <config.h>
#include <libgen.h>
#include <msocket.h>
#include <string.h>
#include <getopt.h>

#define AF_MAXMAX AF_MAX+2

#define MSTACK_VERBOSE 1
int flags;
char family[AF_MAXMAX];
char *fname[AF_MAXMAX]={
"PF_UNSPEC",
"PF_UNIX ",
"PF_INET",
"PF_AX25",
"PF_IPX",
"PF_APPLETALK",
"PF_NETROM",
"PF_BRIDGE",
"PF_ATMPVC",
"PF_X25",
"PF_INET",
"PF_ROSE",
"PF_DECnet",
"PF_NETBEUI",
"PF_SECURITY",
"PF_KEY",
"PF_NETLINK",
"PF_PACKET ",
"PF_ASH",
"PF_ECONET",
"PF_ATMSVC",
"PF_PROTO21",
"PF_SNA",
"PF_IRDA",
"PF_PPPOX",
"PF_WANPIPE",
"PF_PROTO26",
"PF_PROTO27",
"PF_PROTO28",
"PF_PROTO29",
"PF_PROTO30",
"PF_BLUETOOTH",
"PF_PROTO32",
"PF_PROTO33",
"PF_PROTO34"};

void usage()
{
	fprintf(stderr, "Usage:\n\tmstack [-hv] [-o protocol_list] stack_mountpoint command\n"
			"protocol_list may include: all, unix, ipv4, ipv6, netlink, irda or #num \n"
			"  protocols may be prefixed by + (add) - (delete)\n");
	exit(2);
}

static uint32_t hash4(char *s) {
	uint32_t result=0;
	uint32_t wrap=0;
	while (*s) {
		wrap = result >> 24;
		result <<= 8;
		result |= (*s ^ wrap);
		s++;
	}
	return result;
}

static void mstack_setproto(char *args,char *proto,int *flags)
{
	char *str, *token, *saveptr;
	int i,val=1;
	if (args[0] != '-') {
		for (i=0; i<AF_MAXMAX; i++)
			proto[i]=0;
	}
	for (str=args;
			(token=strtok_r(str, ",", &saveptr))!=NULL;str=NULL) {
		if (*token=='+' || *token=='-') {
			val=(*token=='+')?1:0;
			token++;
		}
		switch (hash4(token)) {
			case 0x00000000:
			case 0x00616c6c: for (i=0; i<AF_MAXMAX; i++)
												 proto[AF_UNIX]=val;
											 break;
			case 0x00000075:
			case 0x756e6978: proto[AF_UNIX]=val; break;
			case 0x00000034:
			case 0x69707634: proto[AF_INET]=val; break;
			case 0x00000036:
			case 0x69707636: proto[AF_INET6]=val; break;
			case 0x0000006e:
			case 0x6c070b1f: proto[AF_NETLINK]=val; break;
			case 0x00000070:
			case 0x636b1515: proto[AF_PACKET]=val; break;
			case 0x00000062:
			case 0x031a117e: proto[AF_BLUETOOTH]=val; break;
			case 0x00000069:
			case 0x69726461: proto[AF_IRDA]=val; break;
			case 0x00006970: proto[AF_INET]=val;
											 proto[AF_INET6]=val;
											 proto[AF_NETLINK]=val;
											 proto[AF_PACKET]=val;
											 break;
			default: if (*token == '#' || *token == 'f') {
								 int family=atoi(token+1);
								 if (family > 0 && family < AF_MAXMAX)
									 proto[family]=val;
								 else
									 fprintf(stderr,"mstack: unknown protocol \"%s\"\n",token);
							 } else
								 fprintf(stderr,"mstack: unknown protocol \"%s\"\n",token);
							 break;
		}
	}
}

struct option long_options[] = {
	{"help", 0, 0, 'h'},
	{"verbose", 0, 0, 'v'},
	{"options", 1, 0, 'o'},
	{"protocols", 1, 0, 'o'},
	{"proto", 1, 0, 'o'},
	{0, 0, 0, 0}
};

main(int argc, char *argv[])
{
	int i,c;
	argv++;
	argc--;
	for (i=1;i<AF_MAXMAX;i++)
		family[i]=1;
	while (**argv == '-') {
		char *s=*argv;
		s++;
		if (strcmp(s,"-help") == 0 || strcmp(s,"-verbose") == 0 ||
				strcmp(s,"-options") == 0 || strcmp(s,"-proto") == 0 ||
				strcmp(s,"-protocols") == 0)
			s[1]=0;
		while (*s) {
			switch (*s) {
				case 'h': usage(); break;
				case 'v': flags |= MSTACK_VERBOSE; break;
				case 'o':
				case 'p':
				case 'f': argc--; 
									argv++;
									mstack_setproto(*argv, family, &flags); break;
			}
			s++;
		}
		argv++;
		argc--;
	}
	if (argc < 2)
		usage();
	else {
		int fd;
		char *cmd;
		int all=1;
		for (i=1;i<AF_MAXMAX;i++)
			all *= family[i];
		if (all) {
			if (flags & MSTACK_VERBOSE)
				fprintf(stderr, "pid %d: stack %s for all supported protocol families\n",getpid(),argv[0]);
			if ((fd=msocket(argv[0],0,SOCK_DEFAULT,0)) < 0) {
				perror("mstack");
				exit(1);
			}
		}	else {
			for (i=1;i<AF_MAXMAX;i++)
				if (family[i]) {
					if (flags & MSTACK_VERBOSE)
						fprintf(stderr, "pid %d: stack %s for %d=%s\n",getpid(),argv[0],i,fname[i]);
					if ((fd=msocket(argv[0],i,SOCK_DEFAULT,0)) < 0) {
						perror("mstack: msocket");
						exit(1);
					}
				}
		}
		argv ++;
		argc --;
		cmd=strdup(argv[0]);
		argv[0]=basename(cmd);
		execvp(cmd,argv);
		perror("mstack: exec");
	}
}
