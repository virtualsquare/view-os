/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   um_tag.c 
 *   management of mount tags.
 *   
 *   Copyright 2009 Renzo Davoli University of Bologna - Italy
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
 *   $Id: viewname.c 464 2008-04-17 10:53:55Z garden $
 *
 */   
#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <config.h>
#include <errno.h>
#include <ctype.h>
#include <um_lib.h>

char *tagname[32];

void usage()
{
	fprintf(stderr, 
			"Usage:\n"
			"\tum_tag set tagset command args\n"
			"\tum_tag add tagset command args\n"
			"\tum_tag del tagset command args\n"
			"\tum_tag get\n"
			"\tum_tag lget\n"
			"\tum_tag list tagset\n"
			"\tum_tag llist tagset\n"
			"\tum_tag listall\n"
			"\tum_tag setname tag name\n"
			"\tum_tag getname tag\n"
			"\n"
			"Management of View-OS mount tags\n"
			"\n");
	exit(1);
}

char *command_tags[]={"set","add","del","get","lget","list","llist","listall","setname","getname",NULL};
char  command_argc[]={    4,    4,    4,    2,     2,     3,     3,        2,        4,        3,   0};
enum command         { set,  add,  del,  get,  lget,  list,  llist,  listall,  setname,  getname, error};

int str2tag_single(char *s) {
	int tag;
	if (isdigit(*s))
		tag=atoi(s);
	else {
		for (tag=0; tag<32; tag++)
			if (strcmp(s,tagname[tag]) == 0)
				break;
	}
	if (tag < 0 || tag >= 32)
		fprintf(stderr,"Tag '%s' unknown\n",s);
	return tag;
}

int str2tags_single (char *s){
	int tags=0;
	if (strncmp(s,"0x",2) == 0) {
		sscanf(s+2,"%x",&tags);
	} else
		tags = 1<<str2tag_single(s);
	//printf("str2tags_single  %s %x\n",s,tags);
	return tags;
}

int str2tags (char *s) {
	char *next;
	int tags=0;
	while((next=strtok(s,",")) != NULL) {
		tags |= str2tags_single(next);
		s=NULL;
	}
	return tags;
}

int str2tag (char *s)
{
	if (strncmp(s,"0x",2) == 0) {
		int tags,tag;
		sscanf(s+2,"%x",&tags);
		for (tag=0; tag<32; tag++) {
			if (tags & (1<<tag)) {
				tags &= ~(1<<tag);
				if (tags) 
					fprintf(stderr,"'%s' does not refer to a single tag. Using '0x%08x' instead\n",1<<tag);
				return tag;
			}
		}
		return 0;
	} else
		return str2tag_single(s);
}

enum command getcommand(char *command)
{
	int i;
	while (command_tags[i] != NULL && strcmp(command_tags[i],command) != 0)
		i++;
	return (enum command) i;
}

main(int argc, char *argv[])
{
	int tag;
	enum command cmd;
	int tags; 
	int rv=0;
	if (argc < 2)
		usage();
	for (tag=0; tag<32; tag++) {
		char buf[256];
		rv=um_tagstring(VIEWOS_TAGSTRING_GET,tag,buf,256);
		tagname[tag]=strdup(buf);
	}
	cmd=getcommand(argv[1]);
	if (argc < command_argc[cmd])
		usage();
	if (cmd>2 && argc > command_argc[cmd])
		usage();
	switch (cmd) {
		case set:
			tags=str2tags(argv[2]);
			//printf("%08x\n",tags);
			rv=um_tag(VIEWOS_TAG_SET, &tags, NULL, sizeof(int));
			execvp(argv[3],argv+3);
			break;
		case add:
			tags=str2tags(argv[2]);
			//printf("%08x\n",tags);
			rv=um_tag(VIEWOS_TAG_ADD, &tags, NULL, sizeof(int));
			execvp(argv[3],argv+3);
			break;
		case del:
			tags=str2tags(argv[2]);
			//printf("%08x\n",tags);
			rv=um_tag(VIEWOS_TAG_DEL, &tags, NULL, sizeof(int));
			execvp(argv[3],argv+3);
			break;
		case get:
			rv=um_tag(VIEWOS_TAG_SET, NULL, &tags, sizeof(int));
			if (rv == 0)
				printf("0x%08x\n",tags);
			break;
		case lget: 
			rv=um_tag(VIEWOS_TAG_SET, NULL, &tags, sizeof(int));
			if (rv == 0) {
				char *sep="";
				for (tag=0; tag<32; tag++) {
					if (tags & 1<<tag) {
						if (tagname[tag][0])
							printf("%s%s",sep,tagname[tag]);
						else
							printf("%s%02d",sep,tag);
						sep=",";
					}
				}
				printf("\n");
			}
			break;
		case list: 
			tags=str2tags(argv[2]);
			char *sep="";
			for (tag=0; tag<32; tag++) {
				if (tags & 1<<tag) {
					if (tagname[tag][0])
						printf("%s%s",sep,tagname[tag]);
					else
						printf("%s%02d",sep,tag);
					sep=",";
				}
			}
			printf("\n");
			break;
		case llist: 
			tags=str2tags(argv[2]);
			printf("   0x%08x\n",tags);
			for (tag=0; tag<32; tag++) {
				if (tags & 1<<tag) {
					printf("%02d 0x%08x %s\n",tag,1<<tag,tagname[tag]);
				}
			}
			break;
		case listall:
			for (tag=0; tag<32; tag++) {
				if (tagname[tag][0]) {
					printf("%02d 0x%08x %s\n",tag,1<<tag,tagname[tag]);
				}
			}
			break;
		case setname:
			tag=str2tag(argv[2]);
			um_tagstring(VIEWOS_TAGSTRING_SET,tag,argv[3],strlen(argv[3]));
			break;
		case getname:
			tag=str2tag(argv[2]);
			printf("%02d 0x%08x %s\n",tag,1<<tag,tagname[tag]);
			break;
	}
	if (rv < 0) {
		fprintf(stderr, "Error: %s\n", strerror(errno));
		exit(1);
	}
	exit (0);
}
