/*   This is part of km-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   loginshell.c: Support for view-os as login shell
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
 */

#include<stdio.h>
#include<limits.h>
#include<stdlib.h>
#include<unistd.h>
#include<string.h>
#include<sys/types.h>
#include<pwd.h>
#include<defs.h>
#include<loginshell.h>

int main(int argc,char *argv[]);

static void loginshell_error(char *s)
{
	printk("View-OS login configuration error: %s\n",s);
	sleep(3);
	exit(1); 
}

#define NEWARG ' '
#define CHAR 'A'

/* Finite State Automaton for arg quoting
states: NEWARG -> beginning of a new arg
        CHAR -> a char
				\ -> protected char 
				' " -> quoted part
				'+1 "+1 (i.e. ( or # ) -> protected char inside quote */
static int fsa(char state, char in)
{
	switch (state) {
		case NEWARG:
		case CHAR:
			switch (in) {
				case ' ':
				case '\t':
					state=NEWARG;
					break;
				case '\\':
				case '\'':
				case '"':
					state=in;
					break;
				default:
					state=CHAR; /* outchar */
					break;
			}
			break;
		case '\\':
			state=CHAR; /* outchar */
			break;
		case '\'':
		case '"':
			if (in == '\\')
				state = state+1;
			if (in == state)
				state=CHAR;
			/* else outchar */
			break;
		default:
			state -= 1;
			break;
	}
	return state;
}

/* first scan: count the args,
	 each trasition NEWARG->something else counts one more arg */
static int argcount(char *s)
{
	int state=NEWARG;
	int newstate;
	int argc=0;
	for(state=NEWARG;*s != 0;state=newstate,s++) {
		newstate=fsa(state,*s);
		if (state==NEWARG && newstate!=NEWARG)
			argc++;
	}
	return argc;
}

/* second scan: split and strip quoting chars at the same time:
	 FSA used as a translator. 
	 On site translation (on the same string): the traslation is always
	 not longer than tha original string */
static char **splitargs(char *s,char **argv)
{
	int state=NEWARG;
	int newstate;
	int argc=0;
	char *t=s;
	for(state=NEWARG;*s != 0;state=newstate,s++) {
		newstate=fsa(state,*s);
		//printf("%c %c->%c %s\n",*s,state,newstate,s);
		if (state==NEWARG && newstate!=NEWARG)
			argv[argc++]=t;
		switch (state) {
			case NEWARG:
			case CHAR:
				if (newstate==CHAR)
					*t++=*s;
				break;
			case '\\':
			case '\''+1:
			case '"'+1:
				*t++=*s;
				break;
			case '\'':
			case '"':
				if (newstate==state)
					*t++=*s;
				break;
		}
		if (state!=NEWARG && newstate==NEWARG)
			*t++=0;
	}
	*t=0;
	return argv;
}

/* search the command inside /etc/viewospasswd */
#define LOGINBUFSIZE 1024
static char *loginshell_path(void)
{
	FILE *f=fopen("/etc/viewospasswd","r");
	char buf[LOGINBUFSIZE],*line;
	char *username;
	int usernamelen;
	char *loginshell=NULL;
	struct passwd pwd,*result;
	getpwuid_r(getuid(),&pwd,buf,LOGINBUFSIZE,&result);
	if (result==NULL)
		loginshell_error("This user does not exist!");
	asprintf(&username,"%s:",result->pw_name);
	usernamelen=strlen(username);
	if (f==NULL)
		loginshell_error("/etc/viewospasswd missing");
	while ((line=fgets(buf,LOGINBUFSIZE,f)) != NULL) {
		while (*line==' ' || *line=='\t')
			line++;
		if (*line=='#' || *line=='\n' || *line==0)
			continue;
		if (strncmp(line,username,usernamelen)==0) {
			loginshell=line+usernamelen;
			break;
		}
	}
	if (loginshell == NULL)
		loginshell_error("User not in /etc/viewospasswd");
	free(username);
	line=loginshell+strlen(loginshell);
	line--;
	while (*line == '\n' || *line== '\t' || *line== ' ')
		*line-- = 0;
	return strdup(loginshell);
}

/* call the main program again:
	 use the command specified in /etc/viewospasswd */
void loginshell_view(void)
{
	char *command=loginshell_path();
	int argc=argcount(command)+1;
	char *argv[argc+1];
	argv[0]=LOGIN_SHELL_ARG0;
	argv[argc]=0;
	splitargs(command,argv+1);
	main(argc,argv);
}
