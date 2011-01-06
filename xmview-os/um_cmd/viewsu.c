/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   viewsu user command
 *   
 *   Copyright 2005 Renzo Davoli University of Bologna - Italy
 *   
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License, version 2 or 
 *   (at your option) any later version, as published by the Free Software Foundation.
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
 *   $Id: um_add_service.c 775 2009-09-01 21:15:23Z rd235 $
 *
 */   
#include <config.h>
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <getopt.h>
#include <pwd.h>
#include <grp.h>
#include <string.h>
#include <libgen.h>
#include <um_lib.h>

static struct option long_options[] = {
	{"command", 1, 0, 'c'},
	{"login", 0, 0, 'l'},
	{"shell", 1, 0, 's'},
	{"preserve-environment", 0, 0, 'p'},
	{"help", 1, 0, 'h'},
	{0, 0, 0, 0}
};

char *command;
int login;
char *shell;
int preserve_environment;
char *user;
int uid;
int gid;
char *arg0;
int ngroups;
gid_t *groups;

void usage(char *argv0)
{
	char *name=basename(argv0);
	fprintf(stderr,
			"Usage: %s [options] [LOGIN]\n"
			"\n"
			"Options:\n"
			"  -c, --command COMMAND         pass COMMAND to the invoked shell\n"
			"  -h, --help                    display this help message and exit\n"
			"  -, -l, --login                make the shell a login shell\n"
			//"  -m, -p,\n"
			//"  --preserve-environment        do not reset environment variables, and\n"
			"                                keep the same shell\n"
			"  -s, --shell SHELL             use SHELL instead of the default in passwd\n"
			"\n",
			name
			);
	exit(2);
}

void setpath(void)
{
	char buf[1024];
	char *tag=(uid==0)?"ENV_SUPATH":"ENV_PATH";
	FILE *f=fopen("/etc/login.defs","r");
	char *path;
	if (f) {
		char *s;
		while((s=fgets(buf,1024,f)) != NULL) {
			while (*s==' ' || *s=='\t') s++;
			if (*s=='#') continue;
			if (strncmp(tag,s,strlen(tag))!=0) continue;
			s+=strlen(tag);
			if (*s != ' ' && *s != '\t') continue;
			while (*s==' ' || *s=='\t') s++;
			if (strncmp("PATH=",s,5)!=0) continue;
			s+=5;
			s[strlen(s)-1]=0;
			path=s;
			break;
		}
		fclose(f);
	}
	if (!path) {
		if (uid)
			path="/bin:/usr/bin";
		else
			path="/sbin:/bin:/usr/sbin:/usr/bin";
	}
	setenv("PATH",path,1);
}

int main(int argc, char *argv[])
{
	pid_t pid;
	int status;
	int c;
	struct passwd *pwd;
	
	/* outside viewos use su(1) */
	if (um_check_viewos()==0) 
		execvp("su",argv);
	
	while (1) {
		int option_index = 0;
		c = getopt_long(argc, argv, "c:ls:mph",
				long_options, &option_index);
		if (c == -1)
			break;
		switch (c) {
			case 'c': command=optarg;
								break;
			case 'l': login=1;
								break;
			case 's': shell=optarg;
								break;
		//	case 'm':
		//	case 'p': preserve_environment=1;
		//						break;
			case 'h': usage(argv[0]);
								break;
		}
	}

	if (argc > optind+1)
		usage(argv[0]);

	if (argc > optind) {
		if (strcmp(argv[optind],"-")==0)
			login=1;
		else
			user=argv[optind];
	}

	//if (!preserve_environment)
		//clearenv();
	if (user) {
		pwd=getpwnam(user);
		if (pwd == NULL) {
			fprintf(stderr,"Unknown id: %s\n",user);
			exit(1);
		}
		uid=pwd->pw_uid;
		gid=pwd->pw_gid;
		if (shell == NULL)
			shell=pwd->pw_shell;
	} else {
		user="root";
		pwd=getpwuid(0);
		if(pwd && shell == NULL)
			shell=pwd->pw_shell;
	}
	if (pwd)
		setenv("HOME",pwd->pw_dir,1);
	if (shell == NULL) 
		shell="/bin/sh";
	setenv("SHELL",shell,1);
	if (login)
		asprintf(&arg0,"-%s",shell);
	else
		arg0=shell;
	getgrouplist(user,gid,NULL,&ngroups);
	groups=malloc(ngroups * sizeof (gid_t));
	if (groups == NULL) 
		ngroups=0;
	else
		getgrouplist(user,gid,groups,&ngroups);

	switch (pid=fork()) {
		case -1: exit(1);
		case 0: 
						 if (setresuid(uid,uid,uid) < 0)
							 perror(argv[0]);
						 else {
							 setresgid(gid,gid,gid);
							 setgroups(ngroups,groups);
							 setpath();
							 if (command)
								 execl(shell,arg0,"-c",command,(char *)0);
							 else
								 execl(shell,arg0,(char *)0);
							 perror(arg0);
						 }
						 exit(1);
						 break;
		default:
						 waitpid(pid,&status,0);
						 exit(WEXITSTATUS(status));
	}
	return 0;
}
