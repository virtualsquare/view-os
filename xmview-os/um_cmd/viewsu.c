#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <getopt.h>
#include <pwd.h>
#include <string.h>

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

void usage(void)
{
	fprintf(stderr,
			"Usage: su [options] [LOGIN]\n"
			"\n"
			"Options:\n"
			"  -c, --command COMMAND         pass COMMAND to the invoked shell\n"
			"  -h, --help                    display this help message and exit\n"
			"  -, -l, --login                make the shell a login shell\n"
			//"  -m, -p,\n"
			//"  --preserve-environment        do not reset environment variables, and\n"
			"                                keep the same shell\n"
			"  -s, --shell SHELL             use SHELL instead of the default in passwd\n"
			"\n"
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
			case 'h': usage();
								break;
		}
	}

	if (argc > optind+1)
		usage();

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
		shell=pwd->pw_shell;
	} else {
		pwd=getpwuid(0);
		if(pwd)
			shell=pwd->pw_shell;
	}
	if (pwd)
		setenv("HOME",pwd->pw_dir,1);
	if (!shell) 
		shell="/bin/sh";
	setenv("SHELL",shell,1);
	if (login)
		asprintf(&arg0,"-%s",shell);
	else
		arg0=shell;

	switch (pid=fork()) {
		case -1: exit(2);
		case 0: 
						 setresuid(uid,uid,uid);
						 setresgid(gid,gid,gid);
						 setpath();
						 if (command)
							 execl(shell,arg0,"-c",command,0);
						 else
							 execl(shell,arg0,0);
						 break;
		default:
						 waitpid(pid,&status,0);
	}
}
