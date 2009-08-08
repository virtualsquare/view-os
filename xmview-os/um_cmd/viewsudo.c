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
	{"help", 1, 0, 'h'},
	{0, 0, 0, 0}
};

char *command;
char *user;
char *group;
int uid;
int gid;

void usage(char *argv0)
{
	char *name=basename(argv0);
	fprintf(stderr,
			"Usage: %s [options] [LOGIN]\n"
			"\n"
			"Options:\n"
			"  -u  username|#uid\n"
			"  -g  groupname|#gid\n"
			"\n",
			name
			);
	exit(2);
}

int main(int argc, char *argv[])
{
	pid_t pid;
	int status;
	int c;
	struct passwd *pwd;
	if (um_check_viewos()==0) {
		fprintf(stderr,"This is a View-OS command. It works only inside a umview/kmview virtual machine\n");
		usage(argv[0]);
	}
	while (1) {
		int option_index = 0;
		c = getopt_long(argc, argv, "u:g:h",
				long_options, &option_index);
		if (c == -1)
			break;
		switch (c) {
			case 'u':user=optarg;
							 break;
			case 'g':group=optarg;
							 break;
			case 'h': usage(argv[0]);
								break;
		}
	}
	if (argc==optind)
		usage(argv[0]);

	if (user) {
		if (*user == '#')
			uid=atoi(user+1);
		else {
			pwd=getpwnam(user);
			if (pwd == NULL) {
				fprintf(stderr,"Unknown id: %s\n",user);
				exit(1);
			}
			uid=pwd->pw_uid;
		}
	} else if (group)
		uid=getuid();
	if (pwd==NULL)
		pwd=getpwuid(uid);
	if (pwd) {
		gid=pwd->pw_gid;
		setenv("HOME",pwd->pw_dir,1);
	} 
	if (group) {
		if (*group == '#')
			gid=atoi(group+1);
		else {
			struct group *grp=getgrnam(group);
			if (grp == NULL) {
				fprintf(stderr,"Unknown group id: %s\n",group);
				exit(1);
			}
			gid=grp->gr_gid;
		}
	}
	switch (pid=fork()) {
		case -1: exit(1);
		case 0: 
						 setresuid(uid,uid,uid);
						 setresgid(gid,gid,gid);
						 execvp(argv[optind],argv+optind);
						 break;
		default:
						 waitpid(pid,&status,0);
						 return(WEXITSTATUS(status));
	}
}
