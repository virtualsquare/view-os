#include <stdio.h>
#include <string.h>
#include <alloca.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <config.h>

/* return value: 0=the file is mmapable, 1 otherwise */
static int mmap_not_ok(char *path)
{
	int fd=open(path,O_RDONLY);
	if (fd >= 0) {
		void *tmp;
		int rv;
		tmp=mmap(0,4,PROT_NONE,MAP_PRIVATE,fd,0);
		rv=(tmp == MAP_FAILED);
		close(fd);
		return rv;
	} else
		return 0;
}

/* filecopy copies a file as a tmp file */
char *filecopy(char *from)
{
	char buf[BUFSIZ];
	int fdf,fdt;
	int n;
	static char tempbin[]="/tmp/.umbinfmtXXXXXX";
	mode_t oldmask=umask(0077);
	fdt=mkstemp(tempbin);
	umask(oldmask);
	if (fdt < 0)
		return NULL;
	if ((fdf=open(from,O_RDONLY,0)) < 0)
		return NULL;
	while ((n=read(fdf,buf,BUFSIZ)) > 0)
		write (fdt,buf,n);
	close(fdf);
	fchmod (fdt,0700); 
	close (fdt);
	return tempbin;
}

int execv_nommap(char *cmd,char *argv[]) {
	char *tempbin=filecopy(argv[1]);
	char templock[]="/tmp/.umbinfmtlockXXXXXX";
	int fdlock=mkstemp(templock);
	int pid;
	argv[1]=tempbin;
	if (tempbin == NULL || fdlock < 0)
		return -1;
	else {
		lockf(fdlock,F_LOCK,0);
		unlink(templock);
		if ((pid=fork()) > 0) 
			execv(cmd,argv);
		else if (pid==0) {
			/* watchdog process: if it takes the log it means that
			 * the parent process has exited */
			lockf(fdlock,F_LOCK,0);
			unlink(tempbin);
			close(fdlock);
		} else
			return -1;
		return 0;
	}
}

int main(int argc,char* argv[])
{
	char *split;
	char esc=*argv[0];
	(argv[0])++;
	if ((split=strchr(argv[0],esc)) != NULL) {
		char *split2;
		char *cmd;
		int i;
		char **newargv=alloca(argc+2);
		*split=0;
		split++;
		cmd=argv[0];
		if ((split2=strchr(split,esc)) != NULL) {
			*split2=0;
			split2++;
			newargv[0]=split;
			newargv[1]=split2;
		} else {
			newargv[0]=cmd;
			newargv[1]=split;
		}
		for (i=1;i<argc;i++)
			newargv[i+1]=argv[i];
		newargv[i+1]=0;
		if (mmap_not_ok(newargv[1])) 
			execv_nommap(cmd,newargv);
		else
			execv(cmd,newargv);
		return 0;
	} else {
		fprintf(stderr, "UMBINWRAP is a tool for Virtual BinFmt support\n"
				" This program does not run as a command\n\n");
		return -1;
	}
}
