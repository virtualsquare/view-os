/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   umbinwrap.c: wrapper for executables. In ViewOS "execve" executes 
 *   this program.
 *   If mmap does not work for the executable (it is the case of some
 *   virtual file systems) it copies the executable and uses a watchdog
 *   process to clean up the copy when the execution terminates.
 * 
 *   Copyright 2007 Renzo Davoli University of Bologna - Italy
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
#include <string.h>
#include <alloca.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
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
			/* watchdog process: if it takes the lock it means that
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
	char *s=argv[0];
	char sep=*s;
	char *cmd;
	char **newargv=alloca((argc+3)*sizeof(char *));
	int i;
	int sargc=0;
	*s=0;
	for(i=1;s[i]!=0;i++) {
		if (s[i-1]==0)
			newargv[sargc++]=s+i;
		if (s[i]==sep)
			s[i]=0;
	}
	cmd=newargv[0];
	if (sargc>3) {
		newargv[0]=newargv[3];
		sargc=3;
	}
	if (*newargv[1] == 0) {
		newargv[1]=newargv[2];
		sargc--;
	}
	sargc--;
	for (i=1;i<argc;i++)
		newargv[i+sargc]=argv[i];
	newargv[i+sargc]=0;
#if 0
	for (i=0;i<argc+sargc;i++)
		fprintf(stderr,"%d %s\n",i,newargv[i]);
#endif
	if (mmap_not_ok(newargv[1])) 
		execv_nommap(cmd,newargv);
	else
		execv(cmd,newargv);
	return 0;
}
