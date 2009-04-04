/*
 * Test program for kmview kernel module.
 *
 * Copyright (C) 2009 Renzo Davoli (renzo@cs.unibo.it)
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  Due to this file being licensed under the GPL there is controversy over
 *  whether this permits you to write a module that #includes this file
 *  without placing your module under the GPL.  Please consult a lawyer for
 *  advice before doing this.
 *
 * Compile install and load the module as described in ../README
 * compile this test:
 * $ gcc -o testx testx.c
 * 
 * $ ./testx t command args
 * run the command and print the syscall numbers and args.
 * it works like strace without a pretty printing of the call
 * 
 * e.g.  $ ./testx t ls
 * 972 - Syscall 1->6 3 7604 b7f45ff4 b7f6bce0 0 bfd6c248
 * 972 - Syscall 1->11 bfd6c11a bfd6c2ec bfd6c2f4 bfd6cf0e b7f45ff4 bfd6c178
 * .... (6 is open, 11 is exec) 
 * 
 *
 * $ ./testx o command args
 * run the command and for each "open" syscall print the path (limited to
 * 19 chars)
 * 
 * e.g. $ ./testx o ls
 * 976 - OPEN /etc/ld.so.cache
 * 976 - OPEN /lib/librt.so.1
 * 976 - OPEN /lib/libacl.so.1
 * ...
 *
 * $ ./testx v command args
 * is a basic virtualization. When the process tries to open /etc/passwd
 * /etc/hosts gets opened instead.
 *
 * $ head -1 /etc/passwd
 * root:x:0:0:root:/root:/bin/bash
 * $ ./testx v head -1 /etc/passwd
 * 127.0.0.1 localhost
 *
 * Tracing and virtualization can be safely nested.
 * Try:
 * $ ./testx o ./testx v ./testx o head -1 /etc/passwd
 * the result is:
 * ....
 * 989 - OPEN /etc/ld.so.cache
 * 987 - OPEN /etc/ld.so.cache
 * 989 - OPEN /lib/libc.so.6
 * 987 - OPEN /lib/libc.so.6
 * 989 - OPEN /etc/passwd
 * 987 - OPEN /etc/hosts
 * 127.0.0.1 localhost
 * 
 * the tracer 'outside' the virtualization (987 in this output) gets 
 * /etc/passwd while the tracer running 'inside' (989) gets /etc/hosts.
 */

#include <stdio.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include "../kmview.h"

void dowait(int signal)
{
	int w;
	wait(&w);
}

main(int argc, char *argv[])
{
	int fd;
	struct kmview_event event;
	fd=open("/dev/kmview",O_RDONLY);
	signal(SIGCHLD,dowait);
	if (fork()) {
		while (1) {
			int rv=read(fd,&event,sizeof(event));
			switch (event.tag) {
				case KMVIEW_EVENT_NEWTHREAD:
					{
						struct kmview_ioctl_umpid ump;
						ump.kmpid=event.x.newthread.kmpid;
						ump.umpid=event.x.newthread.kmpid; /* we use umpid == kmpid */
						ioctl(fd, KMVIEW_UMPID, &ump);
						break;
					}
				case KMVIEW_EVENT_TERMTHREAD:
					if (event.x.termthread.remaining == 0)
						exit (0);
					break;
				case KMVIEW_EVENT_SYSCALL_ENTRY:
					if  (*argv[1] == 't') {
						printf("%d - Syscall %d->%d %x %x %x %x %x %x\n",
								getpid(),
								event.x.syscall.x.umpid, event.x.syscall.scno,
								event.x.syscall.args[0], event.x.syscall.args[1],
								event.x.syscall.args[2], event.x.syscall.args[3],
								event.x.syscall.args[4], event.x.syscall.args[5]
								);
					} else if (event.x.syscall.scno == __NR_open) {
						char buf[20];
						int len;
						struct kmview_ioctl_data vdata={
							.kmpid=event.x.syscall.x.umpid,
							.addr=event.x.syscall.args[0],
							.len=19, .localaddr=buf};
						len=ioctl(fd,KMVIEW_READSTRINGDATA,&vdata);
						buf[len]=0;
						vdata.len=len;
						if  (*argv[1] == 'o')
							printf("%d - OPEN %s\n",getpid(),buf);
						else if (*argv[1] == 'v' && strcmp(buf,"/etc/passwd")==0) {
							strcpy(buf,"/etc/hosts");
							ioctl(fd,KMVIEW_WRITEDATA,&vdata);
						}
					}
					ioctl(fd, KMVIEW_SYSRESUME, event.x.syscall.x.umpid);
					break;
				case KMVIEW_EVENT_SYSCALL_EXIT:
					ioctl(fd, KMVIEW_SYSRETURN, &event.x.sysreturn);
					break;
			}
		}
	} else { /* traced root process*/
		ioctl(fd, KMVIEW_ATTACH);
		close(fd);
		argv+=2;
		execvp(argv[0],argv);
	}
}

