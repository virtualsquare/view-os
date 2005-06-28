/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   example of um-ViewOS module
 *   
 *   Copyright 2005 Renzo Davoli University of Bologna - Italy
 *   
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 *   $Id$
 *
 */   
#include <unistd.h>
//#include <fcntl.h>
//#include <sys/types.h>
//#include <sys/stat.h>
//#include <sys/ioctl.h>
//#include <sys/poll.h>
//#include <string.h>
#include <dlfcn.h>
#include "module.h"
#include "lwip/sockets.h"
#include <linux/net.h>
#include <limits.h>
#include "asm/unistd.h"
#include "sockmsg.h"

static struct service s;

static int alwaysfalse()
{
	return 0;
}

static int alwaystrue(char *path)
{
	return 1;
}

static int check(int domain)
{
	return(domain == AF_INET || domain == PF_INET6 || domain == PF_NETLINK || domain == PF_PACKET);
}

struct libtab {
	int tag;
	enum {SOCK, SYS} choice;
	char *funcname;
} lwiplibtab[] = {
	{SYS_SOCKET, 	SOCK, 	"lwip_socket"},
	{SYS_BIND,	SOCK,	"lwip_bind"},
	{SYS_CONNECT,	SOCK,	"lwip_connect"},
	{SYS_LISTEN,	SOCK,	"lwip_listen"},
	{SYS_ACCEPT,	SOCK,	"lwip_accept"},
	{SYS_GETSOCKNAME,	SOCK,	"lwip_getsockname"},
	{SYS_GETPEERNAME,	SOCK,	"lwip_getpeername"},
	{SYS_SEND,	SOCK,	"lwip_send"},
	{SYS_RECV,	SOCK,	"lwip_recv"},
	{SYS_SENDTO,	SOCK,	"lwip_sendto"},
	{SYS_RECVFROM,	SOCK,	"lwip_recvfrom"},
	{SYS_SHUTDOWN,	SOCK,	"lwip_shutdown"},
	{SYS_SETSOCKOPT,	SOCK,	"lwip_setsockopt"},
	{SYS_GETSOCKOPT,	SOCK,	"lwip_getsockopt"},
	//{SYS_SENDMSG,	SOCK,	"lwip_sendmsg"},
	//{SYS_RECVMSG,	SOCK,	"lwip_recvmsg"},
	{__NR_read,	SYS,	"lwip_read"},
	{__NR_write,	SYS,	"lwip_write"},
	{__NR_readv,	SYS,	"lwip_readv"},
	{__NR_writev,	SYS,	"lwip_writev"},
	{__NR_close,	SYS,	"lwip_close"},
	{__NR_fcntl,	SYS,	"lwip_fcntl"},
	{__NR_fcntl64,	SYS,	"lwip_fcntl64"},
	{__NR_ioctl,	SYS,	"lwip_ioctl"},
	//{__NR__newselect,	SYS,	"alwaysfalse"},
	//{__NR_poll,	SYS,	"alwaysfalse"}
};
#define SIZEOFLIBTAB (sizeof(lwiplibtab)/sizeof(struct libtab))
static void *lwiphandle;

static void openlwiplib()
{
	lwiphandle=dlopen("liblwip.so",RTLD_NOW);
	if(lwiphandle==NULL) {
		fprintf(stderr,"lwiplib not found\n");
	} else {
		int i;
		for (i=0;i<SIZEOFLIBTAB;i++) {
			intfun fun;
			if ((fun=dlsym(lwiphandle,lwiplibtab[i].funcname)) != NULL)
			{
				if (lwiplibtab[i].choice==SOCK)
					s.socket[lwiplibtab[i].tag]=fun;
				else
					s.syscall[uscno(lwiplibtab[i].tag)]=fun;
			}
		}
	}
	s.select_register=dlsym(lwiphandle,"lwip_select_register");
}
		
ssize_t lwip_recvmsg(int fd, struct msghdr *msg, int flags) {
	int rv;
	rv=(s.socket[SYS_RECVFROM])(fd,msg->msg_iov->iov_base,msg->msg_iov->iov_len,flags,
			msg->msg_name,&msg->msg_namelen);
	msg->msg_controllen=0;
	return rv;
}

ssize_t lwip_sendmsg(int fd, const struct msghdr *msg, int flags) {
	int rv;
	rv=(s.socket[SYS_SENDTO])(fd,msg->msg_iov->iov_base,msg->msg_iov->iov_len,flags,
			msg->msg_name,msg->msg_namelen);
	return rv;
}

static char *intname[]={"vd","tp","tn"};
static void myputenv(char *arg)
{
	static char intnum[sizeof(intname)/sizeof(char *)];
	int i,j;
	char env[PATH_MAX];
	for (i=0;i<(sizeof(intname)/sizeof(char *));i++) {
		if (strncmp(arg,intname[i],2)==0 && arg[2] >= '0' && arg[2] <= '9') {
			if (arg[3] == '=') {
				sprintf(env,"LWIPV6%s%c=%s",intname[i],arg[2],arg+4);
				putenv(env);
				printf("E=%s\n",env);
				if (arg[2]-'0' > intnum[i]) intnum[i]=arg[2]-'0'+1;
			}
			else if (arg[3] == 0) {
				intnum[i] = arg[2]-'0';
			}
			sprintf(env,"LWIPV6LIB=%s%c",intname[0],intnum[0]+'0');
			for (j=1;j<(sizeof(intname)/sizeof(char *));j++)
				sprintf(env,"%s,%s%c",env,intname[j],intnum[j]+'0');
			putenv(env);
			printf("E=%s\n",env);
			break;
		}
	}	
}

static void lwipargtoenv(char *initargs)
{
	char *next;
	char *unquoted;
	char quoted=0;

	while (*initargs != 0) {
		next=initargs;
		unquoted=initargs;
		while ((*next != ',' || quoted) && *next != 0) {
			*unquoted=*next;
			if (*next == quoted)
				quoted=0;
			else if (*next == '\'' || *next == '\"')
				quoted=*next; 
			else
				unquoted++;
			next++;
		}
		if (*next == ',') {
			*unquoted=*next=0;
			next++;
		}
		if (*initargs != 0)
			myputenv(initargs);
		initargs=next;
	}
}


static int initflag=0;
static void
__attribute__ ((constructor))
init (void)
{
	initflag=1;
}

void _um_mod_init(char *initargs)
{
	if (initflag) {
		printf("lwipv6 init\n");
		s.name="light weight ipv6 stack";
		s.code=0x02;
		lwipargtoenv(initargs);
		s.checkpath=alwaysfalse;
		s.checksocket=check;
		s.syscall=(intfun *)calloc(1,scmap_scmapsize * sizeof(intfun));
		s.socket=(intfun *)calloc(1,scmap_sockmapsize * sizeof(intfun));
		openlwiplib();
		s.syscall[uscno(__NR__newselect)]=alwaysfalse;
		s.syscall[uscno(__NR_poll)]=alwaysfalse;
		s.socket[SYS_SENDMSG]=lwip_sendmsg;
		s.socket[SYS_RECVMSG]=lwip_recvmsg;

		add_service(&s);
		initflag=0;
	}
}

static void
__attribute__ ((destructor))
fini (void)
{
	if(lwiphandle != NULL)
		dlclose(lwiphandle);
	free(s.syscall);
	free(s.socket);
	printf("lwipv6 fini\n");
}
