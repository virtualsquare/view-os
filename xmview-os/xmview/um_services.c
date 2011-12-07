/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   um_services: system call access to services mgmt
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
 *   $Id$
 *
 */   
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/utsname.h>
#include <sys/param.h>
#include <asm/ptrace.h>
#include <asm/unistd.h>
#include <linux/net.h>
#include <limits.h>
#include <dlfcn.h>
#include <pthread.h>
#include <errno.h>
#include <config.h>
#include "defs.h"
#include "sctab.h"
#include "hashtab.h"
#include "capture.h"
#include "utils.h"
#include "gdebug.h"
#include <mhash.h>

#define SALTSIZE 4
#define HASHPWDSIZE mhash_get_block_size(MHASH_SHA1)*2+SALTSIZE*2+1
static char *main_pwd;

static inline void add_alias(int type,char *alias,char *fsname)
{
	struct ht_elem *hte=ht_check(type,alias,NULL,0);
	if (hte) {
		free(ht_get_private_data(hte));
		if (*fsname==0)
			ht_tab_del(hte);
		else 
			ht_set_private_data(hte,strdup(fsname));
	} else {
		if (*fsname!=0)
			ht_tab_add(type,alias,strlen(alias),NULL,NULL,strdup(fsname));
	}
}

static char *rec_alias(int type,char *alias,int depth) {
	struct ht_elem *hte=ht_check(type,alias,NULL,0);
	if (hte) {
		if (depth > MAXSYMLINKS) 
			return alias;
		else
			return rec_alias(type,ht_get_private_data(hte),depth+1);
	} else
		return alias;
}

char *get_alias(int type,char *alias) {
	return rec_alias(type,alias,0);
}

#define _DEFAULT_PATH "/bin:/usr/bin"
static int r_execvp(const char *file, char *const argv[])
{
	if(strchr(file,'/') != NULL)
		return r_execve(file,argv,environ);
	else {
		char *path;
		char *envpath;
		char *pathelem;
		char buf[PATH_MAX];
		if ((envpath=getenv("PATH")) == NULL)
			envpath=_DEFAULT_PATH;
		path=strdup(envpath);
		while((pathelem=strsep(&path,":")) != NULL){
			if (*pathelem != 0) {
				register int i,j;
				for (i=0; i<PATH_MAX && pathelem[i]; i++)
					buf[i]=pathelem[i];
				if(buf[i-1] != '/' && i<PATH_MAX)
					buf[i++]='/';
				for (j=0; i<PATH_MAX && file[j]; j++,i++)
					buf[i]=file[j];
				buf[i]=0;
				if (r_execve(buf,argv,environ)<0 &&
						((errno != ENOENT) && (errno != ENOTDIR) && (errno != EACCES))) {
					free(path);
					return -1;
				}
			}
		}
		free(path);
		errno = ENOENT;
		return -1;
	}
}

static char hex[]="0123456789abcdef";
static inline unsigned int char2hex (char c)
{
	if (c>='0' && c<='9')
		return c-'0';
	if (c>='a' && c<='f')
		return c-'a';
	return 0;
}

static void sha1passwd(const char *ssalt, const char *pw, char *outstr) {
	char out[mhash_get_block_size(MHASH_SHA1)+SALTSIZE];
	char salt[SALTSIZE];
	int i;
	for (i=0; i<SALTSIZE; i++)
		salt[i]=(char2hex(ssalt[2*i])<<4) +char2hex(ssalt[2*i+1]);
	MHASH td;
	td=mhash_init(MHASH_SHA1);
	mhash(td, salt, SALTSIZE);
	mhash(td, pw, strlen(pw));
	strncpy(out,salt,SALTSIZE);
	mhash_deinit(td, out+SALTSIZE);
	for (i=0; i<mhash_get_block_size(MHASH_SHA1)+SALTSIZE; i++) {
		outstr[2*i]=hex[(unsigned char)out[i] >> 4];
		outstr[2*i+1]=hex[(unsigned char)out[i] & 0xf];
	}
	outstr[2*i]=0;
}

static void generatesalt(char *ssalt)
{
	int fd=r_open("/dev/urandom",O_RDONLY,0);
	int i;
	if (fd >= 0) {
		char salt[SALTSIZE];
		read(fd,salt,SALTSIZE);
		r_close(fd);
		for (i=0; i<SALTSIZE; i++) {
			ssalt[2*i]=hex[(unsigned char)salt[i] >> 4];
			ssalt[2*i+1]=hex[(unsigned char)salt[i] & 0xf];
		}
	} else {
		int i;
		for (i=0; i<2*SALTSIZE; i++)
			ssalt[i]='0';
	}
}

static int pwdcmp(const char *passwd, const char *attempt)
{
	char hash[HASHPWDSIZE];
	sha1passwd(passwd,attempt,hash);
	return strcmp(passwd,hash);
}

void hostcmd(struct pcb *pc)
{
	long largv=pc->sysargs[2];
	char cmd[PATH_MAX];
	char tty[256];
	char **argv=getparms(pc,largv);
	int fd;
	umovestr(pc,pc->sysargs[1],PATH_MAX,cmd);
	if (pc->sysargs[3] != umNULL)
		umovestr(pc,pc->sysargs[3],256,tty);
	else
		*tty=0;
	if (*tty) {
		fd=r_open(tty, O_RDWR, 0);
		if (fd<0) {
			pc->retval=-1;
			pc->erno=EINVAL;
			return;
		}
	} else
		fd=-1;
	if (fork()==0) {
		if (fd >= 0) {
			r_setsid();
			r_dup2(fd,0);
			r_dup2(fd,1);
			r_dup2(fd,2);
			r_ioctl(fd,TIOCSCTTY,0);
		}
		unsetenv("LD_PRELOAD");
		r_execvp(cmd,argv);
		exit(1);
	}
	if (fd >= 0)
		close(fd);
	freeparms(argv);
}

int wrap_in_umservice(int sc_number,struct pcb *pc,
		    struct ht_elem *hte, sysfun um_syscall)
{
	char buf[PATH_MAX];
	switch (pc->sysargs[0]) {
		case ADD_SERVICE:
			if (secure && capcheck(CAP_SYS_MODULE,pc)) {
				pc->retval= -1;
				pc->erno=EPERM;
			} else {
				if (umovestr(pc,pc->sysargs[1],PATH_MAX,buf) == 0) {
					int permanent=pc->sysargs[2];
					if (add_service(buf,permanent) < 0)
					{
						pc->retval=-1;
						pc->erno=errno;
					}
				} else {
					pc->retval= -1;
					pc->erno=EINVAL;
				}
			}
			break;
		case DEL_SERVICE:
			if (secure && capcheck(CAP_SYS_MODULE,pc)) {
				pc->retval= -1;
				pc->erno=EPERM;
			} else {
				if (umovestr(pc,pc->sysargs[1],PATH_MAX,buf) == 0) {
					if ((pc->retval=del_service(buf)) != 0) {
						pc->erno=errno;
					}
				}	else {
					pc->retval= -1;
					pc->erno=EINVAL;
				}
			}
			break;
		case LIST_SERVICE:
			if (pc->sysargs[2]>PATH_MAX) pc->sysargs[2]=PATH_MAX;
			pc->retval=list_services(buf,pc->sysargs[2]);
			pc->erno=errno;
			if (pc->retval > 0)
				ustorestr(pc,pc->sysargs[1],pc->retval,buf);
			break;
		case NAME_SERVICE:
			if (umovestr(pc,pc->sysargs[1],PATH_MAX,buf) == 0) {
				if (pc->sysargs[3]>PATH_MAX) pc->sysargs[3]=PATH_MAX;
				/* buf can be reused both for name and description */
				pc->retval=name_service(buf,buf,pc->sysargs[3]);
				pc->erno=errno;
				if (pc->retval == 0)
					ustorestr(pc,pc->sysargs[2],pc->sysargs[3],buf);
				} else {
					pc->retval= -1;
					pc->erno=EINVAL;
				}
				break;
				case RECURSIVE_VIEWOS:
				if (pcb_newfork(pc) >= 0) {
				pc->retval=0;
				pc->erno = 0;
			} else {
				pc->retval= -1;
				pc->erno = ENOMEM;
			}
			break;
		case VIEWOS_GETINFO:
			{
				struct viewinfo vi;
				memset (&vi,0,sizeof(struct viewinfo));
				pcb_getviewinfo(pc,&vi);
				ustoren(pc,pc->sysargs[1],sizeof(struct viewinfo),&vi);
				pc->retval=0;
				pc->erno = 0;
			}
			break;
		case VIEWOS_SETVIEWNAME: 
			{
				if (secure && capcheck(CAP_SYS_ADMIN,pc)) {
					pc->retval= -1;
					pc->erno=EPERM;
				} else {
					char name[_UTSNAME_LENGTH];
					umovestr(pc,pc->sysargs[1],_UTSNAME_LENGTH,name);
					name[_UTSNAME_LENGTH-1]=0;
					pcb_setviewname(pc,name);
					pc->retval=0;
					pc->erno = 0;
				}
			}
			break; 
		case VIEWOS_KILLALL: 
			killall(pc,pc->sysargs[1]);
			pc->retval=0;
			pc->erno = 0;
			break;
		case VIEWOS_ATTACH:
			if (secure && capcheck(CAP_SYS_ADMIN,pc)) {
				pc->retval= -1;
				pc->erno=EPERM;
			} else {
				pc->retval=capture_attach(pc,pc->sysargs[1]);
				if (pc->retval < 0) {
					pc->erno = - pc->retval;
					pc->retval = -1;
				}
			}
			break;
		case VIEWOS_FSALIAS:
			{
				if (secure && capcheck(CAP_SYS_ADMIN,pc)) {
					pc->retval= -1;
					pc->erno=EPERM;
				} else {
					char fsalias[256];
					char fsname[256];
					umovestr(pc,pc->sysargs[1],256,fsalias);
					umovestr(pc,pc->sysargs[2],256,fsname);
					add_alias(CHECKFSALIAS,fsalias,fsname);
					pc->retval=0;
					pc->erno = 0;
				}
			}
			break;
		case VIEWOS_PWD:
			switch (pc->sysargs[1]) {
				case UM_PWD_OP_CHANGE:
					if (secure && capcheck(CAP_SYS_ADMIN,pc)) {
						pc->retval= -1;
						pc->erno=EPERM;
					} else {
						char oldpwd[256];
						char newpwd[256];
						umovestr(pc,pc->sysargs[2],256,oldpwd);
						umovestr(pc,pc->sysargs[3],256,newpwd);
						if (main_pwd && pwdcmp(main_pwd,oldpwd) != 0) {
							pc->retval=-1;
							pc->erno=EPERM;
						} else {
							char hash[HASHPWDSIZE];
							if (main_pwd) free(main_pwd);
							if (*newpwd) {
								generatesalt(hash);
								sha1passwd(hash,newpwd,hash);
								main_pwd=strdup(hash);
							} else
								main_pwd=NULL;
							pc->retval=0;
							pc->erno = 0;
						}
					}
					break;
				case UM_PWD_OP_SET:
					if (secure && capcheck(CAP_SYS_ADMIN,pc)) {
						pc->retval= -1;
						pc->erno=EPERM;
					} else {
						char oldpwd[256];
						char newpwd[256];
						umovestr(pc,pc->sysargs[2],256,oldpwd);
						umovestr(pc,pc->sysargs[3],256,newpwd);
						if (main_pwd && pwdcmp(main_pwd,oldpwd) != 0) {
							pc->retval=-1;
							pc->erno=EPERM;
						} else if (strlen(newpwd)+1 != HASHPWDSIZE) {
							pc->retval=-1;
							pc->erno=EINVAL;
						} else {
							if (main_pwd) free(main_pwd);
							if (*newpwd)
								main_pwd=strdup(newpwd);
							else
								*main_pwd=0;
							pc->retval=0;
							pc->erno = 0;
						}
					}
					break;
				case UM_PWD_OP_ENCODE:
					{
						char oldpwd[256];                               
						char newpwd[HASHPWDSIZE];                                           
						umovestr(pc,pc->sysargs[2],256,oldpwd);
						generatesalt(newpwd);
						sha1passwd(newpwd,oldpwd,newpwd);
						ustorestr(pc,pc->sysargs[3],HASHPWDSIZE,newpwd);
						pc->retval=0;
						pc->erno = 0;
					}
					break;
			}
			break;
		case VIEWOS_CMD:
			{
				if (!hostcmdok) {
					pc->retval= -1;
					pc->erno=ENOSYS;
				} else if (secure && capcheck(CAP_SYS_ADMIN,pc)) {
					pc->retval= -1;
					pc->erno=EPERM;
				} else {
					char pwd[256];
					char cmd[256];
					char pty[256];
					if (pc->sysargs[4] == umNULL)
						*pwd=0;
					else
						umovestr(pc,pc->sysargs[4],256,pwd);
					umovestr(pc,pc->sysargs[1],256,cmd);
					umovestr(pc,pc->sysargs[3],256,pty);
					if (main_pwd != NULL && pwdcmp(main_pwd,pwd) != 0) {
						pc->retval=-1;
						pc->erno=EPERM;
					} else {
						hostcmd(pc);
						pc->retval=0;
						pc->erno = 0;
					}
				}
			}
			break;
		case VIEWOS_OPEN:
			 {
				 char pwd[256];
				 if (pc->sysargs[4] == umNULL)
					 *pwd=0;
				 else
					 umovestr(pc,pc->sysargs[4],256,pwd);
				 if (!hostcmdok) {
					 pc->retval= -1;
					 pc->erno=ENOSYS;
				 } else if (secure && capcheck(CAP_SYS_ADMIN,pc)) {
					 pc->retval= -1;
					 pc->erno=EPERM;
				 } else if (main_pwd != NULL && pwdcmp(main_pwd,pwd) != 0) {
					 pc->retval=-1;
					 pc->erno=EPERM;
				 } else {
					 pc->sysargs[0]=pc->sysargs[1];
					 pc->sysargs[1]=pc->sysargs[2];
					 pc->sysargs[2]=pc->sysargs[3];
					 pc->sysargs[3]=0;
					 pc->sysargs[4]=0;
					 putscno(__NR_open,pc);
					 pc->retval=pc->erno=0;
					 return SC_MODICALL;
				 }
			 }
			 break;
		default:
			 pc->retval = -1;
			 pc->erno = ENOSYS;
	}
	return SC_FAKE;
}

int wrap_out_umservice(int sc_number,struct pcb *pc)
{
	putrv(pc->retval,pc);
	puterrno(pc->erno,pc);
	return SC_MODICALL;
}

