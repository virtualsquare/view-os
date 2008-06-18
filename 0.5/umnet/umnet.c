/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   UMNET: (Multi) Networking in User Space
 *   Copyright (C) 2008  Renzo Davoli <renzo@cs.unibo.it>
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
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <dlfcn.h>
#include <time.h>
#include <pthread.h>
#include <sys/mount.h>
#include <linux/net.h>

#include <config.h>
#include "module.h"
#include "libummod.h"

#include "umnet.h"
#define S_IFSTACK 0160000
#define SOCK_DEFAULT 0

#define TRUE 1
#define FALSE 0

#define UMNET_SERVICE_CODE 0x07
#define DEFAULT_NET_PATH "/dev/net/default"

#ifndef __UMNET_DEBUG_LEVEL__
#define __UMNET_DEBUG_LEVEL__ 0
#endif

#ifdef __UMNET_DEBUG__
#define PRINTDEBUG(level,args...) printdebug(level, __FILE__, __LINE__, __func__, args)
#else
#define PRINTDEBUG(level,args...)
#endif

static struct service s;

struct umnet {
	char *path;
	int pathlen;
	void *dlhandle;
	struct timestamp tst;
	long count;
	struct umnet_operations *netops;
	unsigned long flags;
	long mode;
	uid_t uid;
	gid_t gid;
	time_t mounttime;
	time_t sockettime;
	void *private_data;
};

struct fileinfo {
	int nfd;
	struct umnet *umnet;
};
#if 0
#define WORDLEN sizeof(int *)
#define WORDALIGN(X) (((X) + WORDLEN) & ~(WORDLEN-1))
#define SIZEDIRENT64NONAME (sizeof(__u64)+sizeof(__s64)+sizeof(unsigned short)+sizeof(unsigned char))
#endif

#define MNTTABSTEP 4 /* must be a power of two */
#define MNTTABSTEP_1 (MNTTABSTEP-1)
#define FILETABSTEP 4 /* must be a power of two */
#define FILETABSTEP_1 (FILETABSTEP-1)

#define EXACT 1
#define SUBSTR 0

static struct fileinfo **filetab=NULL;
static int filetabmax=0;

static struct umnet **nettab=NULL;
static int nettabmax=0;

struct umnetdefault {
	int count;
	struct umnet *defstack[AF_MAXMAX];
};

static struct umnetdefault **defnet=NULL;
static int defnetsize=0;

static void cutdots(char *path)
{
	int l=strlen(path);
	l--;
	if (path[l]=='.') {
		l--;
		if(path[l]=='/') {
			if (l!=0) path[l]=0; else path[l+1]=0;
		} else if (path[l]=='.') {
			l--;
			if(path[l]=='/') {
				while(l>0) {
					l--;
					if (path[l]=='/')
						break;
				}
				if(path[l]=='/') {
					if (l!=0) path[l]=0; else path[l+1]=0;
				}
			}
		}
	}
}

/* Is it always "exact"? I think so (rd 20080420) */
static struct umnet *searchnet(char *path,int exact)
{
	register int i;
	struct umnet *result=NULL;
	struct stat64 buf;
	epoch_t maxepoch=0;
	int maxi=-1;

	PRINTDEBUG(0,"SearchNetContext:%s\n",path);
	if (path==NULL)
		fprint2("SearchNetContext:%s\n",path);
	cutdots(path);
	for (i=0;i<nettabmax;i++)
	{
		epoch_t e;
		if ((nettab[i] != NULL)) {
			epoch_t prevepoch=um_setepoch(nettab[i]->tst.epoch);
			//fprint2("%s %s %d\n",path,nettab[i]->path,exact);
			//fprint2("]]%d %d\n",strncmp(path,nettab[i]->path,nettab[i]->pathlen),tst_matchingepoch(&(nettab[i]->tst)));
			if (exact) {
				if ((strcmp(path,nettab[i]->path) == 0) &&
						((e=tst_matchingepoch(&(nettab[i]->tst))) > maxepoch)) {
					maxi=i;
					maxepoch=e;
				} 
			} else {
				int len=nettab[i]->pathlen;
				//fprint2("+%s %s %d\n",path,nettab[i]->path,len);
				if ((strncmp(path,nettab[i]->path,len) == 0 && (path[len] == '/' || path[len]=='\0')) &&
						((e=tst_matchingepoch(&(nettab[i]->tst))) > maxepoch)) {
					maxi=i;
					maxepoch=e;
				}
			}
			um_setepoch(prevepoch);
		}
	}
	if (maxi >= 0)
		result=nettab[maxi];
	//fprint2("SearchContext:%s -> %d\n",path,result);
	return result;
}

void *net_getdl(struct umnet *mh)
{
	return mh->dlhandle;
}

/*insert a new context in the net table*/ 
static struct umnet *addnettab(struct umnet *new)
{
	register int i;
	//pthread_mutex_lock( &nettab_mutex );
	for (i=0;i<nettabmax && nettab[i] != NULL;i++)
		;
	if (i>=nettabmax) {
		register int j;
		register int nettabnewmax=(i + MNTTABSTEP) & ~MNTTABSTEP_1;
		nettab=(struct umnet **)realloc(nettab,nettabnewmax*sizeof(struct umnet *));
		assert(nettab);
		for (j=i;j<nettabnewmax;j++)
			nettab[j]=NULL;
		nettabmax=nettabnewmax;
	}
	nettab[i]=new;
	//pthread_mutex_unlock( &nettab_mutex );
	return nettab[i];
} 

/* execute a specific function (arg) for each nettab element */
static void forallnettabdo(void (*fun)(struct umnet *mc))
{
	register int i;
	for (i=0;i<nettabmax;i++) 
		if (nettab[i] != NULL)
			fun(nettab[i]);
} 

/*
 * delete the i-th element of the tab.
 * the table cannot be compacted as the index is used as id
 */
static void delnettab(struct umnet *mc)
{
	register int i;
	//pthread_mutex_lock( &nettab_mutex );
	for (i=0;i<nettabmax && mc != nettab[i];i++)
		;
	if (i<nettabmax)
		nettab[i]=NULL;
	else
		fprint2("delmnt inexistent entry\n");
	//pthread_mutex_unlock( &nettab_mutex );
}

/* add an element to the filetab (open file table)
 *  * each file has a fileinfo record
 *   */
static int addfiletab()
{
	register int i;
	//pthread_mutex_lock( &nettab_mutex );
	for (i=0;i<filetabmax && filetab[i] != NULL;i++)
		;
	if (i>=filetabmax) {
		register int j;
		filetabmax=(i + MNTTABSTEP) & ~MNTTABSTEP_1;
		filetab=(struct fileinfo **)realloc(filetab,filetabmax*sizeof(struct fileinfo *));
		assert(filetab);
		for (j=i;j<filetabmax;j++)
			filetab[j]=NULL;
	}
	filetab[i]=(struct fileinfo *)malloc(sizeof(struct fileinfo));
	assert(filetab[i]);
	//pthread_mutex_unlock( &nettab_mutex );
	return i;
}

/* delete an entry from the open file table.
 * RD: there is a counter managed by open and close calls */
static void delfiletab(int i)
{
	struct fileinfo *norace=filetab[i];
	filetab[i]=NULL;
	free(norace);
}

static long umnet_addproc(int id, int ppid, int max) {
	int size=max+1;
	if (size > defnetsize) {
		struct umnetdefault **newdefnet;
		newdefnet = realloc(defnet,size*sizeof(struct umnetdefault *));
		if (newdefnet == NULL) 
			return -1;
		else {
			if (defnetsize == 0)
				newdefnet[0]=NULL;
			defnet=newdefnet;
			defnetsize=size;
		}
	}
	if (id == ppid) {
		//fprint2("defnet ROOT %d\n",id);
		defnet[id]=NULL;
	} else {
		//fprint2("defnet %d<-%d %p %p\n",id,ppid,defnet[ppid],defnet[ppid]?defnet[ppid]->defstack[1]:0);
		defnet[id]=defnet[ppid];
		if (defnet[id] != NULL)
			defnet[id]->count++;
	}
	return 0;
}

static long umnet_delproc(int id) {
	if (defnet[id] != NULL) {
		if (defnet[id]->count <= 0) 
			free(defnet[id]);
		else
			defnet[id]->count--;
	}
	return 0;
}

static long umnet_setdefstack(int id, int domain, struct umnet *defstack)
{
	if (domain > 0 && domain < AF_MAXMAX) {
		//fprint2("umnet_setdefstack %d %d %p\n",id,domain,defstack);
		if (defnet[id] == NULL) 
			defnet[id] = calloc(1,sizeof (struct umnetdefault));
		if (defnet[id] != NULL) {
			if (defnet[id]->defstack[domain-1] != defstack) {
				if (defnet[id]->count > 0) {
					struct umnetdefault *new=malloc(sizeof (struct umnetdefault));
					if (new) {
						memcpy(new,defnet[id],sizeof (struct umnetdefault));
						new->count=0;
						defnet[id]->count--;
						defnet[id]=new;
					}	else {
						errno=EINVAL;
						return -1;
					}
				}
				defnet[id]->defstack[domain-1] = defstack;
			}
			return 0;
		} else {
			errno=EINVAL;
			return -1;
		}
	}
}

static struct umnet *umnet_getdefstack(int id, int domain)
{
	if (domain > 0 && domain <= AF_MAXMAX && defnet[id] != NULL) {
		//fprint2("umnet_getdefstack %d %d\n",id,domain);
		//fprint2("   %p %p\n",defnet[id],defnet[id]->defstack[domain-1]);
		return defnet[id]->defstack[domain-1];
	} else {
		return searchnet(DEFAULT_NET_PATH,EXACT);
	}
}

static long umnet_ctl(int type, va_list ap)
{
	int id, ppid, max;

	switch(type)
	{
		case MC_PROC | MC_ADD:
			id = va_arg(ap, int);
			ppid = va_arg(ap, int);
			max = va_arg(ap, int);
			/*fprint2("umnet_addproc %d %d %d\n",id,ppid,max);*/
			return umnet_addproc(id, ppid, max);

		case MC_PROC | MC_REM:
			id = va_arg(ap, int);
			/*fprint2("umnet_delproc %d\n",id);*/
			return umnet_delproc(id);

		default:
			return -1;
	}
}

static int ioctlparms(struct ioctl_len_req *arg)
{
	int fd=arg->fd;
	//fprint2("fd %d arg %d\n",arg->fd,arg->req);

	if (filetab[fd]==NULL) {
		errno = EBADF;
		return -1;
	} else {
		if(filetab[fd]->umnet->netops->ioctlparms) {
			return filetab[fd]->umnet->netops->ioctlparms(
					filetab[fd]->nfd, arg->req, filetab[fd]->umnet);
		} else {
			return 0;
		}
	}
}

struct timestamp *um_x_gettst();
static epoch_t umnet_check(int type, void *arg)
{
	if (type == CHECKPATH) {
		char *path=arg;
		/*fprint2("CHECKPATH %s %d %lld\n",path,um_mod_getumpid(),um_x_gettst()->epoch);*/
#if 0
		int escno=um_mod_getsyscallno();
		if (escno&ESCNO_MAP)
		fprint2("CHECKPATH %s %x %d %x\n",path,escno&ESCNO_MAP,escno&0x3fffffff,
				um_mod_getsyscalltype(escno));
#endif
		struct umnet *mc=searchnet(path,EXACT);
		if ( mc != NULL) 
			return mc->tst.epoch;
		else
			return FALSE;
	} else if (type == CHECKFSTYPE) {
		char *path=arg;
		return (strncmp(path,"umnet",5) == 0);
	} else if (type == CHECKSOCKET) {
		int *sock=arg;
		struct umnet *mc=umnet_getdefstack(um_mod_getumpid(),*sock);
		//fprint2("CHECKSOCKET %d %d %p\n",*sock,um_mod_getumpid(),mc);
		if ( mc != NULL) 
			return mc->tst.epoch;
		else
			return FALSE;
	} else if (type == CHECKIOCTLPARMS)
	   return ioctlparms(arg);
	else {
		return FALSE;
	}
}

static long umnet_msocket(char *path, int domain, int type, int protocol)
{
	struct umnet *mh;
	long rv;
	if (path)
		mh = searchnet(path,EXACT);
	else
		mh = umnet_getdefstack(um_mod_getumpid(),domain);
	assert(mh!=NULL);

	//fprint2("msocket %s %d %d %d\n",path,domain, type, protocol);
	if (type == SOCK_DEFAULT) {
    if (domain == PF_UNSPEC) {
			for (domain=1; domain<=AF_MAXMAX; domain++)
				if (!mh->netops->supported_domain ||
						mh->netops->supported_domain(domain)) 
					umnet_setdefstack(um_mod_getumpid(),domain,mh);
			return 0;
		} else {
			return umnet_setdefstack(um_mod_getumpid(),domain,mh);
		}
	} else if (mh->netops->msocket) {
		rv=mh->netops->msocket(domain, type, protocol, mh);
		if (rv >= 0) {
			int fi = addfiletab();
			filetab[fi]->nfd = rv;
			filetab[fi]->umnet = mh;
			mh->count++;
			rv=fi;
			mh->sockettime=time(NULL);
		}
		return rv;
	} else {
		errno = EINVAL;
		return -1;
	}
}

static long umnet_bind(int fd, const struct sockaddr *addr,
		socklen_t addrlen)
{
	if (filetab[fd]==NULL) {
		errno = EBADF;
		return -1;
	} else {
		if(filetab[fd]->umnet->netops->bind) {
			return filetab[fd]->umnet->netops->bind(
					filetab[fd]->nfd, addr, addrlen);
		} else {
			errno = EINVAL;
			return -1;
		}
	}
}

static long umnet_connect(int fd, const struct sockaddr *serv_addr,
		socklen_t addrlen)
{
	if (filetab[fd]==NULL) {
		errno = EBADF;
		return -1;
	} else {
		if(filetab[fd]->umnet->netops->connect) {
			return filetab[fd]->umnet->netops->connect(
					filetab[fd]->nfd, serv_addr, addrlen);
		} else {
			errno = EINVAL;
			return -1;
		}
	}
}

static long umnet_listen(int fd, int backlog)
{
	if (filetab[fd]==NULL) {
		errno = EBADF;
		return -1;
	} else {
		if(filetab[fd]->umnet->netops->listen) {
			return filetab[fd]->umnet->netops->listen(
					filetab[fd]->nfd, backlog);
		} else {
			errno = EINVAL;
			return -1;
		}
	}
}

static long umnet_accept(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
	if (filetab[fd]==NULL) {
		errno = EBADF;
		return -1;
	} else {
		if(filetab[fd]->umnet->netops->accept) {
			long rv;
			rv=filetab[fd]->umnet->netops->accept(
					filetab[fd]->nfd, addr, addrlen);
			if (rv >= 0) {
				int fi = addfiletab();
				filetab[fi]->nfd = rv;
				filetab[fi]->umnet = filetab[fd]->umnet;
				filetab[fd]->umnet->count++;
				rv=fi;
			}
			return rv;
		} else {
			errno = EINVAL;
			return -1;
		}
	}
}

static long umnet_getsockname(int fd, struct sockaddr *name, socklen_t *namelen)
{
	if (filetab[fd]==NULL) {
		errno = EBADF;
		return -1;
	} else {
		if(filetab[fd]->umnet->netops->getsockname) {
			return filetab[fd]->umnet->netops->getsockname(
					filetab[fd]->nfd, name, namelen);
		} else {
			errno = EINVAL;
			return -1;
		}
	}
}

static long umnet_getpeername(int fd, struct sockaddr *name, socklen_t *namelen)
{
	if (filetab[fd]==NULL) {
		errno = EBADF;
		return -1;
	} else {
		if(filetab[fd]->umnet->netops->getpeername) {
			return filetab[fd]->umnet->netops->getpeername(
					filetab[fd]->nfd, name, namelen);
		} else {
			errno = EINVAL;
			return -1;
		}
	}
}

static long umnet_send(int fd, const void *buf, size_t len, int flags)
{
	if (filetab[fd]==NULL) {
		errno = EBADF;
		return -1;
	} else {
		if(filetab[fd]->umnet->netops->send) {
			return filetab[fd]->umnet->netops->send(
					filetab[fd]->nfd, buf, len, flags);
		} else {
			errno = EINVAL;
			return -1;
		}
	}
}

static long umnet_recv(int fd, void *buf, size_t len, int flags)
{
	if (filetab[fd]==NULL) {
		errno = EBADF;
		return -1;
	} else {
		if(filetab[fd]->umnet->netops->recv) {
			return filetab[fd]->umnet->netops->recv(
					filetab[fd]->nfd, buf, len, flags);
		} else {
			errno = EINVAL;
			return -1;
		}
	}
}

static long umnet_sendto(int fd, const void *buf, size_t len, int flags,
		const struct sockaddr *to, socklen_t tolen)
{
	if (filetab[fd]==NULL) {
		errno = EBADF;
		return -1;
	} else {
		if(filetab[fd]->umnet->netops->sendto) {
			return filetab[fd]->umnet->netops->sendto(
					filetab[fd]->nfd, buf, len, flags, to, tolen);
		} else {
			errno = EINVAL;
			return -1;
		}
	}
}

static long umnet_recvfrom(int fd, void *buf, size_t len, int flags,
		struct sockaddr *from, socklen_t *fromlen)
{
	if (filetab[fd]==NULL) {
		errno = EBADF;
		return -1;
	} else {
		if(filetab[fd]->umnet->netops->recvfrom) {
			return filetab[fd]->umnet->netops->recvfrom(
					filetab[fd]->nfd, buf, len, flags, from, fromlen);
		} else {
			errno = EINVAL;
			return -1;
		}
	}
}

long umnet_sendmsg(int fd, const struct msghdr *msg, int flags) {
	return umnet_sendto(fd,msg->msg_iov->iov_base,msg->msg_iov->iov_len,flags,
			      msg->msg_name,msg->msg_namelen);
}

long umnet_recvmsg(int fd, struct msghdr *msg, int flags) {
	msg->msg_controllen=0;
	return umnet_recvfrom(fd,msg->msg_iov->iov_base,msg->msg_iov->iov_len,flags,
			msg->msg_name,&msg->msg_namelen);
}

static long umnet_getsockopt(int fd, int level, int optname,
		void *optval, socklen_t *optlen)
{
	if (filetab[fd]==NULL) {
		errno = EBADF;
		return -1;
	} else {
		if(filetab[fd]->umnet->netops->getsockopt) {
			return filetab[fd]->umnet->netops->getsockopt(
					filetab[fd]->nfd, level, optname, optval, optlen);
		} else {
			errno = EINVAL;
			return -1;
		}
	}
}

static long umnet_setsockopt(int fd, int level, int optname,
		const void *optval, socklen_t optlen)
{
	if (filetab[fd]==NULL) {
		errno = EBADF;
		return -1;
	} else {
		if(filetab[fd]->umnet->netops->setsockopt) {
			return filetab[fd]->umnet->netops->setsockopt(
					filetab[fd]->nfd, level, optname, optval, optlen);
		} else {
			errno = EINVAL;
			return -1;
		}
	}
}

static long umnet_read(int fd, void *buf, size_t count)
{
	if (filetab[fd]==NULL) {
		errno = EBADF;
		return -1;
	} else {
		if(filetab[fd]->umnet->netops->read) {
			return filetab[fd]->umnet->netops->read(
					filetab[fd]->nfd, buf, count);
		} else {
			errno = EINVAL;
			return -1;
		}
	}
}

static long umnet_write(int fd, const void *buf, size_t count)
{
	if (filetab[fd]==NULL) {
		errno = EBADF;
		return -1;
	} else {
		if(filetab[fd]->umnet->netops->write) {
			return filetab[fd]->umnet->netops->write(
					filetab[fd]->nfd, buf, count);
		} else {
			errno = EINVAL;
			return -1;
		}
	}
}

static long umnet_close(int fd)
{
	long rv;
	if (filetab[fd]==NULL) {
		errno = EBADF;
		return -1;
	} else {
		if(filetab[fd]->nfd>=0 && 
			filetab[fd]->umnet->netops->close) {
			rv=filetab[fd]->umnet->netops->close(
					filetab[fd]->nfd);
			if (rv >=0) {
				filetab[fd]->umnet->count--;
				delfiletab(fd);
			}
			return rv;
		} else {
			errno = EINVAL;
			return -1;
		}
	}
}

static long umnet_ioctl(int fd, int req, void *arg)
{
	if (filetab[fd]==NULL) {
		errno = EBADF;
		return -1;
	} else {
		if(filetab[fd]->umnet->netops->ioctl) {
			return filetab[fd]->umnet->netops->ioctl(filetab[fd]->nfd, req, arg);
		} else {
			errno = EINVAL;
			return -1;
		}
	}
}

static setstat64(struct stat64 *buf64, struct umnet *um)
{
	memset(buf64,0,sizeof(struct stat64));
	buf64->st_mode=um->mode;
	buf64->st_uid=um->uid;
	buf64->st_gid=um->gid;
	buf64->st_mtime=buf64->st_ctime=um->mounttime;
	buf64->st_atime=um->sockettime;
}

static long umnet_fstat64(int fd, struct stat64 *buf64)
{
	if (fd < 0 || filetab[fd] == NULL) {
		errno=EBADF;
		return -1;
	} else {
		setstat64(buf64,filetab[fd]->umnet);
		return 0;
	}
}

static long umnet_stat64(char *path, struct stat64 *buf64)
{
	struct umnet *mh = searchnet(path,EXACT);
	assert(mh);
	//fprint2("stat64 %s %p\n",path,fse);
	setstat64(buf64,mh);
	return 0;
}

/* TODO management of fcntl */
static long umnet_fcntl64(int fd, int cmd, void *arg)
{
	//print2("umnet_fcntl64\n");
	errno=0;
	return 0;
}

static long umnet_fsync(int fd, int cmd, void *arg)
{
	//print2("umnet_fcntl64\n");
	errno=0;
	return 0;
}

static long umnet_access(char *path, int mode)
{
	struct umnet *mh = searchnet(path,EXACT);
	assert(mh);
	return 0;
}

static long umnet_chmod(char *path, int mode)
{
	struct umnet *mh = searchnet(path,EXACT);
	mh->mode=mode;
	return 0;
}

static long umnet_chown(char *path, uid_t owner, gid_t group)
{
	struct umnet *mh = searchnet(path,EXACT);
	if (owner != -1)
		mh->uid=owner;
	if (group != -1)
		mh->gid=group;
	return 0;
}

static int isperm(char *opt)
{
	while (opt){
		opt=strstr(opt,"perm");
		if (opt) {
			if (opt[4]=='\0'){
				memmove(opt,opt+4,strlen(opt+4)+1);
				return 1;
			}
			if (opt[4]==',') {
				memmove(opt,opt+5,strlen(opt+5)+1);
				return 1;
			}
			else
				opt+=4;
		}
	}
	return 0;
}

static long umnet_mount(char *source, char *target, char *filesystemtype,
		unsigned long mountflags, void *data)
{
	void *dlhandle = openmodule(filesystemtype, RTLD_NOW);
	struct umnet_operations *netops;

	PRINTDEBUG(10, "MOUNT %s %s %s %x %s\n",source,target,filesystemtype,
			mountflags, (data!=NULL)?data:"<NULL>");

	if(dlhandle == NULL || (netops=dlsym(dlhandle,"umnet_ops")) == NULL) {
		fprint2("%s\n",dlerror());
		if(dlhandle != NULL)
			dlclose(dlhandle);
		errno=ENODEV;
		return -1;
	} else {
		struct umnet *new = (struct umnet *) malloc(sizeof(struct umnet));
		struct stat64 *s64;
		int i;
		assert(new);
		s64=um_mod_getpathstat();
		new->path = strdup(target);
		new->pathlen = strlen(target);
		new->dlhandle=dlhandle;
		new->netops=netops;
		new->private_data = NULL;
		new->mode=S_IFSTACK|0777;
		new->mounttime=new->sockettime=time(NULL);
		new->uid=0;
		new->gid=0;
		new->flags=mountflags;
		new->count=(isperm(data))?1:0;
		if (new->netops->init) 
			new->netops->init(source,new->path,mountflags,data,new);
		addnettab(new);
		new->tst=tst_timestamp();
		return 0;
	}
}

static long umnet_umount2(char *target, int flags)
{
	struct umnet *mh = searchnet(target,EXACT);
	if (mh == NULL) {
		errno=EINVAL;
		return -1;
	} else {
		if (mh->count > 0 && !(flags & MNT_FORCE)) {
			errno=EBUSY;
			return -1;
		} else {
			if (mh->netops->fini) 
				mh->netops->fini(mh);
			delnettab(mh);
			free(mh->path);
			free(mh);
			return 0;
		}
	}
}

static void contextclose(struct umnet *mc)
{
	umnet_umount2(mc->path,MNT_FORCE);
}   

void umnet_setprivatedata(struct umnet *nethandle, void *privatedata)
{
	if(nethandle)
		nethandle->private_data=privatedata;
}

void *umnet_getprivatedata(struct umnet *nethandle)
{
	if(nethandle)
		return nethandle->private_data;
}

static long umnet_event_subscribe(void (* cb)(), void *arg, int fd, int how)
{
	//fprint2("umnet_event_subscribe %d %d\n",fd,how);
	if (filetab[fd]==NULL) {
		errno=EBADF;
		return -1;
	}
	else {
		if (filetab[fd]->umnet->netops->event_subscribe) {
			return filetab[fd]->umnet->netops->event_subscribe(
					cb, arg, filetab[fd]->nfd, how);
		} else {
			errno = 1;
			return -1;
		}
	}
}

	static void
	__attribute__ ((constructor))
init (void)
{
	fprint2("umnet init\n");
	s.name="umnet";
	s.code=UMNET_SERVICE_CODE;
	s.checkfun=umnet_check;
	s.syscall=(sysfun *)calloc(scmap_scmapsize,sizeof(sysfun));
	s.socket=(sysfun *)calloc(scmap_sockmapsize,sizeof(sysfun));
	s.virsc=(sysfun *)calloc(scmap_virscmapsize,sizeof(sysfun));
	s.ctl = umnet_ctl;

	MCH_ZERO(&(s.ctlhs));
	MCH_SET(MC_PROC, &(s.ctlhs));
	SERVICESYSCALL(s, mount, umnet_mount);
	SERVICESYSCALL(s, umount2, umnet_umount2);
	SERVICEVIRSYSCALL(s, msocket, umnet_msocket);
	SERVICESOCKET(s, bind, umnet_bind);
	SERVICESOCKET(s, connect, umnet_connect);
	SERVICESOCKET(s, listen, umnet_listen);
	SERVICESOCKET(s, accept, umnet_accept);
	SERVICESOCKET(s, getsockname, umnet_getsockname);
	SERVICESOCKET(s, getpeername, umnet_getpeername);
	SERVICESOCKET(s, send, umnet_send);
	SERVICESOCKET(s, recv, umnet_recv);
	SERVICESOCKET(s, sendto, umnet_sendto);
	SERVICESOCKET(s, recvfrom, umnet_recvfrom);
	SERVICESOCKET(s, sendmsg, umnet_sendmsg);
	SERVICESOCKET(s, recvmsg, umnet_recvmsg);
	SERVICESOCKET(s, getsockopt, umnet_getsockopt);
	SERVICESOCKET(s, setsockopt, umnet_setsockopt);
	SERVICESYSCALL(s, read, umnet_read);
	SERVICESYSCALL(s, write, umnet_write);
	SERVICESYSCALL(s, close, umnet_close);
	SERVICESYSCALL(s, stat64, umnet_stat64);
	SERVICESYSCALL(s, lstat64, umnet_stat64);
	SERVICESYSCALL(s, fstat64, umnet_fstat64);
	SERVICESYSCALL(s, fcntl64, umnet_fcntl64);
	SERVICESYSCALL(s, access, umnet_access);
	SERVICESYSCALL(s, chmod, umnet_chmod);
	SERVICESYSCALL(s, chown, umnet_chown);
	SERVICESYSCALL(s, ioctl, umnet_ioctl);
	s.event_subscribe=umnet_event_subscribe;
	add_service(&s);
}

	static void
	__attribute__ ((destructor))
fini (void)
{
	free(s.syscall);
	free(s.socket);
	free(s.virsc);
	forallnettabdo(contextclose);
	fprint2("umnet fini\n");
}
