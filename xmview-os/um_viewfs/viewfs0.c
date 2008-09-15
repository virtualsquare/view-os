/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   Copyright 2008 Renzo Davoli University of Bologna - Italy
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
 *   $Id: viewfs.c 326 2007-04-24 13:19:40Z garden $
 *
 */   
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <string.h>
#include <pthread.h>
#include <utime.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <config.h>
#include <assert.h>
#include <sys/select.h>
#include "viewfs0args.h"
#include "module.h"
#include "libummod.h"
#include "syscallnames.h"

#include "gdebug.h"
#define MAXSIZE ((1LL<<((sizeof(size_t)*8)-1))-1)

static struct service s;
static fd_set viewfs_dirset;
static fd_set fastsysset;
static fd_set parentsysset;
static short fastsc[]={
	__NR_creat,
	__NR_open,
	__NR_openat,
	__NR_execve,

	__NR_chdir,
	__NR_fchdir,
	-1};

struct viewfs {
	char *path;
	char *source;
	char **exceptions;
	int pathlen;
	struct timestamp tst;
	int flags;
};

static struct viewfs **viewfstab=NULL;
static int viewfstabmax=0;

#define WORDLEN sizeof(int *)
#define WORDALIGN(X) (((X) + WORDLEN) & ~(WORDLEN-1))
#define SIZEDIRENT64NONAME (sizeof(__u64)+sizeof(__s64)+sizeof(unsigned short)+sizeof(unsigned char))

#define DT_DIR 4
struct viewfs_dirent64 {
	__u64             d_ino;
	__s64             d_off;
	unsigned short  d_reclen;
	unsigned char   d_type;
	char            *d_name;
};

struct umdirent {
	struct viewfs_dirent64 de;
	struct umdirent *next;
};

struct viewfsdir {
	struct viewfs *vfs;
	int fd;
	char *path;
	char *vfspath;
	struct umdirent *dirinfo; /* conversion fuse-getdir into kernel compliant
															 dirent. Dir head pointer */
	struct umdirent *dirpos;    /* same conversion above: current pos entry */
	struct viewfsdir *next;
};

struct viewfsdir *viewfs_opendirs=NULL;

#define MNTTABSTEP 4 /* must be a power of two */
#define MNTTABSTEP_1 (MNTTABSTEP-1)

#define EXACT 1
#define SUBSTR 0
#define TRUE 1
#define FALSE 0

/* Does this file exist? */
static int file_exist(char *path)
{
	struct stat buf;
	return stat(path,&buf)==0;
}

/* Does this file exist? */
static int file_isdir(char *path)
{
	struct stat buf;
	if (stat(path,&buf)==0)
		return S_ISDIR(buf.st_mode);
	else
		return 0;
}

/* create all the missing dirs in the path */
static void create_path(char *path)
{
	char *s=path+1;
	while (*s) {
		if (*s=='/') {
			*s=0;
			mkdir(path,0777);
			*s='/';
		}
		s++;
	}
}

/* eliminate all the empty useless dirs in the path */
static void destroy_path(char *path)
{
	char *s=path+(strlen(path)-1);
	int rv=0;
	while (rv==0 && s > path) {
		if (*s=='/') {
			*s=0;
			rv=rmdir(path);
			*s='/';
		}
		s--;
	}
}

/* copy a file oldpath->newpath */
static int copyfile (char *oldpath, char *newpath, size_t truncate)
{
	struct stat oldstat;
	int fdin=open(oldpath,O_RDONLY);
	int fdout=-1;
	char buf[4096];
	size_t outsize=0;

	create_path(newpath);
	if (stat(oldpath,&oldstat)==0) {
		if (S_ISDIR(oldstat.st_mode)) {
			close(fdin);
			errno=EPERM;
			return -1;
		}
		fdout=open(newpath,O_WRONLY|O_CREAT|O_TRUNC,(oldstat.st_mode & 0777) | 0600);
	}
	//fprint2("copyfile %s %s %d\n",oldpath,newpath,truncate);
  if (fdin >= 0 && fdout >= 0) {
		size_t nread,readsize=4096;
		if (truncate < readsize) readsize=truncate;
		while ((nread=read(fdin,buf,4096))>0) {
			write(fdout,buf,nread);
			truncate -= nread;
			if (truncate < readsize) readsize=truncate;
		}
	}
	close (fdin);
	close (fdout);
	errno=0;
	return 0;
}

/* path of the hidden file for wipeouts (and rights) */
static inline char *wipeunwrap(struct viewfs *vfs,char *path)
{
	char *wipefile;
	asprintf(&wipefile,"%s/.-%s",vfs->source,path+vfs->pathlen);
	return wipefile;
}

/* boolean: is this deleted? */
static inline int isdeleted (struct viewfs *vfs,char *path)
{
	if (vfs->flags & VIEWFS_MERGE) {
		char *wipefile=wipeunwrap(vfs,path);
		char wiped[4];
		int out=readlink(wipefile,wiped,4);
		//fprint2("isdeleted %s %s %d\n",path,wipefile,out);
		free(wipefile);
		return (out>=0); /*if the readlink succeeded the file is deleted*/
	}
	return FALSE;
}

/* delete wipeout file / save errno */
static inline void wipeunlink (struct viewfs *vfs,char *path)
{
	int erno=errno;
	if (vfs->flags & VIEWFS_COW) {
		char *wipefile=wipeunwrap(vfs,path);
		if (unlink(wipefile) >= 0)
			destroy_path(wipefile);
		free(wipefile);
	}
	errno=erno;
}

/* wipe out a file */
static inline int wipeoutfile (struct viewfs *vfs,char *path)
{
	int rv=0;
	if (vfs->flags & VIEWFS_COW) {
		char *wipefile=wipeunwrap(vfs,path);
		create_path(wipefile);
		rv=symlink("WIP",wipefile);
		free(wipefile);
	}
	return rv;
}

/* path->newpath conversion */
static char *unwrap(struct viewfs *vfs,char *path,int pre)
{
	char *vfspath;
	//fprint2("unwrap %s %d\n",path,pre);
	asprintf(&vfspath,"%s%s",vfs->source,path+vfs->pathlen);
	/*if (!pre && isdeleted(vfs,path)) {
		free(vfspath);
		return strdup("");
	}*/
	return vfspath;
}

static inline int cownoenterror(struct viewfs *vfs,char *path,char *vfspath)
{
	//fprint2("cownoenterror %s %d %d %d\n",path,file_exist(vfspath),file_exist(path),isdeleted(vfs,path));
	if (file_exist(vfspath) || (file_exist(path) && !isdeleted(vfs,path)))	
		return 0;
	else {
		errno=ENOENT;
		return -1;
	} 
}

static inline int cowexisterror(struct viewfs *vfs,char *path,char *vfspath)
{
	//fprint2("cowexisterror %s %d %d %d\n",path,file_exist(vfspath),file_exist(path),isdeleted(vfs,path));
	if (file_exist(vfspath) || (file_exist(path) && !isdeleted(vfs,path)))	{

		errno=EEXIST;
		return -1;
	} else
		return 0;
}

/* OPEN: called if virtual file does not exist & write request
 * returns:
 *  0 - go real
 *  1 - go virtual
 * 	COW:
 *    write access virtual (will copy file)
 *    create virtual
 *  MINCOW:
 *    write access virtual only if write denied (will copy file)
 *    create virtual if write denied on the parent dir
 *  XXX TODO
 *    dev always real unless specific flag.
 */
static int open_exception(struct viewfs *vfs, char *path, long flags)
{
	int rv;
	if (vfs->flags & VIEWFS_MINCOW) {
		int realexists=1;
		int wok=access(path,W_OK);
		if (wok<0 && errno==ENOENT)
			realexists=0;
		if (realexists) {
			if (wok)
				rv= 1;
			else
				rv= 0;
		} else {
			if (flags & O_CREAT) {
				char tmpch;
				char *tmpchp;
				int wok_parent; /* can write real parent dir*/
				for (tmpchp=path+(strlen(path)-1); *tmpchp!='/' && tmpchp>path; tmpchp--)
					;
				if (tmpchp==path) tmpchp++;
				tmpch=*tmpchp; /*tricky temporary change path into parent's path */
				*tmpchp='\0';
				wok_parent=access(path,W_OK);
				*tmpchp=tmpch;
				if (wok_parent)
					rv= 1;
				else
					rv= 0;
			} else
				rv= 1; /* error case open !CREAT nonexistent file */
		}
	} else if (vfs->flags & VIEWFS_COW) /* COW but not MIN */
		rv= 1;
	else  /* MERGE */
		rv= 0;
	//fprint2("open_exception %s %d %x\n",path,rv,vfs->flags);
	return rv;
}

/* isexception:
 * is in the domain of mount.
 * 0 - virtual
 * 1 - real
 */
static inline int isexception(char *path, int pathlen, char **exceptions, struct viewfs *vfs)
{
	if (__builtin_expect((exceptions == NULL && !(vfs->flags & VIEWFS_MERGE)),1))
		return 0;
	else {
		int sysno=(int)um_mod_getsyscallno();
		/* explicit exceptions */
		if (exceptions) {
			char *shortpath=path+pathlen;
			while (*exceptions != 0) {
				int len=strlen(*exceptions);
				if (strncmp(shortpath,*exceptions,len) == 0 &&
						(shortpath[len] == '/' || shortpath[len]=='\0'))
					return 1;
				exceptions ++;
			}
		}
		if (strcmp(path+pathlen,"/.-")==0)
			return 1;
		/* chdir to real dir when possible */
		if (sysno==__NR_chdir || sysno==__NR_fchdir) {
			/*
			struct stat64 buf;
			char *vfspath=unwrap(vfs,path,1);
			int vfsrv=lstat64(vfspath,&buf);
			free(vfspath);
			if (vfsrv==0 && lstat64(path,&buf)==0)
				return 1;
			else
				return 0;
				*/
			return (file_exist(path));
		}
		/* MERGE + COW */
		if (vfs->flags & VIEWFS_MERGE) {
			epoch_t prevepoch=um_setepoch(vfs->tst.epoch);
			/* virtually deleted files goes virtual (otherwise they would be existent) */
			if (isdeleted(vfs,path)) {
				um_setepoch(prevepoch);
				return 0;
			} else {
				/* all rare and non-dangerous calls gets managed by the modules
				 * *but* the fastfysset */
				if (FD_ISSET(sysno,&fastsysset)) {
					struct stat64 buf;
					char *vfspath=unwrap(vfs,path,1);
					int vfsrv=lstat64(vfspath,&buf);
					int openargc=1;
					long openflag=0;
					long *scargs=um_mod_getargs();
#if 0
					if ((vfs->flags & VIEWFS_COW)) {
						long *scargs=um_mod_getargs();
						long sysno=um_mod_getsyscallno();
						int origrv=lstat64(path,&buf);
						fprint2("%d(%s) %s(%d) %s(%d) -> ",sysno, 
								SYSCALLNAME(sysno), 
								path, origrv==0,
								vfspath, vfsrv==0);
					}
#endif
					switch (sysno) {
						case __NR_openat:
							/* open openat creat, the same syscall.
							 * call specific action */
							openargc++;
						case __NR_open:
							if (vfsrv<0 && (scargs[openargc] & O_ACCMODE) && 
									open_exception(vfs,path,scargs[openargc]))
								vfsrv=0;
							break;
						case __NR_creat:
							if (vfsrv<0 && open_exception(vfs,path,O_CREAT|O_WRONLY|O_TRUNC))
								vfsrv=0;
							break;
						case __NR_execve:
							break;
					}
					free(vfspath);
					//fprint2("+++%d\n",vfsrv<0);
					um_setepoch(prevepoch);
					return (vfsrv<0);
				} else {
					um_setepoch(prevepoch);
					return 0;
				}
			}
		} else
			return 0;
	}
}

static inline void freeexceptions(char **exceptions)
{
	if (__builtin_expect((exceptions == NULL),1))
		return;
	else {
		char **excscan=exceptions;
		while (*excscan != 0) {
			free(*excscan);
			excscan++;
		}
		free(exceptions);
	}
}

static struct viewfs *vfs_search(char *path,char *source,int flags)
{
	register int i;
	struct viewfs *result=NULL;
	epoch_t maxepoch=0;
	int maxi=-1;
	for (i=0;i<viewfstabmax;i++)
	{
		epoch_t e;
		if (viewfstab[i] != NULL) {
			if ((strcmp(path,viewfstab[i]->path) == 0) &&
					(strcmp(source,viewfstab[i]->source) == 0) &&
					(flags==viewfstab[i]->flags) &&
					((e=tst_matchingepoch(&(viewfstab[i]->tst))) > maxepoch)) {
				maxi=i;
				maxepoch=e;
			}
		}
	}
	if (maxi >= 0)
		result=viewfstab[maxi];
	//fprint2("Renew:%s %p\n",path, result);
	return result;
}


static struct viewfs *searchcontext(char *path,int exact)
{
	register int i;
	struct viewfs *result=NULL;
	epoch_t maxepoch=0;
	int maxi=-1;
	GDEBUG(1,"SearchContext:%s-%s ENTER!",path, exact?"EXACT":"SUBSTR");
	//fprint2("SearchContext:%s-%s ENTER!\n",path, exact?"EXACT":"SUBSTR");
	for (i=0;i<viewfstabmax;i++)
	{
		epoch_t e;
		if (viewfstab[i] != NULL) {
			if (exact) {
				if ((strcmp(path,viewfstab[i]->path) == 0) &&
						((e=tst_matchingepoch(&(viewfstab[i]->tst))) > maxepoch)) {
					maxi=i;
					maxepoch=e;
				}
			} else {
				int len=viewfstab[i]->pathlen;
				if ((strncmp(path,viewfstab[i]->path,len) == 0 && (path[len] == '/' || path[len]=='\0')) && 
						((e=tst_matchingepoch(&(viewfstab[i]->tst))) > maxepoch) &&
						!(isexception(path,len,viewfstab[i]->exceptions,viewfstab[i]))) {
					maxi=i;
					maxepoch=e;
				}
			}
		}
	}

	if (maxi >= 0)
		result=viewfstab[maxi];
	//fprint2("SearchContext:%s-%s %p\n",path, exact?"EXACT":"SUBSTR",result);
	return result;
}

/*insert a new context in the fuse table*/
static struct viewfs *addviewfstab(struct viewfs *new)
{
	register int i;
	for (i=0;i<viewfstabmax && viewfstab[i] != NULL;i++)
		;
	if (i>=viewfstabmax) {
		register int j;
		register int viewfstabnewmax=(i + MNTTABSTEP) & ~MNTTABSTEP_1;
		viewfstab=(struct viewfs **)realloc(viewfstab,viewfstabnewmax*sizeof(struct viewfs *));
		assert(viewfstab);
		for (j=i;j<viewfstabnewmax;j++)
			viewfstab[j]=NULL;
		viewfstabmax=viewfstabnewmax;
	}
	viewfstab[i]=new;
	return viewfstab[i];
}

/* execute a specific function (arg) for each viewfstab element */
static void forallviewfstabdo(void (*fun)(struct viewfs *vfs))
{
	register int i;
	for (i=0;i<viewfstabmax;i++)
		if (viewfstab[i] != NULL)
			fun(viewfstab[i]);
}
/*
 * delete the i-th element of the tab.
 * the table cannot be compacted as the index is used as id
 */
static void delviewfstab(struct viewfs *vfs)
{
	register int i;
	for (i=0;i<viewfstabmax && vfs != viewfstab[i];i++)
		;
	if (i<viewfstabmax)
		viewfstab[i]=NULL;
	else
		GMESSAGE("delviewfstab inexistent entry");
}

static epoch_t viewfspath(int type,void *arg)
{
	if (type== CHECKPATH) {
		char *path=arg;
		struct viewfs *vfs=searchcontext(path,SUBSTR);
		if ( vfs != NULL) 
			return vfs->tst.epoch;
		else
			return 0;
	} else if (type == CHECKFSTYPE) {
		char *path=arg;
		return (strncmp(path,"viewfs",6) == 0);
	} else
		return 0;
}

static long viewfs_open(char *path, int flags, mode_t mode)
{
	struct viewfs *vfs = searchcontext(path, SUBSTR);
	char *vfspath=unwrap(vfs,path,0);
	int rv;
	/*fprint2("OPEN  %s %s %d %d 0%o\n",
			path,vfspath,file_exist(vfspath),isdeleted(vfs,path),flags);*/
	if ((flags & O_ACCMODE) && (vfs->flags & VIEWFS_COW)) {
		create_path(vfspath);
		/* is not in cow but it exists, copy it! */
		if (!file_exist(vfspath) && 
				file_exist(path) && !isdeleted(vfs,path)) {
			copyfile(path,vfspath,(flags & O_TRUNC)?0:MAXSIZE);
		}
		rv=open(vfspath,flags,mode);
	} else
		rv=open(vfspath,flags,mode);
	if (rv >= 0) {
		wipeunlink(vfs,path);
		if ((vfs->flags & VIEWFS_MERGE) &&
				((flags & O_DIRECTORY) || file_isdir(vfspath))) {
			struct viewfsdir *vfsdir=malloc(sizeof(struct viewfsdir));
			vfsdir->vfs=vfs;
			vfsdir->fd=rv;
			vfsdir->path=strdup(path);
			vfsdir->vfspath=strdup(vfspath);
			vfsdir->dirinfo=vfsdir->dirpos=0;
			vfsdir->next=viewfs_opendirs;
			viewfs_opendirs=vfsdir;
			FD_SET(rv,&viewfs_dirset);
		}
	}
	free(vfspath);
	return rv;
}

static long viewfs_truncate64(char *path, loff_t length)
{
	struct viewfs *vfs = searchcontext(path, SUBSTR);
	int rv=0;
	char *vfspath=unwrap(vfs,path,0);
	if (vfs->flags & VIEWFS_MERGE) {
		if ((rv=cownoenterror(vfs,path,vfspath))==0) { /* ENOENT */
			if (vfs->flags & VIEWFS_COW) {
				if (file_exist(vfspath)) /* virt file */
					rv=truncate64(vfspath,length);
				else {
					if (vfs->flags & VIEWFS_MINCOW) { /* MINCOW */
						rv=truncate64(path,length);
						if (rv<0) {
							rv=copyfile(path,vfspath,length);
						}
					} else { /* COW  !MIN */
						rv=copyfile(path,vfspath,length);
					}
				}
			} else { /* MERGE */
				if (file_exist(vfspath)) {
#ifdef MERGEROFS
					rv=-1;
					errno=EROFS;
#else
					rv=truncate64(vfspath,length);
#endif
				} else
					rv=truncate64(path,length);
			}
		}
	} else /* MOVE */
		rv=truncate(vfspath,length);
	free(vfspath);
	return rv;
}

static long viewfs_link(char *oldpath, char *newpath)
{
	struct viewfs *vfs = searchcontext(newpath, SUBSTR);
	char *vfsnewpath=unwrap(vfs,newpath,1);
	int rv=0;
	//fprint2("link %s %s %s\n",oldpath, newpath, vfsnewpath);
	if (vfs->flags & VIEWFS_MERGE) {
		if ((rv=cowexisterror(vfs,newpath,vfsnewpath))==0) { /* EEXIST */
			char *vfsoldpath=unwrap(vfs,oldpath,1);
			char *thisoldpath;
			if (file_exist(vfsoldpath))
				thisoldpath=vfsoldpath;
			else
				thisoldpath=oldpath;
			if (vfs->flags & VIEWFS_COW) {
				if (vfs->flags & VIEWFS_MINCOW) { /* MINCOW */
					rv=link(thisoldpath,newpath);
					if (rv<0) {
						create_path(vfsnewpath);
						rv=link(thisoldpath,vfsnewpath);
						if (rv<0)
							rv=copyfile(thisoldpath,vfsnewpath,MAXSIZE);
						if (rv>=0) wipeunlink(vfs,newpath);
					}
				} else { /* COW but not MIN */
					create_path(vfsnewpath);
					rv=link(thisoldpath,vfsnewpath);
					if (rv<0)
						rv=copyfile(thisoldpath,vfsnewpath,MAXSIZE);
					if (rv>=0) wipeunlink(vfs,newpath);
				}
			} else { /* MERGE */
				rv=link(thisoldpath,newpath);
			}
			free(vfsoldpath);
		}
	} else /* MOVE */ /* XXX vfsoldpath? */
		rv=link(oldpath,vfsnewpath);
	free(vfsnewpath);
	return rv;
}

static long viewfs_rename(char *oldpath, char *newpath)
{
	struct viewfs *vfs = searchcontext(newpath, SUBSTR);
	char *vfsnewpath=unwrap(vfs,newpath,1);
	int rv=0;
	//fprint2("rename %s %s %s\n",oldpath, newpath, vfsnewpath);
	if (vfs->flags & VIEWFS_MERGE) {
		char *vfsoldpath=unwrap(vfs,oldpath,1);
		char *thisoldpath;
		if (file_exist(vfsoldpath))
			thisoldpath=vfsoldpath;
		else
			thisoldpath=oldpath;
		if (vfs->flags & VIEWFS_COW) {
			if (vfs->flags & VIEWFS_MINCOW) { /* MINCOW */
				rv=rename(thisoldpath,newpath);
				if (rv<0) {
					create_path(vfsnewpath);
					rv=rename(thisoldpath,vfsnewpath);
					if (rv<0)
						rv=copyfile(thisoldpath,vfsnewpath,MAXSIZE);
					if (rv>=0) {
						wipeunlink(vfs,newpath);
						if(thisoldpath==vfsoldpath)
							unlink(vfsoldpath);
						if(file_exist(oldpath))
							wipeoutfile(vfs,oldpath);
					}
				}
			} else { /* COW but not MIN */
				create_path(vfsnewpath);
				rv=rename(thisoldpath,vfsnewpath);
				if (rv<0)
					rv=copyfile(thisoldpath,vfsnewpath,MAXSIZE);
				if (rv>=0) {
					wipeunlink(vfs,newpath);
					if(thisoldpath==vfsoldpath)
						unlink(vfsoldpath);
					if(file_exist(oldpath))
						wipeoutfile(vfs,oldpath);
				}
			}
		} else { /* MERGE */
			rv=rename(thisoldpath,newpath);
		}
		free(vfsoldpath);
	} else /* MOVE */
		rv=rename(oldpath,vfsnewpath);
	free(vfsnewpath);
	return rv;
}

static void umcleandirinfo(struct umdirent *tail);
static struct viewfsdir *viewfs_del_dirfd(struct viewfsdir *vfsdir,int fd)
{
	if (vfsdir != NULL) {
		if (vfsdir->fd == fd) {
			free(vfsdir->path);
			free(vfsdir->vfspath);
			umcleandirinfo(vfsdir->dirinfo);
			free(vfsdir);
			return vfsdir->next;
		} else {
			vfsdir->next=viewfs_del_dirfd(vfsdir->next,fd);
			return vfsdir;
		}
	} else
		return NULL;
}

static long viewfs_close(int fd)
{
	if (FD_ISSET(fd,&viewfs_dirset)) {
		FD_CLR(fd,&viewfs_dirset);
		viewfs_opendirs=viewfs_del_dirfd(viewfs_opendirs,fd);
	}
	return close(fd);
}

static long viewfs_statfs64(char *path, struct statfs64 *buf)
{
	struct viewfs *vfs = searchcontext(path, SUBSTR);
	char *vfspath=unwrap(vfs,path,0);
	int rv= statfs64(vfspath,buf);
	if (rv<0 && errno==ENOENT && (vfs->flags & VIEWFS_MERGE) && !isdeleted(vfs,path)) 
		rv= statfs64(path,buf);
	free(vfspath);
	return rv;
}

static long viewfs_stat64(char *path, struct stat64 *buf)
{
	struct viewfs *vfs = searchcontext(path, SUBSTR);
	char *vfspath=unwrap(vfs,path,0);
	int rv= stat64(vfspath,buf);
	if (rv<0 && errno==ENOENT && (vfs->flags & VIEWFS_MERGE) && !isdeleted(vfs,path)) 
		rv= stat64(path,buf);
	free(vfspath);
	//fprint2("viewfs_stat64 %s rv=%d\n",path,rv);
	return rv;
}

static long viewfs_lstat64(char *path, struct stat64 *buf)
{
	struct viewfs *vfs = searchcontext(path, SUBSTR);
	char *vfspath=unwrap(vfs,path,0);
	int rv= lstat64(vfspath,buf);
	if (rv<0 && errno==ENOENT && (vfs->flags & VIEWFS_MERGE) && !isdeleted(vfs,path)) 
		rv= lstat64(path,buf);
	free(vfspath);
	//fprint2("viewfs_lstat64 %s rv=%d\n",path,rv);
	return rv;
}

static long viewfs_readlink(char *path, char *buf, size_t bufsiz)
{
	struct viewfs *vfs = searchcontext(path, SUBSTR);
	char *vfspath=unwrap(vfs,path,0);
	int rv= readlink(vfspath,buf,bufsiz);
	if (rv<0 && errno==ENOENT && (vfs->flags & VIEWFS_MERGE) && !isdeleted(vfs,path)) 
		rv= readlink(path,buf,bufsiz);
	free(vfspath);
	return rv;
}

static long viewfs_access(char *path, int mode)
{
	struct viewfs *vfs = searchcontext(path, SUBSTR);
	char *vfspath=unwrap(vfs,path,0);
	int rv= access(vfspath,mode);
	if (rv<0 && errno==ENOENT && (vfs->flags & VIEWFS_MERGE) && !isdeleted(vfs,path)) 
		rv= access(path,mode);
	//fprint2("access %s %d-> %d\n",path,mode,rv);
	free(vfspath);
	return rv;
}

/* add something: mkdir, symlink, link */
static long viewfs_mkdir(char *path, int mode)
{
	struct viewfs *vfs = searchcontext(path, SUBSTR);
	int rv=0;
	char *vfspath=unwrap(vfs,path,1);
	if (vfs->flags & VIEWFS_MERGE) {
		if ((rv=cowexisterror(vfs,path,vfspath))==0) { /* EEXIST */
			if (vfs->flags & VIEWFS_COW) {
				if (vfs->flags & VIEWFS_MINCOW) { /* MINCOW */
					rv=mkdir(path,mode);
					if (rv<0) {
						create_path(vfspath);
						rv=mkdir(vfspath,mode);
						if (rv>=0) wipeunlink(vfs,path);
					}
				} else { /* COW but not MIN */
					create_path(vfspath);
					rv=mkdir(vfspath,mode);
					if (rv>=0) wipeunlink(vfs,path);
				}
			} else { /* MERGE */
				rv=mkdir(path,mode);
			}
		}
	} else /* MOVE */
		rv=mkdir(vfspath,mode);
	free(vfspath);
	return rv;
}

static long viewfs_symlink(char *oldpath, char *newpath)
{
	struct viewfs *vfs = searchcontext(newpath, SUBSTR);
	char *vfspath=unwrap(vfs,newpath,1);
	int rv=0;
	if (vfs->flags & VIEWFS_MERGE) {
		if ((rv=cowexisterror(vfs,newpath,vfspath))==0) { /* EEXIST */
			if (vfs->flags & VIEWFS_COW) {
				if (vfs->flags & VIEWFS_MINCOW) { /* MINCOW */
					rv=symlink(oldpath,newpath);
					if (rv<0) {
						create_path(vfspath);
						rv=symlink(oldpath,vfspath);
						if (rv>=0) wipeunlink(vfs,newpath);
					}
				} else { /* COW but not MIN */
					create_path(vfspath);
					rv=symlink(oldpath,vfspath);
					if (rv>=0) wipeunlink(vfs,newpath);
				}
			} else { /* MERGE */
				rv=symlink(oldpath,newpath);
			}
		}
	} else /* MOVE */
		rv=symlink(oldpath,vfspath);
	free(vfspath);
	return rv;
}

/* delete something unlink rmdir */
static long viewfs_unlink(char *path)
{
	struct viewfs *vfs = searchcontext(path, SUBSTR);
	char *vfspath=unwrap(vfs,path,0);
	int rv=0;
	int saverrno;
	//fprint2("viewfs_unlink %s\n",path);
	if (vfs->flags & VIEWFS_MERGE) {
		if ((rv=cownoenterror(vfs,path,vfspath))==0) { /* ENOENT */
			if (vfs->flags & VIEWFS_COW) {
				if (vfs->flags & VIEWFS_MINCOW) { /* MINCOW */
					rv=unlink(vfspath); /* try delete virtual  (what about dangling symlink?)*/
					if (rv<0 && errno==ENOENT) { /* doesn't exist */
						rv=unlink(path); /* try delete real */
						if (rv<0 && (errno==EPERM || errno==EACCES || errno==EROFS))
							rv=wipeoutfile(vfs,path);
					} else if(rv == 0) {
						int saverrno=errno;
						if (rv==0 && file_exist(path))
							wipeoutfile(vfs,path);
						errno=saverrno;
					}
				} else { /* COW but not MIN */
					rv=unlink(vfspath); /* try delete virtual  (what about dangling symlink?)*/
					if (rv<0 && errno==ENOENT)  /* doesn't exist */
						rv=wipeoutfile(vfs,path);
					else if(rv == 0) {
						int saverrno=errno;
						if (file_exist(path))
							wipeoutfile(vfs,path);
						errno=saverrno;
					}
				}
			} else { /* MERGE */
				if (file_exist(vfspath)) {
#ifdef MERGEROFS
					rv=-1;
					errno=EROFS;
#else
					rv=unlink(vfspath);
#endif
				} else
					rv=unlink(path);
			}
		} 
	} else /* MOVE */
		rv=unlink(vfspath);
	free(vfspath);
	return rv;
}

static inline int isdot(char *s)
{
	if (s[0]=='.') {
		if (s[1]==0)
			return 1;
		if (s[1]=='.' && s[2]==0)
			return 1;
	}
	return 0;
}

static int isemptydir(struct viewfs *vfs,char *path)
{
	int dirfd=open(path,O_RDONLY|O_DIRECTORY);
	if (dirfd) {
		char buf[4096];
		int len;
		int count=0;
		while (count==0 && (len=getdents64(dirfd,(struct dirent64 *)buf,4096)) > 0) {
			off_t off=0;
			while (count==0 && off<len) {
				struct dirent64 *de=(struct dirent64 *)(buf+off);
				if (!isdot(de->d_name)) {
					char *this;
					asprintf(&this,"%s/%s",path,de->d_name);
					//fprint2("isemptydir %s %s %d\n",de->d_name,this,isdeleted(vfs,this));
					if (!isdeleted(vfs,this))
						count++;
					free(this);
				}
				off+=de->d_reclen;
			}
		}
		close(dirfd);
		return (count==0);
	} else
		return 0; /* error -> notempty -> error */
}

static void zapwipedir(struct viewfs *vfs,char *path)
{
	int dirfd=open(path,O_RDONLY|O_DIRECTORY);
	if (dirfd) {
		char buf[4096];
		char *this;
		int len;
		while ((len=getdents64(dirfd,(struct dirent64 *)buf,4096)) > 0) {
			off_t off=0;
			while (off<len) {
				struct dirent64 *de=(struct dirent64 *)(buf+off);
				if (!isdot(de->d_name)) {
					asprintf(&this,"%s/.-%s/%s",vfs->source,path+vfs->pathlen,de->d_name);
					//fprint2("zapwipe %s %s\n",de->d_name,this);
					unlink(this);
					free(this);
				}
				off+=de->d_reclen;
			}
		}
		close(dirfd);
		asprintf(&this,"%s/.-%s",vfs->source,path+vfs->pathlen);
		//fprint2("zapwipe %s\n",this);
		rmdir(this);
		free(this);
	}
}

static long viewfs_rmdir(char *path)
{
	struct viewfs *vfs = searchcontext(path, SUBSTR);
	char *vfspath=unwrap(vfs,path,0);
	int rv;
	//fprint2("viewfs_rmdir %s\n",path);
	//fprint2("ISEMPTY %s %d\n",path,isemptydir(vfs,path));
	if (vfs->flags & VIEWFS_MERGE) {
		if (isemptydir(vfs,path)) {
			if (vfs->flags & VIEWFS_COW) {
				if (vfs->flags & VIEWFS_MINCOW) { /* MINCOW */
					rv=rmdir(vfspath); /* try delete virtual  (what about dangling symlink?)*/
					if (rv<0 && errno==ENOENT) { /* doesn't exist */
						rv=rmdir(path); /* try delete real */
						if (rv<0 && (errno==EPERM || errno==EROFS || errno==ENOTEMPTY)) {
							zapwipedir(vfs,path);
							rv=wipeoutfile(vfs,path);
						} 
					} else if (rv==0) {
						int saverrno=errno;
						if (rv==0 && file_exist(path)) {
							zapwipedir(vfs,path);
							wipeoutfile(vfs,path);
						}
						errno=saverrno;
					} 
				} else { /* COW but not MIN */
					rv=rmdir(vfspath); /* try delete virtual  (what about dangling symlink?)*/
					if (rv<0 && errno==ENOENT) {  /* doesn't exist */
						zapwipedir(vfs,path);
						rv=wipeoutfile(vfs,path);
					} else if (rv==0) {
						int saverrno=errno;
						if (rv==0 && file_exist(path)) {
							zapwipedir(vfs,path);
							wipeoutfile(vfs,path);
						}
						errno=saverrno;
					}
				}
			} else { /* MERGE */
				if (file_exist(vfspath)) {
#ifdef MERGEROFS
					rv=-1;
					errno=EROFS;
#else
					rv=rmdir(vfspath);
#endif
				} else
					rv=rmdir(path);
			}
		} else {
			rv=-1;
			errno=ENOTEMPTY;
		}
	} else /* MOVE */
		rv=rmdir(vfspath);
	free(vfspath);
	return rv;
}

/* change something ch{mod,own} / utime(s) */
static long viewfs_chmod(char *path, int mode)
{
	struct viewfs *vfs = searchcontext(path, SUBSTR);
	int rv=0;
	char *vfspath=unwrap(vfs,path,0);
	if (vfs->flags & VIEWFS_MERGE) {
		if ((rv=cownoenterror(vfs,path,vfspath))==0) { /* ENOENT */
			if (vfs->flags & VIEWFS_COW) {
				if (file_exist(vfspath)) /* virt file */
					rv=chmod(vfspath,mode);
				else {
					if (vfs->flags & VIEWFS_MINCOW) { /* MINCOW */
						rv=chmod(path,mode);
						if (rv<0) {
							copyfile(path,vfspath,MAXSIZE);
							rv=chmod(vfspath,mode);
						}
					} else { /* COW  !MIN */
						copyfile(path,vfspath,MAXSIZE);
						rv=chmod(vfspath,mode);
					}
				}
			} else { /* MERGE */
				if (file_exist(vfspath)) {
#ifdef MERGEROFS
					rv=-1;
					errno=EROFS;
#else
					rv=chmod(vfspath,mode);
#endif
				} else
					rv=chmod(path,mode);
			}
		} 
	} else /* MOVE */
		rv=chmod(vfspath,mode);
	free(vfspath);
	return rv;
}

static long viewfs_chown(char *path, uid_t owner, gid_t group)
{
	struct viewfs *vfs = searchcontext(path, SUBSTR);
	int rv=0;
	char *vfspath=unwrap(vfs,path,0);
	if (vfs->flags & VIEWFS_MERGE) {
		if ((rv=cownoenterror(vfs,path,vfspath))==0) { /* ENOENT */
			if (vfs->flags & VIEWFS_COW) {
				if (file_exist(vfspath)) /* virt file */
					rv=chown(vfspath,owner,group);
				else { 
					if (vfs->flags & VIEWFS_MINCOW) { /* MINCOW */
						rv=chown(path,owner,group);
						if (rv<0) {
							copyfile(path,vfspath,MAXSIZE);
							rv=chown(vfspath,owner,group);
						}
					} else { /* COW  !MIN */
						copyfile(path,vfspath,MAXSIZE);
						rv=chown(vfspath,owner,group);
					}
				}
			} else { /* MERGE */
				if (file_exist(vfspath)) {
#ifdef MERGEROFS
					rv=-1;
					errno=EROFS;
#else
					rv=chown(vfspath,owner,group);
#endif
				} else
					rv=chown(path,owner,group);
			}
		}
	} else /* MOVE */
		rv=chown(vfspath,owner,group);
	free(vfspath);
	return rv;
}

static long viewfs_lchown(char *path, uid_t owner, gid_t group)
{
	struct viewfs *vfs = searchcontext(path, SUBSTR);
	int rv=0;
	char *vfspath=unwrap(vfs,path,0);
	if (vfs->flags & VIEWFS_MERGE) {
		if ((rv=cownoenterror(vfs,path,vfspath))==0) { /* ENOENT */
			if (vfs->flags & VIEWFS_COW) {
				if (file_exist(vfspath)) /* virt file */
					rv=lchown(vfspath,owner,group);
				else {         
					if (vfs->flags & VIEWFS_MINCOW) { /* MINCOW */
						rv=lchown(path,owner,group);
						if (rv<0) {
							copyfile(path,vfspath,MAXSIZE);
							rv=lchown(vfspath,owner,group);
						}
					} else { /* COW  !MIN */
						copyfile(path,vfspath,MAXSIZE);
						rv=lchown(vfspath,owner,group);
					}
				}
			} else { /* MERGE */
				if (file_exist(vfspath)) {
#ifdef MERGEROFS
					rv=-1;
					errno=EROFS;
#else
					rv=lchown(vfspath,owner,group);
#endif
				} else
					rv=lchown(path,owner,group);
			}
		}
	} else /* MOVE */
		rv=lchown(vfspath,owner,group);
	free(vfspath);
	return rv;

}

static long viewfs_utime(char *path, struct utimbuf *buf)
{
	struct viewfs *vfs = searchcontext(path, SUBSTR);
	int rv=0;
	char *vfspath=unwrap(vfs,path,0);
	if (vfs->flags & VIEWFS_MERGE) {
		if ((rv=cownoenterror(vfs,path,vfspath))==0) { /* ENOENT */
			if (vfs->flags & VIEWFS_COW) {
				if (file_exist(vfspath)) /* virt file */
					rv=utime(vfspath,buf);
				else {         
					if (vfs->flags & VIEWFS_MINCOW) { /* MINCOW */
						rv=utime(path,buf);
						if (rv<0) {
							copyfile(path,vfspath,MAXSIZE);
							rv=utime(vfspath,buf);
						}
					} else { /* COW  !MIN */
						copyfile(path,vfspath,MAXSIZE);
						rv=utime(vfspath,buf);
					}
				}
			} else { /* MERGE */
				if (file_exist(vfspath)) {
#ifdef MERGEROFS
					rv=-1;
					errno=EROFS;
#else
					rv=utime(vfspath,buf);
#endif
				} else
					rv=utime(path,buf);
			}
		}
	} else /* MOVE */
		rv=utime(vfspath,buf);
	free(vfspath);
	return rv;
}

static long viewfs_utimes(char *path, struct timeval tv[2])
{
	struct viewfs *vfs = searchcontext(path, SUBSTR);
	int rv=0;
	char *vfspath=unwrap(vfs,path,0);
	if (vfs->flags & VIEWFS_MERGE) {
		if ((rv=cownoenterror(vfs,path,vfspath))==0) { /* ENOENT */
			if (vfs->flags & VIEWFS_COW) {
				if (file_exist(vfspath)) /* virt file */
					rv=utimes(vfspath,tv);
				else {         
					if (vfs->flags & VIEWFS_MINCOW) { /* MINCOW */
						rv=utimes(path,tv);
						if (rv<0) {
							copyfile(path,vfspath,MAXSIZE);
							rv=utimes(vfspath,tv);
						}
					} else { /* COW  !MIN */
						copyfile(path,vfspath,MAXSIZE);
						rv=utimes(vfspath,tv);
					}
				}
			} else { /* MERGE */
				if (file_exist(vfspath)) {
#ifdef MERGEROFS
					rv=-1;
					errno=EROFS;
#else
					rv=utimes(vfspath,tv);
#endif
				} else
					rv=utimes(path,tv);
			}
		}
	} else /* MOVE */
		rv=utimes(vfspath,tv);
	free(vfspath);
	return rv;

}

static long viewfs_lseek(int fildes, int offset, int whence)
{
	return (int) lseek64(fildes, (off_t) offset, whence);
}

static long viewfs_msocket(char *path, int domain, int type, int protocol)
{
	struct viewfs *vfs = searchcontext(path, SUBSTR);
	char *vfspath=unwrap(vfs,path,0);
	int rv= msocket(vfspath,domain,type,protocol);
	free(vfspath);
	return rv;
}

static int merge_newentry(char *name,struct umdirent *tail,struct umdirent *oldtail)
{
	if (oldtail) {
		do {
			struct umdirent *next=tail->next;
			if (strcmp(next->de.d_name,name)==0)
				return 0;
			tail=next;
		} while (tail != oldtail);
	}
	return 1;
}

static struct umdirent *umadddirinfo(int fd, struct umdirent *head,
		int wipeout, int rootdir)
{
	if (fd) {
		char buf[4096];
		int len;
		struct umdirent *oldtail=head;
		long long offset;
		if (head==0)
			offset=0;
		else
			offset=head->de.d_off+WORDALIGN(12+strlen(head->de.d_name));
		while ((len=getdents64(fd,(struct dirent64 *)buf,4096)) > 0) {
			off_t off=0;
			while (off<len) {
				struct dirent64 *de=(struct dirent64 *)(buf+off);
				if (!(wipeout && de->d_type == DT_DIR) &&
						merge_newentry(de->d_name,head,oldtail))
				{
					/* .- must not appear in the dir listing! */
					if (!rootdir || (strcmp(de->d_name,".-") != 0)) {
						struct umdirent *new=(struct umdirent *)malloc(sizeof(struct umdirent));
						new->de.d_name=strdup(de->d_name);
						new->de.d_type=de->d_type;
						new->de.d_ino=de->d_ino;
						if (wipeout) {
							new->de.d_reclen=0;
							new->de.d_off=offset;
						} else {
							new->de.d_reclen=WORDALIGN(SIZEDIRENT64NONAME+strlen(de->d_name)+1);
							new->de.d_off=offset=offset+WORDALIGN(12+strlen(de->d_name));
						}
						if (head==NULL) {
							new->next=new;
						} else {
							new->next=head->next;
							head->next=new;
						}
						head=new;
					}
				}
				off+=de->d_reclen;
			}
		}
		return head;
	} else
		return NULL;
}

static struct umdirent *umfilldirinfo(int fd,char *mergepath,struct viewfs *vfs)
{
	struct umdirent *result=umadddirinfo(fd,NULL,0,*(mergepath+vfs->pathlen)==0);
	if (vfs->flags & VIEWFS_MERGE) {
		char *wipedir=wipeunwrap(vfs,mergepath);
		int mergefd=open(wipedir,O_RDONLY|O_DIRECTORY);
		if (mergefd) {
			result=umadddirinfo(mergefd,result,1,0);
			close(mergefd);
		}
		mergefd=open(mergepath,O_RDONLY|O_DIRECTORY);
		result=umadddirinfo(mergefd,result,0,0);
		close(mergefd);
	}
	return result;
}

static void umcleandirinfo(struct umdirent *tail)
{
	if (tail != NULL) {
		while (tail->next != tail) {
			struct umdirent *tmp;
			tmp=tail->next;
			tail->next=tmp->next;
			free(tmp->de.d_name);
			free(tmp);
		}
		free(tail);
	}
}

static long viewfs_getdents64(unsigned int fd, struct dirent64 *dirp, unsigned int count)
{
	if (FD_ISSET(fd,&viewfs_dirset)) {
		struct viewfsdir *vfsdir=viewfs_opendirs;
		while (vfsdir && vfsdir->fd != fd)
			vfsdir=vfsdir->next;
		if (vfsdir) {
			int curoffs=0;
			if (vfsdir->dirinfo == NULL) 
				vfsdir->dirinfo = umfilldirinfo(fd,vfsdir->path,vfsdir->vfs);
			if (vfsdir->dirinfo == NULL)
				return 0;
			else {
				struct dirent64 *current;
				char *base=(char *)dirp;
				int last=0;
				if (vfsdir->dirpos==NULL)
					vfsdir->dirpos=vfsdir->dirinfo;
				else
					last=(vfsdir->dirpos==vfsdir->dirinfo);
				while (!last && curoffs + vfsdir->dirpos->next->de.d_reclen < count)
				{
					vfsdir->dirpos=vfsdir->dirpos->next;
					current=(struct dirent64 *)base;
					if (vfsdir->dirpos->de.d_reclen > 0) {
						current->d_ino=vfsdir->dirpos->de.d_ino;
						current->d_off=vfsdir->dirpos->de.d_off;
						current->d_reclen=vfsdir->dirpos->de.d_reclen;
						current->d_type=vfsdir->dirpos->de.d_type;
						strcpy(current->d_name,vfsdir->dirpos->de.d_name);
						/* workaround: some FS do not set d_ino, but
						 *          * inode 0 is special and is skipped by libc */
						if (current->d_ino == 0)
							current->d_ino = 2;
						base+=vfsdir->dirpos->de.d_reclen;
						curoffs+=vfsdir->dirpos->de.d_reclen;
					}
					last=(vfsdir->dirpos == vfsdir->dirinfo);
				}
			}
			return curoffs;
		}
	} else
		return getdents64(fd,dirp,count);
}

static void viewfs_cow_init(struct viewfs *new)
{
	struct stat64 wipestat;
	char *wipepath;
	asprintf(&(wipepath),"%s/.-",new->source);
	mkdir(wipepath,0777);
	free(wipepath);
}

static long viewfs_mount(char *source, char *target, char *filesystemtype,
		unsigned long mountflags, void *data)
{
	int rv;
	int flags=0;
	char **exceptions=NULL;
	rv=viewfsargs(data,&flags,&exceptions);
	if (rv==0) {
		if (flags & VIEWFS_RENEW){
			flags &= ~VIEWFS_RENEW;
			struct viewfs *vfs=vfs_search(target,source,flags);
			if (vfs) {
				vfs->tst=tst_timestamp();
				rv=0;
			} else {
				errno=ENOENT;
				rv=-1;
			}
		} else {
			struct viewfs *new = (struct viewfs *) malloc(sizeof(struct viewfs));
			new->path = strdup(target);
			new->source = strdup(source);
			new->exceptions=exceptions;
			new->flags=flags;
			if (strcmp(target,"/")==0)
				new->pathlen = 0;
			else
				new->pathlen = strlen(target);
			if (flags & VIEWFS_COW)
				viewfs_cow_init(new);
			addviewfstab(new);
			new->tst=tst_timestamp();
		}
	}
	return rv;
}

static long viewfs_umount2(char *target, int flags)
{
	struct viewfs *vfs = searchcontext(target, EXACT);
	delviewfstab(vfs);
	free(vfs->path);
	free(vfs->source);
	freeexceptions(vfs->exceptions);
	free(vfs);
	return 0;
}

static void createscset(void)
{
	short *p;
	FD_ZERO(&fastsysset);
	for (p=fastsc;*p>=0;p++)
		FD_SET(*p,&fastsysset);
}

	static void
	__attribute__ ((constructor))
init (void)
{
	GMESSAGE("viewfs init");
	s.name="viewfs filesystem patchwork";
	s.code=0x05;
	s.checkfun=viewfspath;
	s.syscall=(sysfun *)calloc(scmap_scmapsize,sizeof(sysfun));
	s.socket=(sysfun *)calloc(scmap_sockmapsize,sizeof(sysfun));
	s.virsc=(sysfun *)calloc(scmap_virscmapsize,sizeof(sysfun));
	SERVICESYSCALL(s, mount, viewfs_mount);
	SERVICESYSCALL(s, umount2, viewfs_umount2);
	SERVICESYSCALL(s, open, viewfs_open);
	SERVICESYSCALL(s, read, read);
	SERVICESYSCALL(s, write, write);
	SERVICESYSCALL(s, close, viewfs_close);
#if __WORDSIZE == 32 //TODO: verify that ppc64 doesn't have these
	SERVICESYSCALL(s, stat64, viewfs_stat64);
	SERVICESYSCALL(s, lstat64, viewfs_lstat64);
	SERVICESYSCALL(s, fstat64, fstat64);
	SERVICESYSCALL(s, statfs64, viewfs_statfs64);
	SERVICESYSCALL(s, fstatfs64, fstatfs64);
#else
	SERVICESYSCALL(s, stat, viewfs_stat64);
	SERVICESYSCALL(s, lstat, viewfs_lstat64);
	SERVICESYSCALL(s, fstat, fstat64);
	SERVICESYSCALL(s, statfs, viewfs_statfs64);
	SERVICESYSCALL(s, fstatfs, fstatfs64);
#endif
	SERVICESYSCALL(s, readlink, viewfs_readlink);
	SERVICESYSCALL(s, getdents64, viewfs_getdents64);
	SERVICESYSCALL(s, access, viewfs_access);
#if __WORDSIZE == 32 //TODO: verify that ppc64 doesn't have these
	SERVICESYSCALL(s, fcntl, fcntl32);
	SERVICESYSCALL(s, fcntl64, fcntl64);
	SERVICESYSCALL(s, _llseek, _llseek);
#else
	SERVICESYSCALL(s, fcntl, fcntl);
#endif
	SERVICESYSCALL(s, lseek,  viewfs_lseek);
	SERVICESYSCALL(s, mkdir, viewfs_mkdir);
	SERVICESYSCALL(s, rmdir, viewfs_rmdir);
	SERVICESYSCALL(s, chown, viewfs_chown);
	SERVICESYSCALL(s, lchown, viewfs_lchown);
	SERVICESYSCALL(s, fchown, fchown);
	SERVICESYSCALL(s, chmod, viewfs_chmod);
	SERVICESYSCALL(s, fchmod, fchmod);
	SERVICESYSCALL(s, unlink, viewfs_unlink);
	SERVICESYSCALL(s, fsync, fsync);
	SERVICESYSCALL(s, fdatasync, fdatasync);
	SERVICESYSCALL(s, link, viewfs_link);
	SERVICESYSCALL(s, rename, viewfs_rename);
	SERVICESYSCALL(s, symlink, viewfs_symlink);
#if __WORDSIZE == 32
	SERVICESYSCALL(s, truncate64, viewfs_truncate64);
	//SERVICESYSCALL(s, ftruncate64, viewfs_ftruncate64);
#else
	SERVICESYSCALL(s, truncate, viewfs_truncate64);
	//SERVICESYSCALL(s, ftruncate, viewfs_ftruncate64);
#endif
	SERVICESYSCALL(s, pread64, pread64);
	SERVICESYSCALL(s, pwrite64, pwrite64);
	SERVICESYSCALL(s, utime, viewfs_utime);
	SERVICESYSCALL(s, utimes, viewfs_utimes);
	SERVICEVIRSYSCALL(s, msocket, viewfs_msocket);
	FD_ZERO(&viewfs_dirset);
	createscset();
	add_service(&s);
}

	static void
	__attribute__ ((destructor))
fini (void)
{
	free(s.syscall);
	free(s.socket);
	free(s.virsc);
	GMESSAGE("viewfs fini");
}
