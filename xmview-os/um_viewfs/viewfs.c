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
 *   $Id$
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
#include "viewfs0args.h"

#include "gdebug.h"
#define INFOEXT "\377"
#define MAXSIZE ((1LL<<((sizeof(size_t)*8)-1))-1)
#define MERGEROFS
#define FILEINFO

static struct service s;
VIEWOS_SERVICE(s)

static fd_set viewfs_dirset;
static fd_set fastsysset;
static uid_t xuid;
static gid_t xgid;
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
	int sourcelen;
	int flags;
};

#define WORDLEN sizeof(int *)
#define WORDALIGN(X) (((X) + WORDLEN) & ~(WORDLEN-1))
#define SIZEDIRENT64NONAME (sizeof(__u64)+sizeof(__s64)+sizeof(unsigned short)+sizeof(unsigned char))

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

static inline mode_t getumaskx(void)
{
	mode_t mask = umask( 0 );
	umask(mask);
	return mask;
}

/* Does this file exist? */
static mode_t file_exist(char *path)
{
	struct stat64 buf;
	if (lstat64(path,&buf)==0)
		return buf.st_mode;
	else
		return 0;
}

/* create all the missing dirs in the path */
static void create_path(struct viewfs *vfs,char *path)
{
	char *s=path+(vfs->sourcelen+1); /* avoid the path to the source dir */
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
static void destroy_path(struct viewfs *vfs,char *path,int wipe)
{
	char *s=path+(strlen(path)-1);
	char *base=path+(vfs->sourcelen+((wipe==0)?0:3)); /* protect ".-/" */
	int rv=0;
	while (rv==0 && s > base) {
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

	if (stat(oldpath,&oldstat)==0) {
		if (S_ISDIR(oldstat.st_mode)) {
			close(fdin);
			errno=EXDEV;
			return -1;
		}
		fdout=open(newpath,O_WRONLY|O_CREAT|O_TRUNC,(oldstat.st_mode & 0777) | 0600);
	}
	//printk("copyfile %s %s %d\n",oldpath,newpath,truncate);
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

/* path->newpath conversion */
static char *unwrap(struct viewfs *vfs,char *path)
{
	char *vfspath;
	asprintf(&vfspath,"%s%s",vfs->source,path+vfs->pathlen);
	return vfspath;
}

/* path of the hidden file for wipeouts (and rights) */
static inline char *wipeunwrap(struct viewfs *vfs,char *path,char *ext)
{
	char *wipefile;
	asprintf(&wipefile,"%s/.-%s%s",vfs->source,path+vfs->pathlen,ext);
	return wipefile;
}

/* boolean: is this deleted? */
static inline int isdeleted (struct viewfs *vfs,char *path)
{
	if (vfs->flags & VIEWFS_MERGE) {
		char *wipefile=wipeunwrap(vfs,path,"");
		struct stat64 buf;
		int erno=errno;
		int rv=lstat64(wipefile,&buf);
		rv=(rv==0 && S_ISREG(buf.st_mode));
		//printk("isdeleted %s %s %lo %d\n",path,wipefile,buf.st_mode,rv);
		free(wipefile);
		errno=erno;
		return rv;
	}
	return FALSE;
}

/* delete wipeout file / save errno */
static inline void wipeunlink (struct viewfs *vfs,char *path)
{
	int erno=errno;
	if (vfs->flags & VIEWFS_COW) {
		//char *realfile=unwrap(vfs,path);
		char *wipefile=wipeunwrap(vfs,path,"");
		if (unlink(wipefile) >= 0)
			destroy_path(vfs,wipefile,1);
		free(wipefile);
	}
	errno=erno;
}

static void create_vpath(struct viewfs *vfs,char *oldpath,char *path);
/* wipe out a file */
static inline int wipeoutfile (struct viewfs *vfs,char *path)
{
	int rv=0;
	if (vfs->flags & VIEWFS_COW) {
		char *realfile=unwrap(vfs,path);
		char *wipefile=wipeunwrap(vfs,path,"");
		char *infofile=wipeunwrap(vfs,path,INFOEXT);
		create_vpath(vfs,path,realfile);
		create_path(vfs,wipefile);
		/* DELETE OTHER info */
		unlink(infofile);
		rv=mknod(wipefile,S_IFREG|0666,0);
		free(realfile);
		free(wipefile);
		free(infofile);
	}
	return rv;
}

static inline void deleteinfo (struct viewfs *vfs,char *path)
{
	int saveerrno=errno;
	/* infofile must be eliminated when a VSTAT file system is later
		 mounted without vstat */
	if (vfs->flags & VIEWFS_COW /*&& vfs->flags & VIEWFS_VSTAT*/) {
		char *infofile=wipeunwrap(vfs,path,INFOEXT);
		if(unlink(infofile)>=0)
			destroy_path(vfs,infofile,1);
		free(infofile);
	}
	errno=saveerrno;
}

static inline unsigned int new_encode_dev(dev_t dev)
{
	unsigned major = major(dev);
	unsigned minor = minor(dev);
	return (minor & 0xff) | (major << 8) | ((minor & ~0xff) << 12);
}

static inline dev_t new_decode_dev(unsigned int dev)
{
	unsigned major = (dev & 0xfff00) >> 8;
	unsigned minor = (dev & 0xff) | ((dev >> 12) & 0xfff00);
	return makedev(major, minor);
}

static void gethexstat(struct viewfs *vfs,char *path,struct stat64 *st)
{ 
	char *infofile;
	char hexstat[60];
	int len;
	
#ifdef FILEINFO
	int fd;
  infofile=wipeunwrap(vfs,path,INFOEXT);
	if ((fd=open(infofile,O_RDONLY))>=0 && (len=read(fd,hexstat,60)) >= 24) {
#else
	infofile=wipeunwrap(vfs,path,INFOEXT);
	if ((len=readlink(infofile,hexstat,60)) >= 24) {
#endif
		if (*hexstat != ' ') {
			mode_t mode;
			sscanf(hexstat,"%08x",&mode);
			if (mode & S_IFMT)
				st->st_mode = mode;
			else
				st->st_mode = (st->st_mode & S_IFMT) | mode;
		}
		if (hexstat[8] != ' ') 
			sscanf(hexstat+8,"%08x",&st->st_uid);
		if (hexstat[16] != ' ') 
			sscanf(hexstat+16,"%08x",&st->st_gid);
		if (len>24) {
		  unsigned int kdev;	
			sscanf(hexstat+24,"%08x",&kdev);
			st->st_rdev=new_decode_dev(kdev);
		}
#ifdef FILEINFO
		close(fd);
#endif
	}
	free(infofile);
}

static void hexencode32(char *s,unsigned int v)
{
	static char hex[]={'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
	int i,j;
	for (i=0,j=7;i<8;i++,j--,v>>=4)
		s[j]=hex[v&0xf];
}

static void puthexstat(struct viewfs *vfs,char *path,
		mode_t mode, uid_t uid, gid_t gid, dev_t rdev)
{
	char *infofile;
	char hexstat[60];
	int len;
#ifdef FILEINFO
	int fd;
	infofile=wipeunwrap(vfs,path,INFOEXT);
	create_path(vfs,infofile);
	if ((fd=open(infofile,O_RDWR|O_CREAT,0644))<0 || (len=read(fd,hexstat,60)) < 24) 
	{
		memset(hexstat,' ',24);
		hexstat[24]=0;
		len=24;
	}
#else
	infofile=wipeunwrap(vfs,path,INFOEXT);
	if ((len=readlink(infofile,hexstat,60)) >= 24)
		unlink(infofile);
	else {
		memset(hexstat,' ',24);
		hexstat[24]=0;
	}
#endif
	if (mode) {
		if ((mode & S_IFMT) == 0 && len >= 24) {
			mode_t oldmode;
			sscanf(hexstat,"%08x",&oldmode);
			mode |= oldmode & S_IFMT;
		}
		hexencode32(hexstat,mode);
	}
	if (uid != -1) 
		hexencode32(hexstat+8,uid);
	if (gid != -1) 
		hexencode32(hexstat+16,gid);
	if (rdev) {
		unsigned int kdev=new_encode_dev(rdev);
		hexencode32(hexstat+24,kdev);
		hexstat[32]=0;
		len=32;
	}
#ifdef FILEINFO
	pwrite(fd,hexstat,len,0);
	close(fd);
#else
	create_path(vfs,infofile);
	//printk("%x %d %d %d=%s=\n",mode,uid,gid,rdev,hexstat);
	symlink(hexstat,infofile);
#endif
	free(infofile);
}

static void new_vstat(struct viewfs *vfs,char *path,mode_t mode,dev_t dev)
{
	uid_t euid;
	gid_t egid;
	/* fs rights must be used here, usually fsuid and fsgid 
		 are the same of euid/egid but users could use
		 set_fsuid/setfsgid */
	um_mod_getfs_uid_gid(&euid,&egid);
	//printk("new_vstat %s\n",path);
	if (euid != xuid || egid != xgid || dev != 0 || mode != 0) {
		puthexstat(vfs,path,mode,
				(euid == xuid)? -1:euid,
				(egid == xgid)? -1:egid,
				dev);
	}
}

/* the file move/link/rename so permissions must follow it */
static void copy_vvstat(struct viewfs *vfs,
		char *oldvpath, char *newvpath, /* pathnames as seen by users */
		char *oldpath,char *newpath) /* these must exist, as seen by the system */
{
	struct stat64 stold;
	struct stat64 stnew;
	/*printk("copy_vvstat %s->%s %s->%s %d->%d\n",oldvpath,newvpath,oldpath,newpath,
			lstat64(oldpath,&stold),lstat64(newpath,&stnew));*/
	if (lstat64(oldpath,&stold) == 0 && lstat64(newpath,&stnew) == 0) {
		gethexstat(vfs,oldvpath,&stold); /* update for virtual vstat */
		if ((stold.st_mode&0777) != (stnew.st_mode&0777)) {
			if (chmod(newpath,stold.st_mode)==0)
				stnew.st_mode = (stnew.st_mode&(~0777)) | (stold.st_mode&0777);
		}
		if (stold.st_uid != stnew.st_uid || stold.st_gid != stnew.st_gid) {
			if (chown(newpath,
						(stold.st_uid==stnew.st_uid)?-1:stold.st_uid,
						(stold.st_gid==stnew.st_gid)?-1:stold.st_gid)==0) {
				stnew.st_uid = stold.st_uid;
				stnew.st_gid = stold.st_gid;
			}
		}
		if (stold.st_mode != stnew.st_mode || stold.st_uid != stnew.st_uid || stold.st_gid != stnew.st_gid) 
			puthexstat(vfs,newvpath,
					(stold.st_mode==stnew.st_mode)?0:stold.st_mode,
					(stold.st_uid==stnew.st_uid)?-1:stold.st_uid,
					(stold.st_gid==stnew.st_gid)?-1:stold.st_gid,
					0);
	}
}

/* create a path (and set up permissions and owner/group if vstat */
static void create_vpath(struct viewfs *vfs,char *path,char *vfspath)
{
	if (vfs->flags & VIEWFS_VSTAT) {
		char *s=vfspath+(vfs->sourcelen+1);
		char *t=path+(vfs->pathlen+1);
		int mode=0777 & ~getumaskx();
		//printk("create_vpath %s %s %s %s\n",path,vfspath,s,t);
		while (*s) {
			if (*s=='/') {
				*s=0;
				if (mkdir(vfspath,mode) == 0) {
					struct stat64 stold;
					int rv;
					*t=0;
					rv=lstat64(path,&stold);
					if ((stold.st_mode & 07777) != mode)
						chmod(vfspath,stold.st_mode);
					if ((vfs->flags & VIEWFS_VSTAT) && rv==0 && (stold.st_uid != xuid || stold.st_gid != xgid))
						puthexstat(vfs,path,0,
								(stold.st_uid == xuid)? -1:stold.st_uid,
								(stold.st_gid == xgid)? -1:stold.st_gid ,
								0);
					*t='/';
				}
				*s='/';
			}
			s++;
			t++;
		}
	} else
		create_path(vfs,vfspath);
}

/* rename virtual to virtual simply move the infofile */
static void copy_vvlinkrename(struct viewfs *vfs, int (*linkrename)(),
		char *oldvpath, char *newvpath)
{
	char *oldinfo=wipeunwrap(vfs,oldvpath,INFOEXT);
	char *newinfo=wipeunwrap(vfs,newvpath,INFOEXT);
	linkrename(oldinfo,newinfo);
	free(oldinfo);
	free(newinfo);
}

/* copy from the real to the real world. The file does not move
	 (as seen from the users) */
static inline void copy_vstat(struct viewfs *vfs,
		char *oldpath,char *newpath) {
	//printk("copy_vstat %s %s\n",oldpath,newpath);
	copy_vvstat(vfs,oldpath,oldpath,oldpath,newpath);
}

static inline int cownoenterror(struct viewfs *vfs,char *path,char *vfspath)
{
	//printk("cownoenterror %s %d %d %d\n",path,file_exist(vfspath),file_exist(path),isdeleted(vfs,path));
	if (file_exist(vfspath) || (file_exist(path) && !isdeleted(vfs,path)))	
		return 0;
	else {
		errno=ENOENT;
		return -1;
	} 
}

static inline int cowexisterror(struct viewfs *vfs,char *path,char *vfspath)
{
	//printk("cowexisterror %s %d %d %d\n",path,file_exist(vfspath),file_exist(path),isdeleted(vfs,path));
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
			if (wok == 0) /* wok==0 means writable */
				rv= 0;
			else
				rv= 1;
		} else {
			rv=0;
			if (vfs->flags & VIEWFS_VSTAT) {
				uid_t euid;
				gid_t egid;
				/* fs ids  (more precise than effective ids) */
				um_mod_getfs_uid_gid(&euid,&egid);
				if (euid != xuid || egid != xgid)
					rv=1;
			}
			if (rv==0) {
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
					if (wok_parent == 0) /* means writable */
						rv= 0;
					else
						rv= 1;
				} else
					rv= 1; /* error case open !CREAT nonexistent file */
			}
		}
	} else if (vfs->flags & VIEWFS_COW) /* COW but not MIN */
		rv= 1;
	else  /* MERGE */
		rv= 0;
	//printk("open_exception %s %d %x\n",path,rv,vfs->flags);
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
		/* chdir to real dir when possible (is a dir & accessible) */
		if (sysno==__NR_chdir || sysno==__NR_fchdir) {
			int rv;
			rv=S_ISDIR(file_exist(path)) && (access(path,X_OK)==0);
			//printk("chdir %s %d %d\n",path,S_ISDIR(file_exist(path)),access(path,X_OK));
			return rv;
		}
		/* MERGE + COW */
		if (vfs->flags & VIEWFS_MERGE) {
			/* virtually deleted files goes virtual (otherwise they would be existent) */
			if (isdeleted(vfs,path)) {
				return 0;
			} else {
				/* all rare and non-dangerous calls gets managed by the modules
				 * *but* the fastsysset */
				if (FD_ISSET(sysno,&fastsysset)) {
					struct stat64 buf;
					char *vfspath=unwrap(vfs,path);
					int vfsrv=lstat64(vfspath,&buf);
					int openargc=1;
					//long openflag=0;
					long *scargs=um_mod_getargs();
#if 0
					if ((vfs->flags & VIEWFS_COW)) {
						long *scargs=um_mod_getargs();
						long sysno=um_mod_getsyscallno();
						int origrv=lstat64(path,&buf);
						printk("%d(%s) %s(%d) %s(%d) -> ",sysno, 
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
					//printk("+++%d\n",vfsrv<0);
					return (vfsrv<0);
				} else {
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

static int viewfs_confirm(int type, void *arg, int arglen,
		struct ht_elem *ht)
{
	char *path=arg;
	struct viewfs *fc=ht_get_private_data(ht);
	return !isexception(path,fc->pathlen,fc->exceptions,fc);
}

static long viewfs_open(char *path, int flags, mode_t mode)
{
	struct viewfs *vfs = um_mod_get_private_data();
	char *vfspath=unwrap(vfs,path);
	int rv;
	int cownewfile=0;
	if (vfs->flags & VIEWFS_DEBUG)
		printk("VIEWFS_OPEN %s->%s 0%o\n",path,vfspath,flags);
	/*printk("OPEN  %s %s %d %d 0%o\n",
			path,vfspath,file_exist(vfspath),isdeleted(vfs,path),flags);*/
	/* ACCMODE means O_WRONLY or O_RDWR - not O_RDONLY */
	if ((flags & O_ACCMODE) && (vfs->flags & VIEWFS_COW)) {
		create_vpath(vfs,path,vfspath);
		/* is not in cow but it exists, copy it! */
		if (!file_exist(vfspath)) {
			if (file_exist(path) && !isdeleted(vfs,path)) {
				rv=copyfile(path,vfspath,(flags & O_TRUNC)?0:MAXSIZE);
				if (rv >= 0 && (vfs->flags & VIEWFS_VSTAT))
					copy_vstat(vfs,path,vfspath);
			} else if (flags & O_CREAT)
				cownewfile=1;
		}
		rv=open(vfspath,flags,mode);
	} else
		rv=open(vfspath,flags,mode);
	if (rv >= 0) {
		wipeunlink(vfs,path);
		if ((vfs->flags & VIEWFS_MERGE) &&
				((flags & O_DIRECTORY) || S_ISDIR(file_exist(vfspath)))) {
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
		if (cownewfile && (vfs->flags & VIEWFS_VSTAT))
			new_vstat(vfs,path,0,0);
	}
	free(vfspath);
	return rv;
}

static long viewfs_truncate64(char *path, loff_t length)
{
	struct viewfs *vfs = um_mod_get_private_data();
	int rv=0;
	char *vfspath=unwrap(vfs,path);
	if (vfs->flags & VIEWFS_DEBUG)
		printk("VIEWFS_TRUNCATE %s->%s %d\n",path,vfspath,length);
	if (vfs->flags & VIEWFS_MERGE) {
		if ((rv=cownoenterror(vfs,path,vfspath))==0) { /* ENOENT */
			if (vfs->flags & VIEWFS_COW) {
				if (file_exist(vfspath)) /* virt file */
					rv=truncate64(vfspath,length);
				else {
					if (vfs->flags & VIEWFS_MINCOW) { /* MINCOW */
						rv=truncate64(path,length);
						if (rv<0) {
							create_path(vfs,vfspath);
							rv=copyfile(path,vfspath,length);
							if (rv >= 0 && (vfs->flags & VIEWFS_VSTAT))
								copy_vstat(vfs,path,vfspath);
						}
					} else { /* COW  !MIN */
						create_path(vfs,vfspath);
						rv=copyfile(path,vfspath,length);
						if (rv >= 0 && (vfs->flags & VIEWFS_VSTAT))
							copy_vstat(vfs,path,vfspath);
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
	struct viewfs *vfs = um_mod_get_private_data();
	char *vfsnewpath=unwrap(vfs,newpath);
	int rv=0;
	if (vfs->flags & VIEWFS_DEBUG)
		printk("VIEWFS_LINK %s %s->%s\n",oldpath,newpath,vfsnewpath);
	//printk("link %s %s %s\n",oldpath, newpath, vfsnewpath);
	if (vfs->flags & VIEWFS_MERGE) {
		if ((rv=cowexisterror(vfs,newpath,vfsnewpath))==0) { /* EEXIST */
			char *vfsoldpath=unwrap(vfs,oldpath);
			char *thisoldpath;
			if (file_exist(vfsoldpath))
				thisoldpath=vfsoldpath;
			else
				thisoldpath=oldpath;
			if (vfs->flags & VIEWFS_COW) {
				if (vfs->flags & VIEWFS_MINCOW) { /* MINCOW */
					rv=link(thisoldpath,newpath);
					if (rv<0) {
						create_vpath(vfs,newpath,vfsnewpath);
						rv=link(thisoldpath,vfsnewpath);
						//printk("link %s-%s -> %d\n",thisoldpath,vfsnewpath,rv);
						if (rv<0) {
							rv=copyfile(thisoldpath,vfsnewpath,MAXSIZE);
							if (rv>=0) {
								wipeunlink(vfs,newpath);
								if (vfs->flags & VIEWFS_VSTAT)
									copy_vvstat(vfs,oldpath,newpath,thisoldpath,vfsnewpath);
							}
						} else {
							wipeunlink(vfs,newpath);
							copy_vvlinkrename(vfs,link,oldpath,newpath);
						}
					}
				} else { /* COW but not MIN */
					create_vpath(vfs,newpath,vfsnewpath);
					rv=link(thisoldpath,vfsnewpath);
					//printk("link %s-%s -> %d\n",thisoldpath,vfsnewpath,rv);
					if (rv<0) {
						rv=copyfile(thisoldpath,vfsnewpath,MAXSIZE);
						if (rv>=0) {
							wipeunlink(vfs,newpath);
							if (vfs->flags & VIEWFS_VSTAT)
								copy_vvstat(vfs,oldpath,newpath,thisoldpath,vfsnewpath);
						}
					} else {
						wipeunlink(vfs,newpath);
						copy_vvlinkrename(vfs,link,oldpath,newpath);
					}
				}
			} else { /* MERGE */
				rv=link(thisoldpath,newpath);
			}
			free(vfsoldpath);
		}
	} else {  /* MOVE */
		char *vfsoldpath=unwrap(vfs,oldpath);
		rv=link(vfsoldpath,vfsnewpath);
		free(vfsoldpath);
	}
	free(vfsnewpath);
	return rv;
}

/* XXX if copy is needed, it does not manage directories */
static long viewfs_rename(char *oldpath, char *newpath)
{
	struct viewfs *vfs = um_mod_get_private_data();
	char *vfsnewpath=unwrap(vfs,newpath);
	int rv=0;
	/*printk("rename %s %s %s\n",oldpath, newpath, vfsnewpath);*/
	if (vfs->flags & VIEWFS_MERGE) {
		char *vfsoldpath=unwrap(vfs,oldpath);
		char *thisoldpath;
		if (file_exist(vfsoldpath))
			thisoldpath=vfsoldpath;
		else if (file_exist(oldpath))
			thisoldpath=oldpath;
		else {
			errno=ENOENT;
			free(vfsnewpath);
			free(vfsoldpath);
			return -1;
		}
		if (vfs->flags & VIEWFS_COW) {
			if (vfs->flags & VIEWFS_MINCOW) { /* MINCOW */
				rv=rename(thisoldpath,newpath);
				if (rv<0) {
					create_vpath(vfs,newpath,vfsnewpath);
					rv=rename(thisoldpath,vfsnewpath);
					if (rv<0) {
						rv=copyfile(thisoldpath,vfsnewpath,MAXSIZE);
						if (rv>=0) {
							wipeunlink(vfs,newpath);
							if (vfs->flags & VIEWFS_VSTAT)
								copy_vvstat(vfs,oldpath,newpath,thisoldpath,vfsnewpath);
						}
					} else {
						wipeunlink(vfs,newpath);
						if (vfs->flags & VIEWFS_VSTAT)
							copy_vvlinkrename(vfs,rename,oldpath,newpath);
					}
					if (rv>=0) {
						if(thisoldpath==vfsoldpath)
							unlink(vfsoldpath);
						if(file_exist(oldpath))
							wipeoutfile(vfs,oldpath);
					}
					/*printk("rename %s %s %d\n",oldpath,newpath,rv);*/
				}
			} else { /* COW but not MIN */
				create_vpath(vfs,newpath,vfsnewpath);
				rv=rename(thisoldpath,vfsnewpath);
				if (rv<0) {
					rv=copyfile(thisoldpath,vfsnewpath,MAXSIZE);
					if (rv>=0) {
						wipeunlink(vfs,newpath);
						if (vfs->flags & VIEWFS_VSTAT)
							copy_vvstat(vfs,oldpath,newpath,thisoldpath,vfsnewpath);
					}
				} else {
					wipeunlink(vfs,newpath);
					if (vfs->flags & VIEWFS_VSTAT)
						copy_vvlinkrename(vfs,link,oldpath,newpath);
				}
				if (rv>=0) {
					if(thisoldpath==vfsoldpath)
						unlink(vfsoldpath);
					if(file_exist(oldpath))
						wipeoutfile(vfs,oldpath);
				}
			}
			if (rv>=0) deleteinfo(vfs,oldpath);
		} else { /* MERGE */
			rv=rename(thisoldpath,newpath);
		}
		free(vfsoldpath);
	} else { /* MOVE */
		char *vfsoldpath=unwrap(vfs,oldpath);
		rv=rename(vfsoldpath,vfsnewpath);
		free(vfsoldpath);
	}
	if (vfs->flags & VIEWFS_DEBUG)
		printk("VIEWFS_RENAME %s %s->%s %d\n",oldpath,newpath,vfsnewpath,rv);
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
	struct viewfs *vfs = um_mod_get_private_data();
	char *vfspath=unwrap(vfs,path);
	int rv= statfs64(vfspath,buf);
	if (vfs->flags & VIEWFS_DEBUG)
		printk("VIEWFS_STATFS %s->%s rv %d\n",path,vfspath,rv);
	if (rv<0 && errno==ENOENT && (vfs->flags & VIEWFS_MERGE) && !isdeleted(vfs,path)) 
		rv= statfs64(path,buf);
	free(vfspath);
	return rv;
}

static long viewfs_lstat64(char *path, struct stat64 *buf)
{
	struct viewfs *vfs = um_mod_get_private_data();
	char *vfspath=unwrap(vfs,path);
	int rv= lstat64(vfspath,buf);
	if (rv<0 && errno==ENOENT && (vfs->flags & VIEWFS_MERGE) && !isdeleted(vfs,path)) {
		rv= lstat64(path,buf);
		/* the path resolution process passes through the file system tree
			 to the leaf node. If lstat64 returns EACCESS means that:
			 - the dir is virtual.
			 - the file does not exist
			 - the (real) dir is protected. So the error is converted to ENOENT */
		if (errno==EACCES) errno=ENOENT;
	}
	if ((vfs->flags & VIEWFS_VSTAT) && rv==0)
		gethexstat(vfs,path,buf);
	if (vfs->flags & VIEWFS_DEBUG)
		printk("VIEWFS_LSTAT %s->%s rv %d\n",path,vfspath,rv);
	free(vfspath);
	if (rv==0 && vfs->flags & VIEWFS_WOK)
		buf->st_mode |= 0222;
	//printk("viewfs_lstat64 %s rv=%d errno=%d\n",path,rv,errno);
	return rv;
}

static long viewfs_readlink(char *path, char *buf, size_t bufsiz)
{
	struct viewfs *vfs = um_mod_get_private_data();
	char *vfspath=unwrap(vfs,path);
	int rv= readlink(vfspath,buf,bufsiz);
	if (vfs->flags & VIEWFS_DEBUG)
		printk("VIEWFS_READLINK %s->%s rv %d\n",path,vfspath,rv);
	if (rv<0 && errno==ENOENT && (vfs->flags & VIEWFS_MERGE) && !isdeleted(vfs,path)) 
		rv= readlink(path,buf,bufsiz);
	free(vfspath);
	return rv;
}

static long viewfs_access(char *path, int mode)
{
	struct viewfs *vfs = um_mod_get_private_data();
	uid_t euid;
	um_mod_getfs_uid_gid(&euid,NULL);
	if (euid==0) {
		if (vfs->flags & VIEWFS_DEBUG)
			printk("VIEWFS_ACCESS %s ROOT ACCESS\n",path);
		return 0;
	} else if (mode==W_OK && (vfs->flags & VIEWFS_WOK)) {
		if (vfs->flags & VIEWFS_DEBUG)
			printk("VIEWFS_ACCESS %s WOK\n",path);
		return 0;
	} else {
		char *vfspath=unwrap(vfs,path);
		int rv= access(vfspath,mode);
		if (vfs->flags & VIEWFS_DEBUG)
			printk("VIEWFS_ACCESS %s->%s %d rv %d\n",path,vfspath,mode,rv);
		if (rv<0 && errno==ENOENT && (vfs->flags & VIEWFS_MERGE) && !isdeleted(vfs,path))
			rv= access(path,mode);
		//printk("access %s %d-> %d\n",path,mode,rv);
		free(vfspath);
		return rv;
	}
}

/* add something: mkdir, symlink, link */
static long viewfs_mkdir(char *path, int mode)
{
	struct viewfs *vfs = um_mod_get_private_data();
	int rv=0;
	char *vfspath=unwrap(vfs,path);
	if (vfs->flags & VIEWFS_DEBUG)
		printk("VIEWFS_MKDIR %s->%s \n",path,vfspath);
	if (vfs->flags & VIEWFS_MERGE) {
		if ((rv=cowexisterror(vfs,path,vfspath))==0) { /* EEXIST */
			if (vfs->flags & VIEWFS_COW) {
				if (vfs->flags & VIEWFS_MINCOW) { /* MINCOW */
					rv=mkdir(path,mode);
					if (rv<0) {
						create_vpath(vfs,path,vfspath);
						rv=mkdir(vfspath,mode);
						if (rv>=0) wipeunlink(vfs,path);
					}
					if (rv >= 0 && (vfs->flags & VIEWFS_VSTAT))
						new_vstat(vfs,path,0,0);
				} else { /* COW but not MIN */
					create_vpath(vfs,path,vfspath);
					rv=mkdir(vfspath,mode);
					if (rv>=0) wipeunlink(vfs,path);
					if (rv >= 0 && (vfs->flags & VIEWFS_VSTAT))
						new_vstat(vfs,path,0,0);
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

static int viewfs_mknod(char *path, mode_t mode, dev_t dev)
{
	struct viewfs *vfs = um_mod_get_private_data();
	int rv=0;
	char *vfspath=unwrap(vfs,path);
	if (vfs->flags & VIEWFS_DEBUG)
		printk("VIEWFS_MKNOD %s->%s \n",path,vfspath);
	if (vfs->flags & VIEWFS_MERGE) {
		if ((rv=cowexisterror(vfs,path,vfspath))==0) { /* EEXIST */
			if (vfs->flags & VIEWFS_COW) {
				if (vfs->flags & VIEWFS_MINCOW) { /* MINCOW */
					rv=mknod(path,mode,dev);
					if (rv<0) {
						create_vpath(vfs,path,vfspath);
						rv=mknod(vfspath,mode,dev);
						if (rv<0) 
							rv=mknod(vfspath,(mode&0777)|S_IFREG,0);
						if (rv>=0) wipeunlink(vfs,path);
					}
					if (rv >= 0 && (vfs->flags & VIEWFS_VSTAT))
						new_vstat(vfs,path,mode& ~getumaskx(),dev);
				} else { /* COW but not MIN */
					create_vpath(vfs,path,vfspath);
					rv=mknod(vfspath,mode,dev);
					if (rv<0) 
						rv=mknod(vfspath,(mode&0777)|S_IFREG,0);
					if (rv>=0) wipeunlink(vfs,path);
					if (rv >= 0 && (vfs->flags & VIEWFS_VSTAT))
						new_vstat(vfs,path,mode& ~getumaskx(),dev);
				}
			} else { /* MERGE */
				rv=mknod(path,mode,dev);
			}
		}
	} else /* MOVE */
		rv=mknod(vfspath,mode,dev);
	free(vfspath);
	return rv;
}

static long viewfs_symlink(char *oldpath, char *newpath)
{
	struct viewfs *vfs = um_mod_get_private_data();
	char *vfspath=unwrap(vfs,newpath);
	int rv=0;
	if (vfs->flags & VIEWFS_DEBUG)
		printk("VIEWFS_SYMLINK %s %s->%s \n",oldpath,newpath,vfspath);
	if (vfs->flags & VIEWFS_MERGE) {
		if ((rv=cowexisterror(vfs,newpath,vfspath))==0) { /* EEXIST */
			if (vfs->flags & VIEWFS_COW) {
				if (vfs->flags & VIEWFS_MINCOW) { /* MINCOW */
					rv=symlink(oldpath,newpath);
					if (rv<0) {
						create_vpath(vfs,newpath,vfspath);
						rv=symlink(oldpath,vfspath);
						if (rv>=0) wipeunlink(vfs,newpath);
					}
					if (rv >= 0 && (vfs->flags & VIEWFS_VSTAT))
						new_vstat(vfs,newpath,0,0);
				} else { /* COW but not MIN */
					create_vpath(vfs,newpath,vfspath);
					rv=symlink(oldpath,vfspath);
					if (rv>=0) wipeunlink(vfs,newpath);
					if (rv >= 0 && (vfs->flags & VIEWFS_VSTAT))
						new_vstat(vfs,oldpath,0,0);
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
	struct viewfs *vfs = um_mod_get_private_data();
	char *vfspath=unwrap(vfs,path);
	int rv=0;
	if (vfs->flags & VIEWFS_DEBUG)
		printk("VIEWFS_UNLINK %s->%s \n",path,vfspath);
	//printk("viewfs_unlink %s\n",path);
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
				if (rv>=0)
					deleteinfo(vfs,path);
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
					//printk("isemptydir %s %s %d\n",de->d_name,this,isdeleted(vfs,this));
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
					//printk("zapwipe %s %s\n",de->d_name,this);
					unlink(this);
					free(this);
				}
				off+=de->d_reclen;
			}
		}
		close(dirfd);
		asprintf(&this,"%s/.-%s",vfs->source,path+vfs->pathlen);
		//printk("zapwipe %s\n",this);
		rmdir(this);
		free(this);
	}
}

static long viewfs_rmdir(char *path)
{
	struct viewfs *vfs = um_mod_get_private_data();
	char *vfspath=unwrap(vfs,path);
	int rv;
	if (vfs->flags & VIEWFS_DEBUG)
		printk("VIEWFS_RMDIR %s->%s \n",path,vfspath);
	//printk("viewfs_rmdir %s\n",path);
	//printk("ISEMPTY %s %d\n",path,isemptydir(vfs,path));
	if (vfs->flags & VIEWFS_MERGE) {
		if (isemptydir(vfs,path)) {
			if (vfs->flags & VIEWFS_COW) {
				if (vfs->flags & VIEWFS_MINCOW) { /* MINCOW */
					rv=rmdir(vfspath); /* try delete virtual  (what about dangling symlink?)*/
					if (rv<0 && errno==ENOENT) { /* doesn't exist */
						rv=rmdir(path); /* try delete real */
						if (rv<0 && (errno==EACCES || errno==EPERM || errno==EROFS || errno==ENOTEMPTY)) {
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
				if (rv>=0)
					deleteinfo(vfs,path);
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

static int vchmod(struct viewfs *vfs, char *path,
		char *vfspath, mode_t mode, int copy)
{
	if (vfs->flags & VIEWFS_VSTAT) {
		if (chmod(vfspath,mode) < 0)
			chmod(vfspath,mode&0777);
		puthexstat(vfs,path,mode,-1,-1,0);
		errno = 0;
		return 0;
	} else {
		if (copy) {
			create_vpath(vfs,path,vfspath);
			copyfile(path,vfspath,MAXSIZE);
		}
		return chmod(vfspath,mode);
	}
}

/* change something ch{mod,own} / utime(s) */
static long viewfs_chmod(char *path, int mode)
{
	struct viewfs *vfs = um_mod_get_private_data();
	int rv=0;
	char *vfspath=unwrap(vfs,path);
	if (vfs->flags & VIEWFS_DEBUG)
		printk("VIEWFS_CHMOD %s->%s 0%o\n",path,vfspath,mode);
	if (vfs->flags & VIEWFS_MERGE) {
		if ((rv=cownoenterror(vfs,path,vfspath))==0) { /* ENOENT */
			if (vfs->flags & VIEWFS_COW) {
				if (file_exist(vfspath)) {/* virt file */
					rv=vchmod(vfs,path,vfspath,mode,0);
				} else {
					if (vfs->flags & VIEWFS_MINCOW) { /* MINCOW */
						rv=chmod(path,mode);
						if (rv<0) {
							rv=vchmod(vfs,path,vfspath,mode,1);
						}
					} else { /* COW  !MIN */
						rv=vchmod(vfs,path,vfspath,mode,1);
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


static int vchown(struct viewfs *vfs, int (*chownf)(), char *path,
		char *vfspath, uid_t owner, gid_t group, int copy)
{
	if (vfs->flags & VIEWFS_VSTAT) {
		chown(vfspath,owner,group);
		puthexstat(vfs,path,0,owner,group,0);
	} else {
		if (copy){
			create_vpath(vfs,path,vfspath);
			copyfile(path,vfspath,MAXSIZE);
		}
		chown(vfspath,owner,group);
	}
	errno = 0;
	return 0;
}

static long viewfs_lchown(char *path, uid_t owner, gid_t group)
{
	struct viewfs *vfs = um_mod_get_private_data();
	int rv=0;
	char *vfspath=unwrap(vfs,path);
	if (vfs->flags & VIEWFS_DEBUG)
		printk("VIEWFS_LCHOWN %s->%s %d %d\n",path,vfspath,owner,group);
	if (vfs->flags & VIEWFS_MERGE) {
		if ((rv=cownoenterror(vfs,path,vfspath))==0) { /* ENOENT */
			if (vfs->flags & VIEWFS_COW) {
				if (file_exist(vfspath)) { /* virt file */
					rv=vchown(vfs,lchown,path,vfspath,owner,group,0);
				}
				else {         
					if (vfs->flags & VIEWFS_MINCOW) { /* MINCOW */
						rv=lchown(path,owner,group);
						if (rv<0) {
							rv=vchown(vfs,lchown,path,vfspath,owner,group,1);
						}
					} else { /* COW  !MIN */
						rv=vchown(vfs,lchown,path,vfspath,owner,group,1);
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

static long viewfs_utimes(char *path, struct timeval *tv)
{
	struct viewfs *vfs = um_mod_get_private_data();
	int rv=0;
	char *vfspath=unwrap(vfs,path);
	if (vfs->flags & VIEWFS_DEBUG)
		printk("VIEWFS_UTIMES %s->%s %ld %ld\n",path,vfspath,(tv)?tv[0].tv_sec:0,(tv)?tv[1].tv_sec:0);
	if (vfs->flags & VIEWFS_MERGE) {
		if ((rv=cownoenterror(vfs,path,vfspath))==0) { /* ENOENT */
			if (vfs->flags & VIEWFS_COW) {
				if (file_exist(vfspath)) /* virt file */
					rv=utimes(vfspath,tv);
				else {         
					if (vfs->flags & VIEWFS_MINCOW) { /* MINCOW */
						rv=utimes(path,tv);
						if (rv<0) {
							create_path(vfs,vfspath);
							rv=copyfile(path,vfspath,MAXSIZE);
							if (rv >= 0 && (vfs->flags & VIEWFS_VSTAT))
								copy_vstat(vfs,path,vfspath);
							rv=utimes(vfspath,tv);
						}
					} else { /* COW  !MIN */
						create_path(vfs,vfspath);
						rv=copyfile(path,vfspath,MAXSIZE);
						if (rv >= 0 && (vfs->flags & VIEWFS_VSTAT))
							copy_vstat(vfs,path,vfspath);
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
	struct viewfs *vfs = um_mod_get_private_data();
	char *vfspath=unwrap(vfs,path);
	int rv= msocket(vfspath,domain,type,protocol);
	if (vfs->flags & VIEWFS_DEBUG)
		printk("VIEWFS_MSOCKET %s->%s rv %d\n",path,vfspath,rv);
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
				if (!(wipeout && de->d_type != DT_REG) && 
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

static inline int real_pathlen(struct viewfs *vfs)
{
	if (vfs->pathlen == 0)
		return 1;
	else
		return vfs->pathlen;
}

/* populate the directory buffer. */
static struct umdirent *umfilldirinfo(int fd,char *mergepath,struct viewfs *vfs)
{
	/* add the entries of the destination dir*/
	struct umdirent *result=umadddirinfo(fd,NULL,0,*(mergepath+real_pathlen(vfs))==0);
	if (vfs->flags & VIEWFS_MERGE) {
		char *wipedir=wipeunwrap(vfs,mergepath,"");
		int mergefd=open(wipedir,O_RDONLY|O_DIRECTORY);
		/* add NULL entries of the deleted files */
		if (mergefd>=0) {
			result=umadddirinfo(mergefd,result,1,0);
			close(mergefd);
		}
		/* add the entries in the source dir (if there an entry is deleted it is a
			 dup entry of the NULL entry so it is not inserted) */
		mergefd=open(mergepath,O_RDONLY|O_DIRECTORY);
		if (mergefd>=0) {
			result=umadddirinfo(mergefd,result,0,0);
			close(mergefd);
		}
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
						 * inode 0 is special and is skipped by libc */
						if (current->d_ino == 0)
							current->d_ino = 2;
						base+=vfsdir->dirpos->de.d_reclen;
						curoffs+=vfsdir->dirpos->de.d_reclen;
					}
					last=(vfsdir->dirpos == vfsdir->dirinfo);
				}
			}
			return curoffs;
		} else
			return -1;
	} else
		return getdents64(fd,dirp,count);
}

static void viewfs_cow_init(struct viewfs *new)
{
	//struct stat64 wipestat;
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
	if (flags & VIEWFS_DEBUG)
		printk("VIEWFS_MOUNT source %s target %s\n",source,target);
	if (rv==0) {
		if (flags & VIEWFS_RENEW){
			flags &= ~VIEWFS_RENEW;
			struct ht_elem *hte=ht_search(CHECKPATH,target,
					strlen(target),&s);
			if (hte) {
				struct viewfs *vfs=ht_get_private_data(hte);
				if (strcmp(source,vfs->source)==0) 
					ht_renew(hte);
				else {
					errno=ENOENT;
					rv=-1;          
				}    
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
			new->sourcelen = strlen(source);
			if (strcmp(target,"/")==0)
				new->pathlen = 0;
			else
				new->pathlen = strlen(target);
			if (flags & VIEWFS_COW)
				viewfs_cow_init(new);
			ht_tab_pathadd(CHECKPATH,source,target,filesystemtype,mountflags,data,&s,0,viewfs_confirm,new);
		}
	}
	return rv;
}

static long viewfs_umountinternal(struct viewfs *vfs, int flags)
{
	if (vfs->flags & VIEWFS_DEBUG)
		printk("VIEWFS_UMOUNT source %s target %s\n",vfs->source,vfs->path);
	free(vfs->path);
	free(vfs->source);
	freeexceptions(vfs->exceptions);
	free(vfs);
	return 0;
}

static long viewfs_umount2(char *target, int flags)
{
	struct viewfs *vfs = um_mod_get_private_data();
	viewfs_umountinternal(vfs,flags);
	ht_tab_del(um_mod_get_hte());
	return 0;
}

static void createscset(void)
{
	short *p;
	FD_ZERO(&fastsysset);
	for (p=fastsc;*p>=0;p++)
		FD_SET(*p,&fastsysset);
}

static long viewfs_event_subscribe(void (* cb)(), void *arg, int fd, int how)
{
	return um_mod_event_subscribe(cb,arg,fd,how);
}

	static void
	__attribute__ ((constructor))
init (void)
{
	GMESSAGE("viewfs init");
	s.name="viewfs";
	s.description="filesystem patchwork";
	s.syscall=(sysfun *)calloc(scmap_scmapsize,sizeof(sysfun));
	s.socket=(sysfun *)calloc(scmap_sockmapsize,sizeof(sysfun));
	s.virsc=(sysfun *)calloc(scmap_virscmapsize,sizeof(sysfun));
	xuid=getuid();
	xgid=getgid();
	SERVICESYSCALL(s, mount, viewfs_mount);
	SERVICESYSCALL(s, umount2, viewfs_umount2);
	SERVICESYSCALL(s, open, viewfs_open);
	SERVICESYSCALL(s, read, read);
	SERVICESYSCALL(s, write, write);
	SERVICESYSCALL(s, close, viewfs_close);
#if __WORDSIZE == 32 //TODO: verify that ppc64 doesn't have these
	SERVICESYSCALL(s, lstat64, viewfs_lstat64);
	SERVICESYSCALL(s, statfs64, viewfs_statfs64);
#else
	SERVICESYSCALL(s, lstat, viewfs_lstat64);
	SERVICESYSCALL(s, statfs, viewfs_statfs64);
#endif
	SERVICESYSCALL(s, readlink, viewfs_readlink);
	SERVICESYSCALL(s, getdents64, viewfs_getdents64);
	SERVICESYSCALL(s, access, viewfs_access);
#if __WORDSIZE == 32 //TODO: verify that ppc64 doesn't have these
	SERVICESYSCALL(s, fcntl, fcntl64);
	SERVICESYSCALL(s, _llseek, _llseek);
#else
	SERVICESYSCALL(s, fcntl, fcntl);
#endif
	SERVICESYSCALL(s, lseek,  viewfs_lseek);
	SERVICESYSCALL(s, mkdir, viewfs_mkdir);
	SERVICESYSCALL(s, rmdir, viewfs_rmdir);
	SERVICESYSCALL(s, lchown, viewfs_lchown);
	SERVICESYSCALL(s, chmod, viewfs_chmod);
	SERVICESYSCALL(s, unlink, viewfs_unlink);
	SERVICESYSCALL(s, fsync, fsync);
	SERVICESYSCALL(s, fdatasync, fdatasync);
	SERVICESYSCALL(s, link, viewfs_link);
	SERVICESYSCALL(s, rename, viewfs_rename);
	SERVICESYSCALL(s, symlink, viewfs_symlink);
#if __WORDSIZE == 32
	SERVICESYSCALL(s, truncate64, viewfs_truncate64);
	SERVICESYSCALL(s, ftruncate64, ftruncate64);
#else
	SERVICESYSCALL(s, truncate, viewfs_truncate64);
	SERVICESYSCALL(s, ftruncate, ftruncate64);
#endif
	SERVICESYSCALL(s, pread64, pread64);
	SERVICESYSCALL(s, pwrite64, pwrite64);
	SERVICESYSCALL(s, utimes, viewfs_utimes);
	SERVICESYSCALL(s, mknod, viewfs_mknod);
	SERVICEVIRSYSCALL(s, msocket, viewfs_msocket);
	s.event_subscribe=viewfs_event_subscribe;
	FD_ZERO(&viewfs_dirset);
	createscset();
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
