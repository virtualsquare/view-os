/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   UMBINFMT: Virtual BinFMT
 *    Copyright (C) 2006  Renzo Davoli <renzo@cs.unibo.it>
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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include <utime.h>
#include <limits.h>
#include <sys/time.h>
#include <sys/mount.h>
#include <dlfcn.h>
#include <pthread.h>
#include <linux/types.h>
#include <linux/unistd.h>
#include <stdarg.h>
#include <stdint.h>
#include <sys/types.h>
#include <config.h>
#include "module.h"
#include "libummod.h"
//#include "umbinfmt.h"

/* Enable umbinfmt own debug output */

//#define __UMBINFMT_DEBUG__ 1   /* it is better to enable it from makefile */
#ifndef __UMBINFMT_DEBUG_LEVEL__
#define __UMBINFMT_DEBUG_LEVEL__ 0
#endif

#ifdef __UMBINFMT_DEBUG__
#define PRINTDEBUG(level,args...) printdebug(level, __FILE__, __LINE__, __func__, args)
#else
#define PRINTDEBUG(level,args...)
#endif

/* internal real system call insulated for nesting */
#define syscall_stat64 stat64
#define syscall_getuid getuid
#define syscall_getgid getgid

static struct service s;
VIEWOS_SERVICE(s)

static struct ht_elem *service_ht;

struct binfileinfo {
	struct umregister *reg;
	struct umbinfmt *bfmount;
	int flags;
	int pos;
	int len;
	char *contents;
};

struct umregister {
	char *name;
	unsigned char enabled;
	char type;
	unsigned char offset;
	unsigned char len;
	unsigned char *flags;
	unsigned char *magic;
	unsigned char *mask;
	char *interpreter;
	struct umregister *next;
};

static char rootdir[]="/";
static char registerfile[]="register";
static char statusfile[]="status";
#define UBM_IS_ROOT(X) ((X) == ((struct umregister *)rootdir))
#define UBM_IS_REGISTER(X) ((X) == ((struct umregister *)registerfile))
#define UBM_IS_STATUS(X) ((X) == ((struct umregister *)statusfile))

#define UMBINFMT_DEBUG 1

struct umbinfmt {
	char *path;
	unsigned char enabled;
	char flags;
	int inuse;
	struct umregister *head;
	struct ht_elem *binfmt_ht;
};

struct umbinfmt_dirent64 {
	__ino64_t             d_ino;
	__off64_t             d_off;
	unsigned short  d_reclen;
	unsigned char   d_type;
	char            d_name[0];
};

#ifdef __UMBINFMT_DEBUG__
static void printdebug(int level, const char *file, const int line, const char *func, const char *fmt, ...) {
	va_list ap;

	if (level >= __UMBINFMT_DEBUG_LEVEL__) {
		va_start(ap, fmt);
#ifdef _PTHREAD_H
		printk("[%d:%lu] dev %s:%d %s(): ", getpid(), pthread_self(), file, line, func);
#else
		printk("[%d] dev %s:%d %s(): ", getpid(), file, line, func);
#endif
		vprintk(fmt, ap);
		printk("\n");
		va_end(ap);
	}
}
#endif

static int searchbinfmt(struct umbinfmt *fc,struct binfmt_req *req)
{
	char *buf=req->buf;
	if (fc->enabled) {
		struct umregister *scan=fc->head;
		while (scan != NULL && req->interp==NULL) {
			if (scan->enabled) {
				if (scan->type == 'E') {
					int suffixpos=strlen(req->path)-scan->len;
					if (suffixpos>0 && strcmp(req->path+suffixpos,scan->magic)==0) {
						req->interp=scan->interpreter;
						req->flags=(strchr(scan->flags,'P') != NULL)?BINFMT_KEEP_ARG0:0;
					}
				} else if (scan->type == 'M') {
					int i,j,diff;
					/*for (i=scan->offset,j=0,diff=0;i<128 && j<scan->len && diff==0;i++,j++)
						printk("%02x %02x %02x %2x\n",buf[i],scan->magic[j],scan->mask[j],
						(buf[i] ^ scan->magic[j]) & scan->mask[j]);*/
					for (i=scan->offset,j=0,diff=0;i<128 && j<scan->len && diff==0;i++,j++)
						diff=(buf[i] ^ scan->magic[j]) & scan->mask[j];
					if (diff==0) {
						req->interp=scan->interpreter;
						req->flags=(strchr(scan->flags,'P') != NULL)?BINFMT_KEEP_ARG0:0;
					}
				}
			}
			scan=scan->next;
		}
	}
	//printk("searchbinfmt %s %s\n",req->path,req->interp);
	if (req->interp!=NULL)
		return 1;
	else
		return 0;
}

#if 0
#define MAXARGS 256

static void debugfun(char *s,struct umbinfmt *fc)
{
#ifdef DEBUGUMBINFMTARGS
	printf("DEBUG\n");
#endif
	fc->flags |= UMBINFMT_DEBUG;
}

void devargs(char *opts, struct devargitem *devargtab, int devargsize, void *arg)
{
	char *sepopts[MAXARGS];
	int nsepopts=0;
	int i;
	char *optcopy=strdup(opts);
	char *s=optcopy;
	char quote=0,olds;
#ifdef DEBUGUMBINFMTARGS
	printf("devargs opts %s\n",s);
#endif
	/* PHASE 1: tokenize options */
	for (quote=0,s=opts,olds=*s;olds != 0 && nsepopts < MAXARGS;s++) {
		sepopts[nsepopts++]=s;
		while (*s != 0 && (*s != ',' || quote != 0))
		{
			if (*s=='\\' && *(s+1)!=0)
				s+=2;
			if (*s=='\'' || *s=='\"') {
				if (*s == quote)
					quote=0;
				else
					if (quote==0)
						quote=*s;
			}
			s++;
		}
		olds=*s;*s=0;
	}
#ifdef DEBUGUMBINFMTARGS
	for (i=0;i<nsepopts;i++)
		printf("separg %d = %s\n",i,sepopts[i]);
#endif
	/* PHASE 2 recognize UMUMBINFMT options */
	for (i=0;i<nsepopts;i++) {
		int j;
		for (j=0; j<devargsize && 
				strncmp(sepopts[i],devargtab[j].arg,strlen(devargtab[j].arg)) != 0; j++)
			;
		if (j<devargsize)
			devargtab[j].fun(sepopts[i]+strlen(devargtab[j].arg),arg);
	}
	free(optcopy);
}

static struct devargitem umbinfmtargtab[] = {
	{"debug", debugfun},
};
#define UMBINFMTARGTABSIZE sizeof(umbinfmtargtab)/sizeof(struct devargitem)
#endif

static struct umregister *delete_reg(struct umregister *head, struct umregister *this)
{
	if (head == NULL)
		return NULL;
	else if (head == this) {
		struct umregister *next=this->next;
		free(this->name);
		free(this->flags);
		free(this->magic);
		free(this->mask);
		free(this->interpreter);
		free(this);
		return next;
	} else
		return delete_reg(head->next,this);
}

static struct umregister *delete_allreg(struct umregister *head)
{
	if (head == NULL)
		return NULL;
	else {
		delete_allreg(head->next);
		free(head->name);
		free(head->flags);
		free(head->magic);
		free(head->mask);
		free(head->interpreter);
		free(head);
		return NULL;
	}
}

static int checkbinfmt(int type, void *arg, int arglen, struct ht_elem *ht)
{
	struct binfmt_req *req=arg;
	void *private_data=ht_get_private_data(ht);
	if (private_data)
		return searchbinfmt(private_data,req);
	else
		return 0;
}

static long umbinfmt_mount(char *source, char *target, char *filesystemtype,
		unsigned long mountflags, void *data)
{
	struct umbinfmt *new = (struct umbinfmt *) malloc(sizeof(struct umbinfmt));
	assert(new);
	new->path = strdup(target);
	new->flags=(data && strcmp((char*)data,"debug")==0)?UMBINFMT_DEBUG:0;
	new->inuse=0;
	new->enabled=1;
	new->head=NULL;
	if (strcmp(source,"none")==0 || strcmp(source,"/")==0)
		new->binfmt_ht=ht_tab_add(CHECKBINFMT,NULL,0,&s,checkbinfmt,new);
	else
		new->binfmt_ht=ht_tab_add(CHECKBINFMT,source,strlen(source),&s,checkbinfmt,new);
	ht_tab_pathadd(CHECKPATH,source,target,filesystemtype,mountflags,data,&s,0,NULL,new);
	return 0;
}

static void umbinfmt_umount_internal(struct umbinfmt *fc, int flags)
{
	struct umbinfmt *fc_norace=fc;
	char *target=fc->path;
	if (fc_norace->flags & UMBINFMT_DEBUG) 
		printk("UMOUNT => path:%s flag:%d\n",target, flags);
	ht_tab_invalidate(fc->binfmt_ht);
	ht_tab_invalidate(um_mod_get_hte());
	delete_allreg(fc->head);
	free(fc_norace->path);
	free(fc_norace);
}

static long umbinfmt_umount2(char *target, int flags)
{
	struct umbinfmt *fc=um_mod_get_private_data();
	if (fc == NULL) {
		errno=EINVAL;
		return -1;
	} else if (fc->inuse > 0) {
		errno=EBUSY;
		return -1;
	} else {
		struct ht_elem *binfmt_ht=fc->binfmt_ht;
		umbinfmt_umount_internal(fc,flags);
		ht_tab_del(binfmt_ht);
		ht_tab_del(um_mod_get_hte());
		return 0;
	}
}

#if 0
#define TRUE 1
#define FALSE 0

static int alwaysfalse()
{
	return FALSE;
}
#endif

static char *unwrap(struct umbinfmt *fc,char *path)
{
	char *reduced=path+strlen(fc->path);
	if (*reduced == 0)
		return("/");
	else
		return(reduced);
}


static struct umregister *searchfile(char *path,struct umbinfmt *fc)
{
	char *unpath=unwrap(fc,path);
	if (strcmp(unpath,rootdir)==0)
		return (struct umregister *)rootdir;
	else if (strcmp(unpath+1,registerfile)==0)
		return (struct umregister *)registerfile;
	else if (strcmp(unpath+1,statusfile)==0)
		return (struct umregister *)statusfile;
	else {
		struct umregister *scan=fc->head;
		while (scan != NULL && strcmp(unpath+1,scan->name) != 0)
			scan=scan->next;
		return scan;
	}
}

#define SIZEOFPUREDIRENT (sizeof(struct umbinfmt_dirent64))
static char *add_dirent(char *start, char *name, char *base)
{
	struct umbinfmt_dirent64 *de=(struct umbinfmt_dirent64 *)start;
	de->d_ino=2;
	de->d_reclen=SIZEOFPUREDIRENT+strlen(name)+1;
	de->d_off=(start-base)+de->d_reclen;
	de->d_type=0;
	strcpy(de->d_name,name);
	return start+de->d_reclen;
}

static char *create_dirent(struct umbinfmt *fc, int *len)
{
	int totlen=0;
	struct umregister *scan=fc->head;
	char *contents,*scont;
	totlen+=SIZEOFPUREDIRENT+2; /* . */
	totlen+=SIZEOFPUREDIRENT+3; /* .. */
	totlen+=SIZEOFPUREDIRENT+7; /* status */
	totlen+=SIZEOFPUREDIRENT+9; /* register */
	while (scan != NULL) {
		totlen+=SIZEOFPUREDIRENT+strlen(scan->name)+1;
		scan=scan->next;
	}
	contents=scont=malloc(totlen);
	assert(contents);
	scont=add_dirent(scont,".",contents);
	scont=add_dirent(scont,"..",contents);
	scont=add_dirent(scont,"status",contents);
	scont=add_dirent(scont,"register",contents);
	scan=fc->head;
	while (scan != NULL) {
		scont=add_dirent(scont,scan->name,contents);
		scan=scan->next;
	}
	*len=totlen;
	return contents;
}

#define dec2hex(X) (((X)<10)?(X)+'0':(X)+'a'-10)
static char *hexstring(char *src,char *hex,int len)
{
	register int i;
	for (i=0;i<len;i++) {
		hex[2*i]=dec2hex(src[i] >> 4);
		hex[2*i+1]=dec2hex(src[i] & 0xf);
	}
	hex[2*i]=0;
	return hex;
}

static char *createcontents(int fd,struct umbinfmt *fc,int *len)
{
	struct binfileinfo *ft=getfiletab(fd);
	struct umregister *reg=ft->reg;
	assert (reg);
	if (UBM_IS_ROOT(reg)) {
		return create_dirent(fc,len);
	}
	else if (UBM_IS_STATUS(reg)) {
		char *rv;
		if (fc->enabled) 
			rv= strdup("enabled");
		else
			rv= strdup("disabled");
		*len=strlen(rv);
		return rv;
	} else {
		char *rv;
		char magic[257];
		char mask[257];
		asprintf(&rv,"%sabled\n"
				"interpreter %s\n"
				"flags: %s\n"
				"offset %d\n"
				"magic %s\n"
				"mask %s\n",
				(reg->enabled)?"en":"dis",
				reg->interpreter,
				reg->flags,
				reg->offset,
				hexstring(reg->magic,magic,reg->len),
				hexstring(reg->mask,mask,reg->len));
		*len=strlen(rv);
		return rv;
	}
}

static long umbinfmt_open(char *path, int flags, mode_t mode)
{
	struct umbinfmt *fc = um_mod_get_private_data();
	int fd;
	int rv;
	assert(fc!=NULL);
	struct umregister *file=searchfile(path,fc);
	if (file == NULL) 
		rv=-ENOENT;
	else if ((UBM_IS_REGISTER(file) && (flags & O_WRONLY)== 0) ||
			(flags & O_RDWR) ||
			(UBM_IS_ROOT(file) && !(flags & O_DIRECTORY) && (flags & O_WRONLY)))
		rv=-EINVAL;
	else {
		fd = addfiletab(sizeof(struct binfileinfo));
		struct binfileinfo *ft=getfiletab(fd);
		assert(fd>=0);

#ifdef __UMBINFMT_DEBUG__
		PRINTDEBUG(10,"FLAGOPEN path:%s \nFLAGS:0x%x MODE:%d\n",path,flags,mode);

		if(flags &  O_CREAT)
			PRINTDEBUG(10, "O_CREAT\n");
		if(flags & O_TRUNC)
			PRINTDEBUG(10, "O_TRUNC\n");
		if(flags &  O_RDONLY)
			PRINTDEBUG(10, "O_RDONLY:\n");
		if(flags &  O_APPEND)
			PRINTDEBUG(10, "O_APPEND\n");
		if(flags &  O_WRONLY)
			PRINTDEBUG(10, "O_WRONLY\n");
		if(flags &  O_RDWR)
			PRINTDEBUG(10, "O_RDWR\n");
		if(flags &  O_ASYNC)
			PRINTDEBUG(10, "O_ASYNC\n");
		if(flags &  O_DIRECT)
			PRINTDEBUG(10, "O_DIRECT\n");
		if(flags &  O_DIRECTORY)
			PRINTDEBUG(10, "O_DIRECTORY\n");
		if(flags &  O_EXCL)
			PRINTDEBUG(10, "O_EXCL\n");
		if(flags &  O_LARGEFILE)
			PRINTDEBUG(10, "O_LARGEFILE\n");
		if(flags &  O_DIRECT)
			PRINTDEBUG(10, "O_NOATIME\n");
		if(flags &  O_DIRECTORY)
			PRINTDEBUG(10, "O_NOCTTY\n");
		if(flags &  O_EXCL)
			PRINTDEBUG(10, "O_NOCTTY\n");
		if(flags &  O_NOFOLLOW)
			PRINTDEBUG(10, "O_NOFOLLOW\n");
		if(flags &  (O_NONBLOCK | O_NDELAY))
			PRINTDEBUG(10, "O_NONBLOCK o O_NDELAY\n");
		if(flags &  O_SYNC)
			PRINTDEBUG(10, "SYNC\n");
#endif
		ft->reg = file;
		ft->bfmount = fc;
		ft->flags = flags & ~(O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC);
		ft->pos = 0;
		if (!(flags & O_WRONLY)) {
			ft->contents = createcontents(fd,fc,&(ft->len));
		} else {
			ft->len = 0;
			ft->contents = NULL;
		}
		fc->inuse++;
		rv=0;
	}

	if (rv < 0)
	{
		if (fc->flags & UMBINFMT_DEBUG) 
			printk("OPEN[%d] ERROR => path:%s flags:0x%x\n", fd, path, flags);	
		errno = -rv;
		return -1;
	} else {
		if (fc->flags & UMBINFMT_DEBUG) 
			printk("OPEN[%d] => path:%s flags:0x%x\n", fd, path, flags);
		return fd;
	}
}



static long umbinfmt_close(int fd)
{
	int rv;
	struct binfileinfo *ft=getfiletab(fd);

	if (ft->bfmount->flags & UMBINFMT_DEBUG) 
		printk("CLOSE[%d]\n",fd);
	if (ft->contents != NULL)
		free(ft->contents);
	ft->bfmount->inuse--;
	if (UBM_IS_STATUS(ft->reg)) {
		if (ft->bfmount->enabled == 0xff)
			ft->bfmount->head=delete_allreg(ft->bfmount->head);
	} else {
		if (ft->reg->enabled == 0xff)
			ft->bfmount->head=delete_reg(ft->bfmount->head,ft->reg);
	}
	delfiletab(fd);
	return 0;
}

static int count_dents64(void *buf, int count, int max) {
	struct umbinfmt_dirent64 *d64=(struct umbinfmt_dirent64 *)buf;
	if (count == 0 || count < d64->d_reclen || max == 0)
		return 0;
	else {
		void *next=(void *)(((char *)buf) + d64->d_reclen);
		return count_dents64(next,count - d64->d_reclen,max - d64->d_reclen) + d64->d_reclen;
	}
}

static long umbinfmt_getdents64(int fd, void *buf, size_t count){
	int rv;
	struct binfileinfo *ft=getfiletab(fd);
	if (! UBM_IS_ROOT(ft->reg)) {
		errno=ENOTDIR;
		return -1;
	}
	else {
		char *tail=(ft->contents)+ft->pos;
		int rv=count_dents64(tail,count,ft->len-ft->pos);
		memcpy(buf,(ft->contents)+ft->pos,rv);
		if (rv<0) {
			errno= -rv;
			return -1;
		} else {
			ft->pos += rv;
			return rv;
		}
	}
}

static long umbinfmt_read(int fd, void *buf, size_t count)
{
	int rv;
	struct binfileinfo *ft=getfiletab(fd);
	if (UBM_IS_ROOT(ft->reg)) {
		errno=EISDIR;
		return -1;
	}
	else {
		rv = count;
		if (rv > ft->len - ft->pos)
			rv= ft->len - ft->pos;
		strncpy(buf,(ft->contents)+ft->pos,rv);
		if (rv<0) {
			errno= -rv;
			return -1;
		} else {
			ft->pos += rv;
			return rv;
		}
	}
}

static char *toknext(char *str,char sep)
{
	while(*str && *str != sep && *str != '\n')
		str++;
	if (*str) 
		*(str++)=0;
	return str;
}

#define F_NAME 0
#define F_TYPE 1
#define F_OFFSET 2
#define F_MAGIC 3
#define F_MASK 4
#define F_INTERPRETER 5
#define F_FLAGS 6

static char *dechex(char *src,unsigned char *len)
{
	char buf[128];
	char *rv;
	int i;
	if (*len > 0)
		for (i=0;i < *len;i++)
			buf[i]=0xff;
	i=0;
	while (*src != 0 && i<128) {
		if(src[0] == '\\' && src[1] == 'x' && src[2] != 0 && src[3] != 0) {
			unsigned int v;
			src +=2;
			sscanf(src,"%2x",&v);
			buf[i++]=v;
			src+=2;
		} else {
			buf[i++]=*src;
			src++;
		}
	}
	buf[i];
	if (*len == 0)
		*len=i;
	else
		buf[*len]=0;
	rv=malloc(*len);
	assert(rv);
	memcpy(rv,buf,*len);
	return rv;
}

static void ubm_register(struct umbinfmt *fc,char *buf, size_t count)
{
	char regstr[256];
	if (count > 0 && buf) {
		char sep=*buf;;
		char *scan=regstr;
		char *fields[7];
		int i;
		if (count > 255) count=255;
		strncpy(regstr,buf+1,count-1);
		regstr[count-1]=0;
		for (i=0;i<7;i++) {
			fields[i]=scan;
			scan=toknext(scan,sep);
		}
		if (fields[F_NAME][0] != 0 && fields[F_MAGIC][0] != 0 && fields[F_INTERPRETER][0] != 0 &&
				(fields[F_TYPE][0] == 'M' || fields[F_TYPE][0] == 'E')) {
			struct umregister *new=malloc(sizeof (struct umregister));
			new->name=strdup(fields[F_NAME]);
			new->enabled=1;
			new->flags=strdup(fields[F_FLAGS]);
			new->type=fields[F_TYPE][0];
			new->offset=(atoi(fields[F_OFFSET]));
			new->interpreter=strdup(fields[F_INTERPRETER]);
			new->len=0;
			new->magic=dechex(fields[F_MAGIC],&(new->len));
			new->mask=dechex(fields[F_MASK],&(new->len));
			new->next=fc->head;
			fc->head=new;
		}
	}
}

static long umbinfmt_write(int fd, void *buf, size_t count)
{
	int rv=count;
	struct binfileinfo *ft=getfiletab(fd);
	char *cbuf=buf;

	if (UBM_IS_REGISTER(ft->reg)) {
		if (ft->pos == 0)
			ubm_register(ft->bfmount,buf,count);
	} 
	else if (UBM_IS_STATUS(ft->reg)) {
		if (count >= 1) { 
			if (*cbuf=='1')
				ft->bfmount->enabled = 1;
			else if (*cbuf=='0')
				ft->bfmount->enabled = 0;
			if (count >= 2 && cbuf[0]=='-' && cbuf[1]=='1')
				ft->bfmount->enabled = 0xff;
		}
	} else {
		if (count >= 1) { 
			if (*cbuf=='1')
				ft->reg->enabled = 1;
			else if (*cbuf=='0')
				ft->reg->enabled = 0;
			if (count >= 2 && cbuf[0]=='-' && cbuf[1]=='1')
				ft->reg->enabled = 0xff;
		}
	}
	if (rv<0) {
		errno= -rv;
		return -1;
	} else {
		ft->pos += rv;
		return rv;
	}
}

static int common_stat64(struct umbinfmt *fc,struct umregister *reg, struct stat64 *buf64)
{
	int rv;
	if (reg == NULL) {
		errno=ENOENT;
		return -1;
	}
	memset(buf64, 0, sizeof(struct stat64));
	buf64->st_nlink=1;
	if (UBM_IS_ROOT(reg)) 
		buf64->st_mode=S_IFDIR | 0755;
	else if (UBM_IS_REGISTER(reg))
		buf64->st_mode=S_IFREG | 0200;
	else if (UBM_IS_STATUS(reg))
		buf64->st_mode=S_IFREG | 0644;
	else 
		buf64->st_mode=S_IFREG | 0644;
	rv=0;
	if (fc->flags & UMBINFMT_DEBUG) 
		printk("stat->GETATTR => status: %s\n",
				rv ? "Error" : "Success");
	return rv;
}

static long umbinfmt_stat64(char *path, struct stat64 *buf64)
{
	struct umbinfmt *umbinfmt=um_mod_get_private_data();
	struct umregister *reg=searchfile(path,umbinfmt);
	return common_stat64(umbinfmt,reg,buf64);
}

static long umbinfmt_lstat64(char *path, struct stat64 *buf64)
{
	return umbinfmt_stat64(path,buf64);
}

static long umbinfmt_access(char *path, int mode)
{
	struct umbinfmt *fc=um_mod_get_private_data();
	struct umregister *reg=searchfile(path,fc);
	int rv;
	assert(fc!=NULL);
	if (fc->flags & UMBINFMT_DEBUG) 
		printk("ACCESS => path:%s mode:%s%s%s%s\n", 
				path,
				(mode & R_OK) ? "R_OK": "",
				(mode & W_OK) ? "W_OK": "",
				(mode & X_OK) ? "X_OK": "",
				(mode & F_OK) ? "F_OK": "");


	if (UBM_IS_ROOT(reg))
		rv= !(mode & W_OK); /* it is forbidden to create new file by hand*/
	else if (UBM_IS_REGISTER(reg))
		rv=(!(mode & R_OK) && !(mode & X_OK)); /* only WRITE on register */
	else
		rv=(!(mode & X_OK));

	if (rv)
		return 0;
	else {
		errno=EACCES;
		return -1;
	}
#if 0
	if (UBM_IS_ROOT(reg))
		return(!(mode & W_OK));
	else if (UBM_IS_REGISTER(reg))
		return(!(mode & R_OK) && !(mode & X_OK));
	else
		return(!(mode & X_OK));
#endif
}

static loff_t umbinfmt_x_lseek(int fd, off_t offset, int whence)
{
	struct binfileinfo *ft=getfiletab(fd);
	switch (whence) {
		case SEEK_SET:
			ft->pos=offset;
			break;
		case SEEK_CUR:
			ft->pos+=offset;
			break;
		case SEEK_END:
			ft->pos=ft->len+offset;
			break;
	}
	if (ft->pos<0) ft->pos=0;
	if (ft->pos > ft->len) ft->pos=ft->len;
	return ft->pos;
}

static long umbinfmt_lseek(int fd, int offset, int whence)
{
	return umbinfmt_x_lseek(fd, offset, whence);
}

static long umbinfmt__llseek(unsigned int fd, unsigned long offset_high,  unsigned  long offset_low, loff_t *result, unsigned int whence)
{
	PRINTDEBUG(10,"umbinfmt__llseek %d %d %d %d\n",fd,offset_high,offset_low,whence);
	if (result == NULL) {
		errno = EFAULT;
		return -1;
	} else {
		loff_t rv;
		loff_t offset=((loff_t)offset_high)<<32 | offset_low;
		rv=umbinfmt_x_lseek(fd,offset,whence);
		if (rv >= 0) {
			*result=rv;
			return 0;
		} else {
			errno = -rv;
			return -1;
		}
	}
}

static void contextclose(struct umbinfmt *fc)
{
	umbinfmt_umount2(fc->path,MNT_FORCE);
}

static long umbinfmt_event_subscribe(void (* cb)(), void *arg, int fd, int how)
{
	return 1;
}

#if 0
static epoch_t umbinfmt_check(int type, void *arg)
{
	if (type == CHECKBINMFT) {
		struct binfmt_req *req=arg;
		if (strcmp(req->path,"/tmp/f1/bin/ls")==0 ||
				strcmp(req->path,"/tmp/ls")==0) {
			req->interp="/usr/local/bin/qemu-i386";
			return get_epoch()-1;
		} else
			return 0;
	}
	else 
		return 0;
}
#endif

static long umbinfmt_fcntl64()
{
	return 0;
}

static void umbinfmt_destructor(int type,struct ht_elem *mp)
{
	switch (type) {
		case CHECKPATH:
			um_mod_set_hte(mp);
			umbinfmt_umount_internal(um_mod_get_private_data(), MNT_FORCE);
	}
}

	static void
	__attribute__ ((constructor))
init (void)
{
	printf("umbinfmt init\n");
	s.name="umbinfmt";
	s.description="virtual binfmt_misc";
	s.destructor=umbinfmt_destructor;
	s.syscall=(sysfun *)calloc(scmap_scmapsize,sizeof(sysfun));
	s.socket=(sysfun *)calloc(scmap_sockmapsize,sizeof(sysfun));
	SERVICESYSCALL(s, mount, umbinfmt_mount);
	SERVICESYSCALL(s, umount2, umbinfmt_umount2);
	SERVICESYSCALL(s, open, umbinfmt_open);
	SERVICESYSCALL(s, read, umbinfmt_read);
	SERVICESYSCALL(s, write, umbinfmt_write);
	SERVICESYSCALL(s, close, umbinfmt_close);
#if !defined(__x86_64__)
	SERVICESYSCALL(s, stat64, umbinfmt_stat64);
	SERVICESYSCALL(s, lstat64, umbinfmt_lstat64);
#else
	SERVICESYSCALL(s, stat, umbinfmt_stat64);
	SERVICESYSCALL(s, lstat, umbinfmt_lstat64);
#endif
	SERVICESYSCALL(s, access, umbinfmt_access);
	SERVICESYSCALL(s, lseek, umbinfmt_lseek);
#if ! defined(__x86_64__)
	SERVICESYSCALL(s, _llseek, umbinfmt__llseek);
#endif
	SERVICESYSCALL(s, getdents64, umbinfmt_getdents64);
	SERVICESYSCALL(s, fcntl64, umbinfmt_fcntl64);
	//SERVICESYSCALL(s, chown, umbinfmt_chown);
	//SERVICESYSCALL(s, fchown, fchown);
	//SERVICESYSCALL(s, chmod, umbinfmt_chmod);
	//SERVICESYSCALL(s, fchmod, fchmod);
	//SERVICESYSCALL(s, fsync, umbinfmt_fsync); 
	//SERVICESYSCALL(s, _newselect, umbinfmt_select);
	//SERVICESYSCALL(s, ioctl, umbinfmt_ioctl); 
	s.event_subscribe=umbinfmt_event_subscribe;
	service_ht=ht_tab_add(CHECKFSTYPE,"umbinfmt",0,&s,NULL,NULL);
}

	static void
	__attribute__ ((destructor))
fini (void)
{
	ht_tab_del(service_ht);
	free(s.syscall);
	free(s.socket);
	printf("umbinfmt fini\n");
}

