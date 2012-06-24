/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   fuse/umfuse module for iso9660 filesystem support
 *   
 *   Copyright 2005,2006,2007 Renzo Davoli University of Bologna - Italy
 *   
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License
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


#if 0
#ifdef linux
/* For pread()/pwrite() */
#define _XOPEN_SOURCE 500
#endif
#endif

#include <config.h>
#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <zlib.h>
#include <dirent.h>
#include <libgen.h>
#include <errno.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <cdio/iso9660.h>
#include <cdio/logging.h>
#include "zisofs.h"
#include <v2fuseutils.h>

#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

#define BRUTECACHETEST
#ifdef BRUTECACHETEST

#define BRUTECACHESIZE 128
#include <time.h>
struct brutecache {
	iso9660_t *isofs;
	char *path;
	struct stat *stat;
	time_t time;
} brutecache[BRUTECACHESIZE];

static void brutecache_add(iso9660_t *isofs,const char *path,struct stat *stat)
{
	int i,newi;
	time_t min,now;
	now=min=time(NULL);
	for (newi=i=0;i<BRUTECACHESIZE;i++) {
		if (brutecache[i].path == NULL)
			break;
		if (brutecache[i].time < min) {
			min=brutecache[i].time;
			newi=i;
		}
	}
	if (i < BRUTECACHESIZE) newi=i;
	if (brutecache[newi].path != NULL)
		free(brutecache[newi].path);
	brutecache[newi].path=strdup(path);
	brutecache[newi].isofs=isofs;
	if (stat==NULL) {
		if (brutecache[newi].stat != NULL) {
			free(brutecache[newi].stat);
			brutecache[newi].stat=NULL;
		}
	} else {
		if (brutecache[newi].stat == NULL)
			brutecache[newi].stat = malloc(sizeof(struct stat));
		*(brutecache[newi].stat) = *stat;
	}
	brutecache[newi].time=now;
}

static int brutecache_search(iso9660_t *isofs,const char *path,struct stat *stat)
{
	int i;
	for (i=0;i<BRUTECACHESIZE;i++) {
		if (brutecache[i].isofs == isofs &&
				strcmp(brutecache[i].path,path)==0) {
			brutecache[i].time=time(NULL);
			if (brutecache[i].stat != NULL) {
				*stat=*(brutecache[i].stat);
				return 0;
			} else
				return -ENOENT;
		}
	}
	return EAGAIN; /*positive, go on searching */
}

static void brutecache_rmiso(iso9660_t *isofs)
{
	int i;
	for (i=0;i<BRUTECACHESIZE;i++) {
		if (brutecache[i].isofs == isofs) {
			if (brutecache[i].path != NULL) {
				free(brutecache[i].path);
				brutecache[i].path=NULL;
			}
			if (brutecache[i].stat != NULL) {
				free(brutecache[i].stat);
				brutecache[i].stat=NULL;
			}
		}
	}
}
#endif

static int f_iso9660_readlink(const char *path, char *buf, size_t size)
{
	struct fuse_context *mycontext=fuse_get_context();
	iso9660_t *isofs=(iso9660_t *) mycontext->private_data;

	iso9660_stat_t *isostat;
	isostat= iso9660_ifs_stat(isofs,path);

	if (isostat->rr.b3_rock == yep &&
			S_ISLNK(isostat->rr.st_mode)) {
		
		if (isostat->rr.i_symlink < size) {
			size=isostat->rr.i_symlink;
			strncpy(buf,isostat->rr.psz_symlink,size);
			buf[size]='\0';
		} else
			strncpy(buf,isostat->rr.psz_symlink,size);
		 
		free(isostat);
		return 0;
	} else {
		free(isostat);
    return -EINVAL;
	}
}

static int f_iso9660_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		                       off_t offset, struct fuse_file_info *fi)
{
	struct fuse_context *mycontext=fuse_get_context();
	iso9660_t *isofs=(iso9660_t *) mycontext->private_data;

	//printf("f_iso9660_readdir %s\n",path);
	iso9660_stat_t *isostat=
		//iso9660_ifs_stat_translate(isofs,path);
		iso9660_ifs_stat(isofs,path);
	//printf("f_iso9660_getdir %s stat done\n",path);
	if (isostat ==NULL)
		return -ENOENT;
	else {
		CdioList *entlist;
		CdioListNode *entnode;

	//printf("f_iso9660_readdir %s\n",path);
		entlist = iso9660_ifs_readdir (isofs, path);
	//printf("f_iso9660_readdir %s done\n",path);

		if (entlist != NULL) {

			_CDIO_LIST_FOREACH (entnode, entlist)
			{
				char filename[4096];
				int type;
				iso9660_stat_t *p_statbuf = _cdio_list_node_data (entnode);
	//printf("f_iso9660_translate %s %s\n",p_statbuf->filename,p_statbuf->rr.psz_symlink);
				//iso9660_name_translate(p_statbuf->filename, filename);
				//iso9660_name_translate_ext(p_statbuf->filename, filename, iso9660_ifs_get_joliet_level(isofs));
				strcpy(filename,p_statbuf->filename);
	//printf("f_iso9660_translate %s done\n",path);
				//printf ("/%s\n", filename);
				switch (p_statbuf->type) {
					case _STAT_FILE: type=DT_REG;break;
					case _STAT_DIR:  type=DT_DIR;break;
				}
				struct stat st;
				memset(&st, 0, sizeof(st));
				st.st_ino=2;
				st.st_mode=type<<12;
				//printf("filler %s %d\n",filename,type);
				if (filler(buf, filename, &st, 0))
					break;
			}

			_cdio_list_free (entlist, true);
		}

	}
	free(isostat);
	return 0;
}

/*************** COMPRESSED ISO (ZISO) DEFS ***************/
static const unsigned char zisofs_magic[8] = {
	  0x37, 0xE4, 0x53, 0x96, 0xC9, 0xDB, 0xD6, 0x07
};

static unsigned int get_731(void *pnt)
{
	  unsigned char *p = (unsigned char *)pnt;
		  return ((unsigned int)p[0]) + ((unsigned int)p[1] << 8) +
				    ((unsigned int)p[2] << 16) + ((unsigned int)p[3] << 24);
}
/***************************************************************/

struct iso9660fileinfo {
	iso9660_stat_t *stat;
	unsigned long fullsize;
	unsigned char block_shift;
	unsigned char *pointer_block;
};

static int f_iso9660_intread(iso9660_t *isofs,iso9660_stat_t *isostat,char *buf, size_t size, off_t offset)
{
	off_t firstblock=offset/ISO_BLOCKSIZE;
	off_t lastblock;
	//printf("INTREAD %ld %lld\n",size,offset);
	int readrv=1;
	off_t bytesread=0;
	if (offset+size > isostat->size)
		size= isostat->size - offset;
	lastblock=(offset+size)/ISO_BLOCKSIZE;
	char cdbuf[ISO_BLOCKSIZE];
	memset (cdbuf, 0, ISO_BLOCKSIZE);
	offset -= firstblock*ISO_BLOCKSIZE;
	while (size > 0 && readrv > 0) {
		//printf("f_iso9660_read seek/read \n");
		readrv=iso9660_iso_seek_read(isofs, cdbuf, 
				isostat->lsn+firstblock,1);
		//printf("f_iso9660_read seek/read done %lld %lld %lld\n",firstblock,offset,isostat->lsn+firstblock);
		if (readrv>0) {
			off_t len=(ISO_BLOCKSIZE-offset < size)?ISO_BLOCKSIZE-offset:size;
			memcpy(buf,cdbuf+offset,len);
			offset=0;
			size-=len;
			buf+=len;
			bytesread+=len;
			firstblock++;
		}
	} 
	return bytesread;
}

static mode_t convertmode(mode_t nonxamode,uint16_t xaattr)
{
	mode_t rv=0;
	nonxamode &= 0777;
	rv |= (xaattr & 0x5000) >> 12; /* others */
	rv |= (xaattr & 0x500) >> 5; /* group */
	rv |= (xaattr & 0x50) << 2 ; /* user */
	if (xaattr & XA_ATTR_DIRECTORY)
		rv |= __S_IFDIR;
	else
		rv |= __S_IFDIR;
	//printf(" MODE CONV %x %o\n",xaattr,rv);
	return rv;
}

#if ( FUSE_MINOR_VERSION >= 5 )
static int f_iso9660_statfs(const char *path, struct statvfs *stbuf)
{
    int res;

		struct fuse_context *mycontext=fuse_get_context();
		iso9660_t *isofs=(iso9660_t *) mycontext->private_data;
		static iso9660_pvd_t pvd;

		/* XXX pvd seems to contain trash in the MS part if its fields */
		if (iso9660_ifs_read_pvd (isofs, &pvd)) {
			memset(stbuf, 0, sizeof(struct statvfs));
			stbuf->f_bsize=pvd.logical_block_size & 0xffff;
			stbuf->f_frsize=stbuf->f_bsize;
			stbuf->f_blocks=pvd.volume_space_size & 0xffffffff;
			/*fprintf(stderr,"STATFS! %p %ld %lx %lld %llx\n",isofs,
					pvd.logical_block_size, pvd.logical_block_size,
					pvd.volume_space_size, pvd.volume_space_size);*/
			return 0;
		} else 
			return -EINVAL;
}
#endif

static int f_iso9660_getattr(const char *path, struct stat *stbuf)
{
	struct fuse_context *mycontext=fuse_get_context();
	iso9660_t *isofs=(iso9660_t *) mycontext->private_data;
#ifdef BRUTECACHETEST
	{
		int rv=brutecache_search(isofs,path,stbuf);
		if (rv <= 0)
			return rv;
	}
#endif

	//printf("f_iso9660_getattr %p %s\n",isofs,path);
	iso9660_stat_t *isostat=
		//iso9660_ifs_stat_translate(isofs,path);
		iso9660_ifs_stat(isofs,path);
	if (isostat ==NULL) {
#ifdef BRUTECACHETEST
		brutecache_add(isofs,path,NULL);
#endif
		return -ENOENT;
	} else {
		memset (stbuf,0,sizeof(struct stat));
		/* XXX workaround
		 * should be unique and != existing devices */
		stbuf->st_dev=(dev_t) ((long)isofs);
		switch (isostat->type) {
			case _STAT_FILE: 
				stbuf->st_mode=__S_IFREG|0555;break;
			case _STAT_DIR: 
				stbuf->st_mode=__S_IFDIR|0555;break;
		}
		stbuf->st_nlink=1;
		stbuf->st_uid=0;
		stbuf->st_gid=0;
		stbuf->st_rdev=0;
		stbuf->st_size=isostat->size;
		stbuf->st_ino=isostat->lsn;
		//fprintf(stderr,"%s-> lsn %d xa?%d rr?%d\n",path,isostat->lsn,iso9660_ifs_is_xa(isofs),isostat->rr.b3_rock == yep);
		if (isostat->rr.b3_rock == yep) {
			stbuf->st_mode=isostat->rr.st_mode;
			stbuf->st_nlink=isostat->rr.st_nlinks;
			stbuf->st_uid=isostat->rr.st_uid;
			stbuf->st_gid=isostat->rr.st_gid;
			if (isostat->rr.i_symlink > 0) {
				stbuf->st_size=isostat->rr.i_symlink;
			}
		} else
		/* XA permission management already untested */
		if (iso9660_ifs_is_xa(isofs)) {
			stbuf->st_uid=isostat->xa.user_id;
			stbuf->st_gid=isostat->xa.group_id;
			stbuf->st_ino=isostat->xa.filenum;
			stbuf->st_mode=convertmode(stbuf->st_mode,isostat->xa.attributes);
		}
		/* check it is a reg file? */
		if (isostat->size >= sizeof(struct compressed_file_header)) { /* file shorted than the header cannot be compressed */
			struct compressed_file_header hdr;
			int rv;
			rv=f_iso9660_intread(isofs,isostat,(char *)&hdr,sizeof(hdr),0);
			if (rv == sizeof(hdr)) {
				if (memcmp(hdr.magic,zisofs_magic,sizeof(zisofs_magic))==0) 
					stbuf->st_size=get_731(hdr.uncompressed_len);
			}
		}
		stbuf->st_blksize=ISO_BLOCKSIZE;
		stbuf->st_blocks=isostat->secsize;
		stbuf->st_atime= stbuf->st_mtime= stbuf->st_ctime=mktime(&isostat->tm);
	 //char filename[4096];
		//iso9660_name_translate(isostat->filename, filename);
		//iso9660_name_translate_ext(isostat->filename, filename, iso9660_ifs_get_joliet_level(isofs));
		//strcpy(filename,isostat->filename);
		//printf("f_iso9660_getattr OKAY %s\n",filename);
#ifdef BRUTECACHETEST
		brutecache_add(isofs,path,stbuf);
#endif
		free(isostat);
		return 0;
	}
}

static int f_iso9660_open(const char *path, struct fuse_file_info *fi)
{
	struct fuse_context *mycontext=fuse_get_context();
	iso9660_t *isofs=(iso9660_t *) mycontext->private_data;

	iso9660_stat_t *isostat=
		iso9660_ifs_stat(isofs,path);
	//printf("f_iso9660_open %s stat done\n",path);
	fi->fh=(unsigned long)NULL;
	if (isostat ==NULL)
		return -ENOENT;
	else	 {
		struct iso9660fileinfo *fh9660=malloc(sizeof (struct iso9660fileinfo));
		if (fh9660==NULL)
			return -ENOMEM;
		fh9660->stat=isostat;
		fh9660->pointer_block=NULL;
		fh9660->fullsize=isostat->size;
		fh9660->block_shift=0;
		fi->fh = (unsigned long) fh9660;
		if (fh9660->fullsize >= sizeof(struct compressed_file_header)) { /* file shorted than the header cannot be compressed */
			struct compressed_file_header hdr;
			int rv;
			rv=f_iso9660_intread(isofs,isostat,(char *)&hdr,sizeof(hdr),0);
			if (rv == sizeof(hdr)) {
				if (memcmp(hdr.magic,zisofs_magic,sizeof(zisofs_magic))==0) {
					unsigned nblocks;
					size_t tablesize;
					fh9660->fullsize=get_731(hdr.uncompressed_len);
					fh9660->block_shift=hdr.block_size;
					nblocks=(fh9660->fullsize+(1<<hdr.block_size)-1) >> hdr.block_size;
					tablesize=(nblocks+1) * 4;
					if ((fh9660->pointer_block=malloc(tablesize)) ==NULL)
					{
						free(fh9660);
						free(isostat);
						return -ENOMEM;
					}
					if (f_iso9660_intread(isofs,isostat,(char *)fh9660->pointer_block,tablesize,hdr.header_size<<2) != tablesize) {
						free(fh9660);
						free(isostat);
						return -EIO;
					}
				}
			}
		}
    return 0;
	}
}

static int f_iso9660_comprread(iso9660_t *isofs,struct iso9660fileinfo *fh9660,char *buf, size_t size, off_t offset)
{
	off_t firstblock=offset>>fh9660->block_shift;
	off_t lastblock;
	unsigned long readrv=1;
	off_t bytesread=0;
	if (offset+size > fh9660->fullsize)
		size= fh9660->fullsize - offset;
	lastblock=(offset+size)>>fh9660->block_shift;
	unsigned char *outbuf=malloc(1<<fh9660->block_shift);
	if (outbuf == NULL)
		return -ENOMEM;
	unsigned char *inbuf=malloc((1<<fh9660->block_shift)*2);
	if (inbuf == NULL) {
		free(outbuf);
		return -ENOMEM;
	}
	offset -= firstblock<<fh9660->block_shift;
	while (size > 0 && readrv > 0) {
		unsigned long cstart,cend,csize;
		cstart=get_731(fh9660->pointer_block+(4*firstblock));
		cend=get_731(fh9660->pointer_block+(4*(firstblock+1)));
    csize=cend-cstart;
		readrv=1<<fh9660->block_shift;
		if ((f_iso9660_intread(isofs,fh9660->stat,(char *)inbuf,csize,cstart) != csize) || 
				(uncompress(outbuf,&readrv,inbuf,csize) != Z_OK)) {
			free(inbuf);
			free(outbuf);
			return -EIO;
		}
		if (readrv>0) {
			off_t len=((1<<fh9660->block_shift)-offset < size)?(1<<fh9660->block_shift)-offset:size;
			memmove(buf,outbuf+offset,len);
			offset=0;
			size-=len;
			buf+=len;
			bytesread+=len;
			firstblock++;
		}
	} 
	free(inbuf);
	free(outbuf);
	return bytesread;
}

static int f_iso9660_read(const char *path, char *buf, size_t size, off_t offset,
                    struct fuse_file_info *fi)
{
	//printf("f_iso9660_read %s\n",path);
	struct fuse_context *mycontext=fuse_get_context();
	iso9660_t *isofs=(iso9660_t *) mycontext->private_data;

#if 0
	iso9660_stat_t *isostat=
		iso9660_ifs_stat(isofs,path);
	//printf("f_iso9660_read %s stat done\n",path);
	if (isostat ==NULL)
		return -ENOENT;
	else 
#endif
	{
		struct iso9660fileinfo *fh9660=(struct iso9660fileinfo *)((long)(fi->fh));
		if (fh9660 ==NULL)
			return -ENOENT;
		if (fh9660->pointer_block == NULL) /* UNCOMPRESSED ISO */
			return f_iso9660_intread(isofs,fh9660->stat,buf,size,offset);
		else
			return f_iso9660_comprread(isofs,fh9660,buf,size,offset);
	}
}

static int f_iso9660_release(const char *path, struct fuse_file_info *fi)
{
    struct iso9660fileinfo *fh9660=(struct iso9660fileinfo *)((long)(fi->fh));
		free(fh9660->stat);
		if (fh9660 != NULL) {
			if (fh9660->pointer_block != NULL)
				free(fh9660->pointer_block);
			free(fh9660);
		}
    return 0;
}

/* waiting for FUSE 2.6 */
#if ( FUSE_MINOR_VERSION <= 5 )
static void *init_data;

void *f_iso9660_init(void)
{
	return init_data;
}
#else
void *f_iso9660_init(struct fuse_conn_info *conn)
{
	struct fuse_context *mycontext;
	mycontext=fuse_get_context();
	//printf("INIT %p %p\n",mycontext,mycontext->private_data);
	return mycontext->private_data;
}
#endif

void f_iso9660_destroy(void *arg)
{
	iso9660_t *isofs=arg;
#ifdef BRUTECACHETEST
	brutecache_rmiso(isofs);
#endif
}

static struct fuse_operations iso9660_oper = {
    .getattr	= f_iso9660_getattr,
    .readlink	= f_iso9660_readlink,
#if ( FUSE_MINOR_VERSION >= 5 )
    .statfs	= f_iso9660_statfs,
#endif
    .readdir	= f_iso9660_readdir,
    .open	= f_iso9660_open,
    .read	= f_iso9660_read,
    .release	= f_iso9660_release,
    .init	= f_iso9660_init,
		.destroy = f_iso9660_destroy
};


struct fuse *fuse;
#if ( FUSE_MINOR_VERSION <= 5 )
int fuse_fd;
#else
struct fuse_chan *fuse_fd;
#endif

int main(int argc, char *argv[])
{
	int err;
	struct fuse_context *mycontext;
	iso9660_t *isofs;
	int i;

	if (argc < 3) 
		v2f_usage(argv[0],&iso9660_oper);
	v2f_rearrangeargv(argc,argv);
	//isofs=iso9660_open_ext(argv[argc-2],ISO_EXTENSION_ALL);
	
	isofs=iso9660_open_ext(argv[1],ISO_EXTENSION_ALL);
	if (!isofs)
		return -1;
	//printf("open %s %p\n",argv[argc-2],isofs);
	if (!iso9660_ifs_read_superblock(isofs,ISO_EXTENSION_ALL))
		return -1;
	cdio_loglevel_default=CDIO_LOG_ERROR;
	/* ADD -s: libiso9660 and our brute cache are not thread safe */
	for (i=0; i<argc-1; i++)
		argv[i]=argv[i+1];
	argv[i]="-s";
#if ( FUSE_MINOR_VERSION <= 5 )
		init_data=isofs;
		err=fuse_main(argc,argv,&iso9660_oper);
#else
		err=fuse_main(argc,argv,&iso9660_oper,isofs);
#endif

		iso9660_close(isofs);
		return err;
}
