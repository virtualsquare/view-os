/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   fuse/umfuse module for ext2 filesystems
 *   
 *   Copyright 2005 Renzo Davoli University of Bologna - Italy
 *   Modified 2005 Andrea Seraghiti
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

//TODO:
//symlink
//fsync!?
//extended attributes
//flush is correct?!
//writepage?!
//file (in functions open) is always writable, is correct?
//bug ls, sometimes there aren't all file and/or directory
//
#if 0
#ifdef linux
/* For pread()/pwrite() */
#define _XOPEN_SOURCE 500
#endif
#endif

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/statfs.h>
#include <ext2fs/ext2fs.h>
#include <ext2fs/ext2_io.h>


#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

//#define DEBUG

struct ext2_file {
	errcode_t		magic;
	ext2_filsys 		fs;
	ext2_ino_t		ino;
	struct ext2_inode	inode;
	int 			flags;
	__u64			pos;
	blk_t			blockno;
	blk_t			physblock;
	char 			*buf;
};

static int ext2_getattr(const char *path, struct stat *stbuf)
{
	ext2_ino_t ino_n;
	struct ext2_inode  ino;
	int err;

	ext2_filsys e2fs;
	struct fuse_context *mycontext = fuse_get_context();
	e2fs = (ext2_filsys) mycontext->private_data;

	#ifdef DEBUG
	printf("\text2_getattr:%s %p\n",path,e2fs);
	#endif

	err = ext2fs_namei(e2fs, EXT2_ROOT_INO, EXT2_ROOT_INO, path, &ino_n);
	#ifdef DEBUG
	printf("\t\text2_namei:%sERR:%d\n",path, err);
	#endif
	if(err != 0 || ino_n == 0)//change < to !=
		return -ENOENT;
	
	err = ext2fs_read_inode (e2fs, ino_n, &ino);
	#ifdef DEBUG
	printf("\t\text2_read_inodeERR:%d\n",err);
	#endif
	if(err < 0)
		return -ENOENT;

	stbuf->st_dev = (dev_t) e2fs;
	stbuf->st_ino = ino_n;
	stbuf->st_mode = ino.i_mode;
	stbuf->st_nlink = ino.i_links_count;
	stbuf->st_uid = ino.i_uid;
	stbuf->st_gid = ino.i_gid;
	stbuf->st_rdev = 0; /* TODO special files mgmt */
	stbuf->st_size = ino.i_size;
	stbuf->st_blksize = e2fs->blocksize;
	stbuf->st_blocks = ino.i_blocks;
	stbuf->st_atime = ino.i_atime;
	stbuf->st_mtime = ino.i_mtime;
	stbuf->st_ctime = ino.i_ctime;
	return 0;
}

//TODO error to symlink
static int ext2_readlink(const char *path, char *buf, size_t size)
{
	ext2_ino_t ino_n;
	struct ext2_inode  ino;
	int err;
	char *buffer = 0;
	char *pathname;

	ext2_filsys e2fs;
	struct fuse_context *mycontext=fuse_get_context();
	e2fs=(ext2_filsys) mycontext->private_data;

	#ifdef DEBUG
	printf("\text2_readlink:%s\n",path);
	#endif
	err = ext2fs_namei(e2fs, EXT2_ROOT_INO, EXT2_ROOT_INO, path, &ino_n);
	if(err < 0 || ino_n == 0)
		return -ENOENT;
	
	err = ext2fs_read_inode (e2fs, ino_n, &ino);
	if(err < 0)
		return -ENOENT;
	
	if (!LINUX_S_ISLNK(ino.i_mode))
		return -EINVAL;
	if ( ext2fs_inode_data_blocks(e2fs, &ino) ) {
		err = ext2fs_get_mem(e2fs->blocksize, &buffer);
		if (err)
			return err;
		err = io_channel_read_blk(e2fs->io, ino.i_block[0], 1, buffer);
		if (err) {
			ext2fs_free_mem(&buffer);
			return err;
		}
		pathname = buffer;
	} else
		pathname = (char *)&(ino.i_block[0]);
	size--;
	if (ino.i_size < size)
		size = ino.i_size;
	memcpy(buf,pathname,size);
	buf[size]=0;

	if (buffer)
		ext2fs_free_mem(&buffer);
	return 0;
}

struct dir_iter_data {
	fuse_dirh_t h; 
	fuse_dirfil_t filler;
};

struct dir_filliter_data {
	void *buf; 
	fuse_fill_dir_t filler;
};

static int ext2_readdir_iter(
		ext2_ino_t    dir,
		int   entry,
		struct ext2_dir_entry *dirent, int   offset,
		int   blocksize, char  *buf, void *vpsid)
{
	int res;
	unsigned char type;
	int len;
	struct dir_filliter_data *psid=(struct dir_filliter_data *)vpsid;
	struct stat st;
	memset(&st, 0, sizeof(st));

	len=dirent->name_len & 0xff;
	dirent->name[len]=0; // bug wraparound

	switch  (dirent->name_len >> 9) {
		case EXT2_FT_UNKNOWN:	type=DT_UNKNOWN;break;
		case EXT2_FT_REG_FILE:	type=DT_REG;break;
		case EXT2_FT_DIR:	type=DT_DIR;break;
		case EXT2_FT_CHRDEV:	type=DT_CHR;break;
		case EXT2_FT_BLKDEV:	type=DT_BLK;break;
		case EXT2_FT_FIFO:	type=DT_FIFO;break;
		case EXT2_FT_SOCK:	type=DT_SOCK;break;
		case EXT2_FT_SYMLINK:	type=DT_LNK;break;
		default: 		type=DT_UNKNOWN;break;
	} 
	st.st_ino=dirent->inode;
	st.st_mode=type<<12;
	res = psid->filler(psid->buf, dirent->name, &st, 0);
	return 0;
}

static int ext2_dir_iter(
		ext2_ino_t    dir,
		int   entry,
		struct ext2_dir_entry *dirent, int   offset,
		int   blocksize, char  *buf, void *vpsid)
{
	int res;
	unsigned char type;
	int len;
	struct dir_iter_data *psid=(struct dir_iter_data *)vpsid;
	len=dirent->name_len & 0xff;
	dirent->name[len]=0; // bug wraparound

	switch  (dirent->name_len >> 9) {
		case EXT2_FT_UNKNOWN:	type=DT_UNKNOWN;break;
		case EXT2_FT_REG_FILE:	type=DT_REG;break;
		case EXT2_FT_DIR:	type=DT_DIR;break;
		case EXT2_FT_CHRDEV:	type=DT_CHR;break;
		case EXT2_FT_BLKDEV:	type=DT_BLK;break;
		case EXT2_FT_FIFO:	type=DT_FIFO;break;
		case EXT2_FT_SOCK:	type=DT_SOCK;break;
		case EXT2_FT_SYMLINK:	type=DT_LNK;break;
		default: 		type=DT_UNKNOWN;break;
	} 
	res = psid->filler(psid->h, dirent->name, type, dirent->inode);
	return 0;
}

static int ext2_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		                           off_t offset, struct fuse_file_info *fi)
{
	ext2_ino_t ino_n;
	ext2_file_t e2file;
	int err;
	struct dir_filliter_data sid;
	sid.buf=buf;
	sid.filler=filler;

	ext2_filsys e2fs;
	struct fuse_context *mycontext=fuse_get_context();
	e2fs=(ext2_filsys) mycontext->private_data;

	err=ext2fs_namei_follow(e2fs, EXT2_ROOT_INO, EXT2_ROOT_INO, path, &ino_n);
#ifdef DEBUG
	printf("\text2_getdir\n\text2_namei_followERR:%d\n",err);
#endif
	if(err < 0 || ino_n == 0)
		return -ENOENT;
	err=ext2fs_file_open(e2fs, ino_n, 0, &e2file);
	if(err < 0)
		return -ENOENT;
	err=ext2fs_dir_iterate2(e2fs,ino_n, 0, NULL, ext2_readdir_iter, &sid);
	if(err < 0)
		return -ENOENT;
	return 0;
}

static int ext2_getdir(const char *path, fuse_dirh_t h, fuse_dirfil_t filler)
{
    ext2_ino_t ino_n;
    ext2_file_t e2file;
    int err;
    struct dir_iter_data sid;
    sid.h=h;
    sid.filler=filler;

    ext2_filsys e2fs;
    struct fuse_context *mycontext=fuse_get_context();
    e2fs=(ext2_filsys) mycontext->private_data;

    err=ext2fs_namei_follow(e2fs, EXT2_ROOT_INO, EXT2_ROOT_INO, path, &ino_n);
	#ifdef DEBUG
	printf("\text2_getdir\n\text2_namei_followERR:%d\n",err);
	#endif
    if(err < 0 || ino_n == 0)
        return -ENOENT;
    err=ext2fs_file_open(e2fs, ino_n, 0, &e2file);
    if(err < 0)
        return -ENOENT;
    err=ext2fs_dir_iterate2(e2fs,ino_n, 0, NULL, ext2_dir_iter, &sid);
    if(err < 0)
        return -ENOENT;
    return 0;
}

static int ext2_open(const char *path, struct fuse_file_info *fi)
{
	//TODO check permission,Open should check if the operation is permitted for the given flags.
	//open must only check if the operations is permittes except the flags:
	//O_CREAT, O_EXCL, O_TRUNC
	ext2_ino_t ino_n = 0;
	ext2_file_t e2file;
	int err;

	ext2_filsys e2fs;
	struct fuse_context *mycontext = fuse_get_context();
	e2fs = (ext2_filsys) mycontext->private_data;

	#ifdef DEBUG
	printf("\text2_open:%s\n",path);
	printf("\t\tflag:%d\n",fi->flags);
	#endif
	err = ext2fs_namei_follow(e2fs, EXT2_ROOT_INO, EXT2_ROOT_INO, path, &ino_n);
	#ifdef DEBUG
	printf("\t\text2_namei_followERR:%d\n",err);
	#endif
	if(err < 0 || ino_n == 0)
		return -ENOENT;
	//err=ext2fs_file_open(e2fs, ino_n,  0, &e2file);
	err = ext2fs_file_open(e2fs, ino_n, EXT2_FILE_WRITE, &e2file);
	#ifdef DEBUG
	printf("\t\text2_file_openERR:%d\n",err);
	#endif
	if(err < 0)
		return -ENOENT;

	fi->fh = (long) e2file;
	return 0;
}

//create a file
static int ext2_mknod(const char *path, mode_t mode, dev_t dev)
{
	char	*cp;
	ext2_ino_t	parent, newfile;
	struct ext2_inode inode;
	int retval;
	char *name;
	char *path_parent;
	ext2_filsys e2fs;
	
	struct fuse_context *mycontext = fuse_get_context();
	e2fs = (ext2_filsys) mycontext->private_data;
	/*check if the file exist, but I do it in high level?!
	retval = ext2fs_namei(current_fs, EXT2_ROOT_INO, EXT2_ROOT_INO, path, &newfile);
	if (retval == 0) {
		fprintf(stderr, "The file '%s' already exists\n", path);
		return 1;
	}*/
	path_parent = strdup(path);
	#ifdef DEBUG
	printf("\text2_mknod:%s\n",path);
	#endif
	retval = ext2fs_new_inode(e2fs, EXT2_ROOT_INO, 010755, 0, &newfile);
	if (retval) {
		#ifdef DEBUG
		fprintf(stderr, "Error to allocate inode:%d\n",retval);
		#endif
		return -retval;
	}
	#ifdef DEBUG
	printf("\t\tAllocated inode: %u\n", newfile);
	#endif
	
	cp = strrchr(path_parent, '/');
	*cp = 0;
	if (strlen(path_parent) == 0)
		path_parent = "/";
	cp++;//cp point to file name
	/*name = strdup(cp); // XXX ERR: this DUP has no FREE!!!*/
	name = cp;
	retval = ext2fs_namei(e2fs, EXT2_ROOT_INO, EXT2_ROOT_INO, path_parent, &parent);
	#ifdef DEBUG
	printf("\t\tName of file to create:%s\n",name);
	printf("\t\tName of parent:%s\n",path_parent);
	#endif
make_link:
	retval = ext2fs_link(e2fs, parent, name, newfile, EXT2_FT_REG_FILE);

	if (retval == EXT2_ET_DIR_NO_SPACE) {
		printf("EXT2_ET_DIR_NO_SPACE\n");
		retval = ext2fs_expand_dir(e2fs, parent);
		if (retval) {
			fprintf(stderr, "while expanding directory\n");
			return retval;
		}
		//retval = ext2fs_link(e2fs, 2, name, newfile, EXT2_FT_REG_FILE);
		goto make_link;
	}
        if (ext2fs_test_inode_bitmap(e2fs->inode_map, newfile))
		fprintf(stderr, "Warning: inode already set\n");
			
	ext2fs_inode_alloc_stats2(e2fs, newfile, +1, 0);
	memset(&inode, 0, sizeof(inode));
	inode.i_mode = mode;
	inode.i_atime = inode.i_ctime = inode.i_mtime = time(NULL);
	inode.i_links_count = 1;
	inode.i_size = 0; //initial size of file
	
	retval = ext2fs_write_new_inode(e2fs, newfile, &inode);
	if (retval) {
		fprintf(stderr, "Error while creating inode %u\n", newfile);
		return retval;
	}
	return 0;
}


static int ext2_read(const char *path, char *buf, size_t size, off_t offset,
                    struct fuse_file_info *fi)
{
	ext2_file_t e2file;
	int err;
	unsigned int newpos;
	unsigned int got;

	ext2_filsys e2fs;
	struct fuse_context *mycontext=fuse_get_context();
	e2fs=(ext2_filsys) mycontext->private_data;

	e2file=(ext2_file_t)(fi->fh);
    	#ifdef DEBUG
	printf("\text2_read-file read:%lu\n", fi->fh);
	#endif
	err = ext2fs_file_lseek(e2file, offset, SEEK_SET, &newpos);
	if(err < 0)
		return -ENOENT;
	err = ext2fs_file_read(e2file, buf, size, &got);
	if(err < 0)
		return -ENOENT;
	//ext2fs_file_close(e2file);
	return got;
}

static int ext2_write(const char *path, const char *buf, size_t size, off_t offset,
                    struct fuse_file_info *fi)
{
	ext2_file_t e2file;
	ext2_off_t file_size;
	unsigned int newpos;
	unsigned int got = 0;
	int retval = 0;
	char *buftmp = buf;

	ext2_filsys e2fs;
	struct fuse_context *mycontext=fuse_get_context();
	e2fs=(ext2_filsys) mycontext->private_data;
	#ifdef DEBUG
	printf("\text2_write\n");
	printf("\t\tfiletab:%d\n",fi->fh);
	#endif
	e2file = (ext2_file_t)(fi->fh);
	#ifdef DEBUG
	printf("\t\tfileflag:%d\n",e2file->flags);
	#endif
	
	//adjust the file size
	file_size = ext2fs_file_get_size(e2file);
	#ifdef DEBUG
	printf("\t\tFileSize:%d\n",file_size);
	if ((offset+size) > file_size)
		printf("ext2fs_file_set_size %lld %d  %d\n", offset,size,(offset + size) );
	#endif
	if ((offset+size) > file_size)
		retval = ext2fs_file_set_size(e2file, (offset + size) );
	#ifdef DEBUG
	printf("\t\tSize:%dErr:%d\n",offset+size, retval);
	#endif

	ext2_off_t newoffset = (ext2_off_t) offset;
	retval = ext2fs_file_lseek(e2file, offset, SEEK_SET, &newpos);
	#ifdef DEBUG
	printf("\t\toffset%d-newpos:%d\n", offset, newpos);	
	printf("\t\text2_file_lseekErr:%d\n",retval);
	#endif
	if(retval < 0)
		return -ENOENT;
	got = newpos;
	#ifdef DEBUG
	printf("\t\tbuf%d-size:%d-got:%d\n",buf,size,got);
	printf("\t\tstampa:%s-blocksize%dEND\n",buf,e2fs->blocksize);
	#endif
	retval = 0;
	while ((size > 0) && (!retval)) {
		retval = ext2fs_file_write(e2file, buftmp, size, &got);
		size -= got;
		buftmp += got;
	#ifdef DEBUG
	printf("\t\tCycle:%d\n",size);
	#endif
		}	
	#ifdef DEBUG
	printf("\t\tbuf%d-size:%d-got:%d\n",buf,size,got);
	printf("\t\text2_file_writeERR:%d\n",retval);
	#endif
	if(retval < 0)
		return -ENOENT;
	retval = ext2fs_file_flush(e2file);
	#ifdef DEBUG
	printf("\t\tFLUSHintoWrite:%d\n",retval);
	#endif
	return got;
}

/*
 * This routine is used whenever a command needs to turn a string into
 * an inode.
 */
/*ext2_ino_t string_to_inode(char *str)
{
	ext2_ino_t	ino;
	int		len = strlen(str);
	char		*end;
	int		retval;

    ext2_filsys e2fs;
    struct fuse_context *mycontext=fuse_get_context();
    e2fs=(ext2_filsys) mycontext->private_data;

    if ((len > 2) && (str[0] == '<') && (str[len-1] == '>')) {
printf("COSI\n");
		ino = strtoul(str+1, &end, 0);
		if (*end=='>')
			return ino;
	}

	retval = ext2fs_namei(e2fs, EXT2_ROOT_INO, EXT2_ROOT_INO, str, &ino);
	printf("stringtoinoderr:%d\n",retval);
	if (retval) {
		//com_err(str, retval, "");
		return 0;
	}
	return ino;
}*/

static int ext2_mkdir(const char *path, mode_t mode)
{
	int err;
	ext2_ino_t parent;// = NULL;
	char	*name;
	char	*cp;
	char *path_parent = strdup(path);

	ext2_filsys e2fs;
	struct fuse_context *mycontext=fuse_get_context();
	e2fs = (ext2_filsys) mycontext->private_data;
	#ifdef DEBUG
	printf("\text2_mkdir:%s\n",path_parent);
	#endif
	
 	cp = strrchr(path_parent, '/');//point to last /
	if (cp) { 
		name = strdup(cp+1);
		*cp = 0;
		if(!strlen(path_parent))
			strcat(path_parent, "/");
		err = ext2fs_namei(e2fs, EXT2_ROOT_INO, EXT2_ROOT_INO, path_parent, &parent);
		if (!parent) {
			#ifdef DEBUG
			printf("Parent Inode not found\n");
			#endif
			return -ENOENT;
		}

	} else {//if there isn't parent
		#ifdef DEBUG
		printf("path without /\n");
		#endif
		return -ENOENT;
	}
try_again:
	#ifdef DEBUG
	printf("\t\tInode_Parent:%dpath%sname:%sinodebitmap%d\n",
			parent,path_parent,name,e2fs->inode_map);
	#endif
	err = ext2fs_mkdir(e2fs, parent, 0, name);
	#ifdef DEBUG
	printf("\t\tMkdirError:%d\n",err);
	#endif
	if (err == EXT2_ET_DIR_NO_SPACE) {
		#ifdef DEBUG
		fprintf(stderr, "Expand dir space\n");
		#endif
		err = ext2fs_expand_dir(e2fs, path_parent);
		if (err) {
			fprintf(stderr, "Error while expanding directory\n");
			return -ENOENT;
		}
		goto try_again;
	}
	if (err) {
		fprintf(stderr, "Mkdir error:%d\n",err);
		return -ENOENT;
	}
	return 0;
}
struct rd_struct {
	ext2_ino_t	parent;
	int		empty;
};

static int rmdir_proc(ext2_ino_t dir EXT2FS_ATTR((unused)),
		      int	entry EXT2FS_ATTR((unused)),
		      struct ext2_dir_entry *dirent,
		      int	offset EXT2FS_ATTR((unused)),
		      int	blocksize EXT2FS_ATTR((unused)),
		      char	*buf EXT2FS_ATTR((unused)),
		      void	*private)
{
	struct rd_struct *rds = (struct rd_struct *) private;

	if (dirent->inode == 0)
		return 0;
	if (((dirent->name_len&0xFF) == 1) && (dirent->name[0] == '.'))
		return 0;
	if (((dirent->name_len&0xFF) == 2) && (dirent->name[0] == '.') &&
	    (dirent->name[1] == '.')) {
		rds->parent = dirent->inode;
		return 0;
	}
	rds->empty = 0;
	return 0;
}

static int unlink_file_by_name(char *filename)
{
	int		retval;
	ext2_ino_t	dir;
	char		*basename;
	
	ext2_filsys e2fs;
	struct fuse_context *mycontext=fuse_get_context();
	e2fs = (ext2_filsys) mycontext->private_data;

	basename = strrchr(filename, '/');
	if (basename) {
		*basename++ = '\0';
		retval = ext2fs_namei(e2fs, EXT2_ROOT_INO, EXT2_ROOT_INO, filename, &dir);
		if (!dir)
			return;
	} else {
		dir = 2;//cwd;
		basename = filename;
	}
	retval = ext2fs_unlink(e2fs, dir, basename, 0, 0);
	if (retval)
		printf("unlink_file_by_name:%d\n", retval);
	return retval;
}

static int release_blocks_proc(ext2_filsys fs, blk_t *blocknr,
			       int blockcnt EXT2FS_ATTR((unused)), 
			       void *private EXT2FS_ATTR((unused)))
{
	blk_t	block;

	block = *blocknr;
	ext2fs_block_alloc_stats(fs, block, -1);
	return 0;
}

static int kill_file_by_inode(ext2_ino_t inode)
{
	struct ext2_inode inode_buf;
	int retval;
	
	ext2_filsys e2fs;
	struct fuse_context *mycontext=fuse_get_context();
	e2fs = (ext2_filsys) mycontext->private_data;

	retval = ext2fs_read_inode(e2fs, inode, &inode_buf);
	if(retval)
		return retval;
	inode_buf.i_dtime = time(NULL);
	
	retval = ext2fs_write_inode(e2fs, inode, &inode_buf);
	if(retval)
		return retval;

	if (!ext2fs_inode_has_valid_blocks(&inode_buf))
		return 1;

	ext2fs_block_iterate(e2fs, inode, 0, NULL,
			     release_blocks_proc, NULL);
	ext2fs_inode_alloc_stats2(e2fs, inode, -1,
				  LINUX_S_ISDIR(inode_buf.i_mode));
	return 0;
}

static int ext2_rmdir(const char *path)
{

	int retval;
	ext2_ino_t inode_num;
	struct ext2_inode inode;
	struct rd_struct rds;

	ext2_filsys e2fs;
	struct fuse_context *mycontext=fuse_get_context();
	e2fs = (ext2_filsys) mycontext->private_data;

	retval = ext2fs_namei(e2fs, EXT2_ROOT_INO, EXT2_ROOT_INO, path, &inode_num);
	#ifdef DEBUG
	printf("\text2_rmdir\n\t\tpath:%s\n\t\tnameiErr:%d\n",path, retval);
	#endif
	if (retval) {
		fprintf(stderr, "while trying to resolve filename");
		return -ENOENT;
	}
	
	retval = ext2fs_read_inode(e2fs, inode_num, &inode);
	printf("\t\text2fs_read_inodeERR:%d\n",retval);

	if (!LINUX_S_ISDIR(inode.i_mode)) {
		printf("ERROR,file is not a directory\n");
		return -ENOTDIR;
	}

	rds.parent = 0;
	rds.empty = 1;

	retval = ext2fs_dir_iterate2(e2fs, inode_num, 0, 0, rmdir_proc, &rds);
	if (retval) {
		printf("while iterating over directory\n");
		return -ENOENT;
	}
	#ifdef DEBUG
	printf("\t\text2fs_dir_iterateERR:%d\n",retval);
	#endif

	if (rds.empty == 0) {
		printf("directory not empty\n");
		return -ENOTEMPTY;
	}

	inode.i_links_count = 0;
	retval = ext2fs_write_inode(e2fs, inode_num, &inode);
	#ifdef DEBUG
	printf("\t\text2fs_write_inodeERR:%d\n",retval);
	#endif
		
	if (retval) {
		printf("while writing inode %u", inode_num);
		return 1;
	}
	unlink_file_by_name(path);
	kill_file_by_inode(inode_num);
	if (rds.parent) {
		if ( retval = ext2fs_read_inode(e2fs, rds.parent, &inode) )
			return retval;
		if (inode.i_links_count > 1)
			inode.i_links_count--;
		if ( retval = ext2fs_write_inode(e2fs, rds.parent, &inode) )
			return retval;
	}
	return 0;	
}
/*
 * Given a mode, return the ext2 file type
 */
static int ext2_file_type(unsigned int mode)
{
	if (LINUX_S_ISREG(mode))
		return EXT2_FT_REG_FILE;

	if (LINUX_S_ISDIR(mode))
		return EXT2_FT_DIR;
	
	if (LINUX_S_ISCHR(mode))
		return EXT2_FT_CHRDEV;
	
	if (LINUX_S_ISBLK(mode))
		return EXT2_FT_BLKDEV;
	
	if (LINUX_S_ISLNK(mode))
		return EXT2_FT_SYMLINK;

	if (LINUX_S_ISFIFO(mode))
		return EXT2_FT_FIFO;
	
	if (LINUX_S_ISSOCK(mode))
		return EXT2_FT_SOCK;
	
	return 0;
}

static int ext2_symlink(const char *sourcename, const char *destname)
{
	ext2_ino_t	ino;
	struct ext2_inode inode;
	int		retval;
	ext2_ino_t	dir;
	char		*dest, *cp, *basename;


	ext2_filsys e2fs;
	struct fuse_context *mycontext=fuse_get_context();
	e2fs = (ext2_filsys) mycontext->private_data;

	#ifdef DEBUG
	printf("\text2_symlink\n");
	#endif
	/* Figure out the destination.  First see if it exists and is
	 * a directory. */
	if (! (retval=ext2fs_namei(e2fs, EXT2_ROOT_INO, EXT2_ROOT_INO, destname, &dir)))
		dest = basename;
	else {
		/* OK, it doesn't exist.  See if it is '<dir>/basename' or 'basename' */
		cp = strrchr(destname, '/');
		if (cp) {
			*cp = 0;
			retval = ext2fs_namei(e2fs, EXT2_ROOT_INO, EXT2_ROOT_INO, destname, &dir);
			if (retval != 0 || dir == 0)
				return -ENOENT;
			dest = cp+1;
		} else {
			dir = 2; // XXX err cwd;
			dest = destname;
		}
	}

	//retval = ext2fs_link(e2fs, dir, dest, ino, ext2_file_type(inode.i_mode));
	#ifdef DEBUG
	fprintf(stderr, "\t\text2fs_link error:%d\n",retval);
	#endif
	return 0;
}


static int ext2_link(const char *sourcename, const char *destname)
{
	ext2_ino_t	ino;
	struct ext2_inode inode;
	int		retval;
	ext2_ino_t	dir;
	char		*dest, *cp, *basename;


	ext2_filsys e2fs;
	struct fuse_context *mycontext=fuse_get_context();
	e2fs = (ext2_filsys) mycontext->private_data;

	#ifdef DEBUG
	printf("\text2_link %s %s\n",sourcename,destname);
	#endif
	/*Get the source inode*/
	retval = ext2fs_namei(e2fs, EXT2_ROOT_INO, EXT2_ROOT_INO, sourcename, &ino);
	if (retval != 0 || ino == 0)
		return -ENOENT; //inode with this name does not exist
	basename = strrchr(sourcename, '/');
	if (basename)
		basename++;
	else
		basename = sourcename;
	/* Figure out the destination.  First see if it exists and is
	 * a directory. */
	if (! (retval=ext2fs_namei(e2fs, EXT2_ROOT_INO, EXT2_ROOT_INO, destname, &dir)))
		dest = basename;
	else {
		/* OK, it doesn't exist.  See if it is '<dir>/basename' or 'basename' */
		cp = strrchr(destname, '/');
		if (cp) {
			*cp = 0;
			retval = ext2fs_namei(e2fs, EXT2_ROOT_INO, EXT2_ROOT_INO, destname, &dir);
			if (retval != 0 || dir == 0)
				return -ENOENT;
			dest = cp+1;
		} else {
			dir = 2;// XXX ERR cwd;
			dest = destname;
		}
	}
	retval = ext2fs_read_inode(e2fs, ino, &inode);
	if (retval) {
		fprintf(stderr, "while reading inode %u", ino);
		return 1;
	}
	retval = ext2fs_link(e2fs, dir, dest, ino, ext2_file_type(inode.i_mode));
	if (retval == 0) {
		inode.i_links_count ++;
		retval =  ext2fs_write_inode(e2fs, ino, &inode);
	}
	
	#ifdef DEBUG
	fprintf(stderr, "\t\text2fs_link error:%d\n",retval);
	#endif
	return 0;
}


static int ext2_unlink(const char *path)
{
	int retval;
	ext2_ino_t inode_num;
	struct ext2_inode inode;

	ext2_filsys e2fs;
	struct fuse_context *mycontext=fuse_get_context();
	e2fs = (ext2_filsys) mycontext->private_data;

	retval = ext2fs_namei(e2fs, EXT2_ROOT_INO, EXT2_ROOT_INO, path, &inode_num);
	if (retval) {
		printf("while trying to resolve filename");
		return -ENOENT;
	}
	
	retval = ext2fs_read_inode(e2fs, inode_num, &inode);
	if (retval) {
		printf("while reading inode %u", inode_num);
		return 1;
	}

	if (LINUX_S_ISDIR(inode.i_mode)) {
		fprintf(stderr, "file is a directory");
		return -EISDIR;
	}

	--inode.i_links_count;
	retval = ext2fs_write_inode(e2fs, inode_num, &inode);
	if (retval) {
		fprintf(stderr, "while writing inode %u", inode_num);
		return -EIO;
	}

	unlink_file_by_name(path);
	if (inode.i_links_count == 0)
		kill_file_by_inode(inode_num);

	return 0;
}

static int ext2_chmod(const char *path, mode_t mode)
{
	ext2_ino_t ino_n;
	struct ext2_inode  ino;
	int err;

	ext2_filsys e2fs;
	struct fuse_context *mycontext = fuse_get_context();
	e2fs = (ext2_filsys) mycontext->private_data;

	#ifdef DEBUG
	printf("\text2_chmod:%s\n",path);
	#endif

	err = ext2fs_namei(e2fs, EXT2_ROOT_INO, EXT2_ROOT_INO, path, &ino_n);
	#ifdef DEBUG
	printf("\t\text2_namei:%sERR:%d\n",path, err);
	#endif
	if(err != 0 || ino_n == 0)//change < to !=
		return -ENOENT;
	
	err = ext2fs_read_inode (e2fs, ino_n, &ino);
	#ifdef DEBUG
	printf("\t\text2_read_inodeERR:%d\n",err);
	#endif
	if(err < 0)
		return -ENOENT;
	
	ino.i_mode = mode;
	err = ext2fs_write_inode(e2fs, ino_n, &ino);
	if (err) {
		fprintf(stderr, "Error while writing inode %u\n", ino_n);
		return err;
	}
	return 0;
}

static int ext2_chown(const char *path, uid_t owner, gid_t group)
{
	ext2_ino_t ino_n;
	struct ext2_inode  ino;
	int err;

	ext2_filsys e2fs;
	struct fuse_context *mycontext = fuse_get_context();
	e2fs = (ext2_filsys) mycontext->private_data;

	#ifdef DEBUG
	printf("\text2_chown:%s\n",path);
	#endif

	err = ext2fs_namei(e2fs, EXT2_ROOT_INO, EXT2_ROOT_INO, path, &ino_n);
	#ifdef DEBUG
	printf("\t\text2_namei:%sERR:%d\n",path, err);
	#endif
	if(err != 0 || ino_n == 0)//change < to !=
		return -ENOENT;
	
	err = ext2fs_read_inode (e2fs, ino_n, &ino);
	#ifdef DEBUG
	printf("\t\text2_read_inodeERR:%d\n",err);
	#endif
	if(err < 0)
		return -ENOENT;
	
	ino.i_uid = owner;
	ino.i_gid = group;
	err = ext2fs_write_inode(e2fs, ino_n, &ino);
	if (err) {
		fprintf(stderr, "Error while writing inode %u\n", ino_n);
		return err;
	}
	return 0;
}

static int ext2_truncate(const char *path, int length)
{
	ext2_ino_t ino_n;
	struct ext2_inode  ino;
	int err;

	ext2_filsys e2fs;
	struct fuse_context *mycontext = fuse_get_context();
	e2fs = (ext2_filsys) mycontext->private_data;

	#ifdef DEBUG
	printf("\text2_truncate:%s\n",path);
	#endif
	err = ext2fs_namei(e2fs, EXT2_ROOT_INO, EXT2_ROOT_INO, path, &ino_n);
	#ifdef DEBUG
	printf("\t\text2_namei:%sERR:%d\n",path, err);
	#endif
	if(err != 0 || ino_n == 0)//change < to !=
		return -ENOENT;
	
	err = ext2fs_read_inode (e2fs, ino_n, &ino);
	#ifdef DEBUG
	printf("\t\text2_read_inodeERR:%d\n",err);
	#endif
	if(err < 0)
		return -ENOENT;
	
	ino.i_size = length; //size of file
	//TODO free the old space(I must change bitmap?)
	err = ext2fs_write_inode(e2fs, ino_n, &ino);
	if (err) {
		fprintf(stderr, "Error while writing inode %u\n", ino_n);
		return err;
	}
	return 0;
}

static int ext2_rename(const char *oldpath, const char *newpath)
{
	printf("TODO RENAME\n");
	return 0;
}

static int ext2_utime(const char *path, const struct utimbuf *buf)
{
	ext2_ino_t ino_n;
	struct ext2_inode  ino;
	int err;

	ext2_filsys e2fs;
	struct fuse_context *mycontext = fuse_get_context();
	e2fs = (ext2_filsys) mycontext->private_data;

	#ifdef DEBUG
	printf("\text2_utime:%s\n",path);
	#endif

	err = ext2fs_namei(e2fs, EXT2_ROOT_INO, EXT2_ROOT_INO, path, &ino_n);
	#ifdef DEBUG
	printf("\t\text2_namei:%sERR:%d\n",path, err);
	#endif
	if(err != 0 || ino_n == 0)//change < to !=
		return -ENOENT;
	
	err = ext2fs_read_inode (e2fs, ino_n, &ino);
	#ifdef DEBUG
	printf("\t\text2_read_inodeERR:%d\n",err);
	#endif
	if(err < 0)
		return -ENOENT;
	
	ino.i_atime = buf->actime;
	ino.i_mtime = buf->modtime;
	err = ext2fs_write_inode(e2fs, ino_n, &ino);
	if (err) {
		fprintf(stderr, "Error while writing inode %u\n", ino_n);
		return err;
	}
	return 0;
}

static int ext2_statfs(const char *path, struct statfs *buf)
{
		printf("TODO STATFS\n");
	return 0;
}

static int ext2_flush(const char *path, struct fuse_file_info *fi)
{
#ifdef DEBUG	
	printf("\text2_flush,file;%lu\n",fi->fh);
#endif

	ext2_file_t e2file;
	ext2_filsys e2fs;
	struct fuse_context *mycontext=fuse_get_context();
	e2fs = (ext2_filsys) mycontext->private_data;
	#ifdef DEBUG
	printf("\text2_flush\n");
	#endif

//	if ((e2file->flags & EXT2_FILE_BUF_VALID) || (e2file->flags & EXT2_FILE_BUF_DIRTY))
//		printf("Ce roba da flusciare!!!!!!!!!!!!!!!\n");
	#ifdef DEBUG
	printf("\t\tfiletab:%d\n",fi->fh);
	#endif
	e2file = (ext2_file_t)(fi->fh);
	#ifdef DEBUG
	printf("\t\tfileflag:%d\n",e2file->flags);
	#endif
	int retval = ext2fs_file_flush(e2file);
	#ifdef DEBUG
	printf("\t\tFLUSH:%d\n",retval);
	#endif
	return 0;
}

static int ext2_release(const char *path, struct fuse_file_info *fi)
{
	ext2_file_t e2file;
	int err;

	e2file = (ext2_file_t)(fi->fh);
	#ifdef DEBUG
	fprintf(stderr, "\text2_Release,file:%lu\n",fi->fh);
	#endif

	#ifdef DEBUG
	if ((e2file->flags & EXT2_FILE_BUF_VALID) || (e2file->flags & EXT2_FILE_BUF_DIRTY))
		printf("La roba gli aRRIVA!!!!!!!!!!!!!!!!!\n");
	#endif
	err = ext2fs_file_close(e2file);
	#ifdef DEBUG
	printf("\t\tCLOSE ERRORE:%d\n",err);
	#endif
	return 0;
}

/* temporary solution waiting for FUSE 2.6 */
#if ( FUSE_MINOR_VERSION <= 5 )
static void *init_data;

void *ext2_init(void)
{
	return init_data;
}
#else
void *ext2_init(void)
{ 
	  struct fuse_context *mycontext;
		mycontext=fuse_get_context();
		return mycontext->private_data;
} 
#endif


static struct fuse_operations ext2_oper = {
	.init	= ext2_init,
	.getattr	= ext2_getattr,
	.readlink	= ext2_readlink,
	.readdir	= ext2_readdir,
	.mknod		= ext2_mknod,
	.mkdir		= ext2_mkdir,
	.rmdir		= ext2_rmdir,
	.open		= ext2_open,
	.read		= ext2_read,
	.write		= ext2_write, 
	.release	= ext2_release,
	.unlink		= ext2_unlink,
	.link		= ext2_link,
	.symlink	= ext2_symlink,
	.rename		= ext2_rename,
	.truncate	= ext2_truncate,
	.flush		 = ext2_flush,
	.chmod		= ext2_chmod,
	.chown		= ext2_chown,
	.utime		= ext2_utime,
	//.statfs		= ext2_statfs,
/*
ok    .getattr	= ext2_getattr,
ok    .readlink	= ext2_readlink,
ok    .getdir	= ext2_getdir,
ok    .mknod	= ext2_mknod,
ok    .mkdir	= ext2_mkdir,
process    .symlink	= ext2_symlink,
ok    .unlink	= ext2_unlink,
ok    .rmdir	= ext2_rmdir,
process    .rename	= ext2_rename,
process    .link	= ext2_link,
process    .chmod	= ext2_chmod,
process    .chown	= ext2_chown,
process     .truncate	= ext2_truncate,
prcess    .utime	= ext2_utime,
ok    .open	= ext2_open,
ok    .read	= ext2_read,
proces    .write	= ext2_write,
process    .statfs	= ext2_statfs,
ok    .release	= ext2_release,
    .fsync	= ext2_fsync,
    */
#if 0
#ifdef HAVE_SETXATTR
    .setxattr	= ext2_setxattr,
    .getxattr	= ext2_getxattr,
    .listxattr	= ext2_listxattr,
    .removexattr= ext2_removexattr,
#endif
#endif
};


static int close_filesystem(ext2_filsys current_fs)
{
	int	retval;
	
	if (current_fs->flags & EXT2_FLAG_IB_DIRTY) {
		retval = ext2fs_write_inode_bitmap(current_fs);
		if (retval)
			fprintf(stderr, "ext2fs_write_inode_bitmap_error:%d", retval);
	}
	if (current_fs->flags & EXT2_FLAG_BB_DIRTY) {
		retval = ext2fs_write_block_bitmap(current_fs);
		if (retval)
			fprintf(stderr, "ext2fs_write_block_bitmap_error:%d", retval);
	}
	retval = ext2fs_close(current_fs);
	if (retval)
		fprintf(stderr, "ext2fs_close_error:%d", retval);
	current_fs = NULL;
	return 0;
}

struct fuse *fuse;
int fuse_fd;

int main(int argc, char *argv[])
{
	int err, i, retval;
	io_channel data_io = 0;
	struct fuse_context *mycontext;
	ext2_filsys e2fs;
	//argv[0]=nome file system
#ifdef DEBUG
	printf("argc:%d\n",argc);
	for(i=0;i<argc;i++)
		printf("Argv[%d]:%s\n",i,argv[i]);
#endif
	if (argc < 3) {
		return -ENODEV;
	}
	char *source = strdup(argv[argc-2]);//2 1 image.ext2
	char *mountpoint = strdup(argv[argc-1]);//1 2 mountpoint
	
	//if (strcmp(argv[1],"-o")==0)
	//	argv+=2;
	//	

	

/*	initialize_ext2_error_table();
	fprintf (stderr, "debugfs %s (data)\n", E2FSPROGS_VERSION, E2FSPROGS_DATE);
*/
	//TODO:EXT2_FLAG_RW is static.but I can open e image in read only mode!
	err = ext2fs_open (source, EXT2_FLAG_RW, 0, 0, unix_io_manager, &e2fs);
//#ifdef DEBUG
	if(err) {
		printf("Open_ext2 Error:%d\n",err);
		return -ENODEV; //TODO:change umfuse if a filesystem report an error
	}
//#endif

	err = ext2fs_read_inode_bitmap(e2fs);
#ifdef DEBUG
	printf("read_inode_bitmaPerr%d\n",err);
#endif

	err = ext2fs_read_block_bitmap(e2fs);
#ifdef DEBUG
	printf("read_block_bitmaPerr%d\n",err);
	//printf("blocksize:%d\n",e2fs->blocksize);

	if(e2fs->flags & EXT2_FLAG_RW)
		printf("FileSistem Read&Write\n");
	else
		printf("FileSistem ReadOnly\n");
#endif

	if (data_io) {
#ifdef DEBUG
		printf("data_io Setting...\n");
#endif
		retval = ext2fs_set_data_io(e2fs, data_io);
		if (retval) {
			fprintf(stderr,"ERROR:while setting data source:%d\n",retval);
			//goto errout;
		}
	}

	fuse_fd = fuse_mount(mountpoint, "rw");//vuole il  mountpoint, attenzione rw e' dummy, e' ignorato da umfuse ma non libfuse!!
#ifdef DEBUG
printf("fuse-fd%d\n",fuse_fd);
#endif
#if ( FUSE_MINOR_VERSION <= 5 )
	fuse = fuse_new(fuse_fd, NULL, &ext2_oper, sizeof(ext2_oper));
	init_data=e2fs;
#else
	fuse = fuse_new(fuse_fd, NULL, &ext2_oper, sizeof(ext2_oper), e2fs);
#endif

//fuse_main(argc, argv, &ext2_oper);
#ifdef DEBUG
	printf("vaiInLoop\n");
#endif
	fuse_loop(fuse);
	//fuse_loop_mt(fuse);

	ext2fs_flush(e2fs);
	//ext2fs_free(e2fs);
	close_filesystem(e2fs);
	//ext2fs_close(e2fs);
	return 0;
}
