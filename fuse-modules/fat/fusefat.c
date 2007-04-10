/*
    FUSEFAT: fat32 filesystem implementation for FUSE
	
	FUSEFAT: Copyright (C) 2006-2007  Paolo Angelelli <angelell@cs.unibo.it>	
	FUSE:    Copyright (C) 2001-2006  Miklos Szeredi <miklos@szeredi.hu>
	
    This program can be distributed under the terms of the GNU GPL.
*/

#define FUSE_USE_VERSION 26

#include "libfat.h"
#include <fuse.h>

#define fusefat_getvolume(V)     struct fuse_context *mycontext = fuse_get_context(); V = (Volume_t *) mycontext->private_data;
	

static int fusefat_getattr(const char *path, struct stat *stbuf) {
    int res;
	File_t F;
	Volume_t *V;
	fusefat_getvolume(V);
	fat_lock(V);
	if ((res = fat_open(path, &F, V, O_RDONLY)) != 0) { fat_unlock(V); fprintf(stderr,"-- %d",__LINE__); return -ENOENT; }
	if ((res = fat_stat(&F, stbuf)) != 0) { fat_unlock(V); fprintf(stderr,"-- %d",__LINE__);return -1; }
	fat_unlock(V);
	fprintf(stderr,"getattr(%s)\n",path);
    return 0;
}

static int fusefat_open(const char *path, struct fuse_file_info *fi) {
    int res;
	File_t *F;
	Volume_t *V;
	fusefat_getvolume(V);
	F = malloc(sizeof(File_t));
	fat_lock(V);
	if ((res = fat_open(path, F, V, O_RDWR)) != 0) { fat_unlock(V); fprintf(stderr,"-- %d",__LINE__); free(F); return -ENOENT; }
	fat_unlock(V);
	fi->fh = (off64_t) F;
	fprintf(stderr,"open(%s)\n",path);
    return 0;
}

static int fusefat_access(const char *path, int mask) {
	return 0;
//    return fusefat_open(path, NULL);
}

static int fusefat_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi) {
    struct dirent de;
    (void) offset;
    (void) fi;	
    int res;
	File_t F;
	Volume_t *V;
	fusefat_getvolume(V);
	fprintf(stderr,"readdir(%s)\n",path);
	fat_lock(V);
    if ((res =  fat_open(path, &F, V, O_RDONLY)) != 0) { fat_unlock(V); fprintf(stderr,"-- %d",__LINE__); return -ENOENT; }

    while ((res = fat_readdir(&F, &de)) == 0) {
        struct stat st;
        memset(&st, 0, sizeof(st));
        st.st_ino = de.d_ino;
		if (de.d_type == DT_DIR) { 
			st.st_mode = S_IFDIR;
		} else st.st_mode = S_IFREG;


//		st.st_mode = de.d_type << 12;
		
        if (filler(buf, de.d_name, &st, 0))
            break;
    }
	fat_unlock(V);
    return 0;
}

static int fusefat_release(const char *path, struct fuse_file_info *fi)
{
    /* Just a stub.  This method is optional and can safely be left
       unimplemented */

//    (void) path;
//    (void) fi;
	free((File_t *) fi->fh);
    return 0;
}


static int fusefat_mknod(const char *path, mode_t mode, dev_t rdev) {
    int res;
	char dirname[4096];
    char filename[1024];
	File_t Parent;
	Volume_t *V;
	fusefat_getvolume(V);
/*    if (!(S_ISREG(mode))) {
		return -1;
	} */

	fat_dirname(path, dirname);
    fat_filename(path, filename);
	fat_lock(V);
	fprintf(stderr,"dirname: %s, filename: %s\n", dirname, filename);
	if ((res =  fat_open(dirname, &Parent, V, O_RDWR)) != 0) { fat_unlock(V); fprintf(stderr,"-- %d",__LINE__); return -ENOENT; }
	if ((res =  fat_create(V, &Parent, filename , NULL, S_IFREG, 0)) != 0) { fat_unlock(V); fprintf(stderr,"-- %d",__LINE__); return -1; }
	fat_unlock(V);
    return 0;
}

static int fusefat_mkdir(const char *path, mode_t mode) {
    int res;
    char dirname[4096];
    char filename[1024];
    File_t Parent;
	Volume_t *V;
	fusefat_getvolume(V);
    fat_dirname(path, dirname);
    fat_filename(path, filename);

	fat_lock(V);
    if ((res =  fat_open(dirname, &Parent, V, O_RDWR)) != 0) { fat_unlock(V); fprintf(stderr,"-- %d",__LINE__); return -ENOENT; }
    if ((res =  fat_mkdir(V, &Parent, filename , NULL, S_IFDIR)) != 0) { fat_unlock(V); fprintf(stderr,"-- %d",__LINE__); return -1; }

	fat_unlock(V);
    return 0;
}

static int fusefat_unlink(const char *path) {
    int res;
	File_t F;
	Volume_t *V;
	fusefat_getvolume(V);
	fat_lock(V);
	if ((res =  fat_open(path, &F, V, O_RDWR)) != 0) { fat_unlock(V); fprintf(stderr,"-- %d",__LINE__); return -ENOENT; }
	if ((res =  fat_delete(&F, 0)) != 0) { fat_unlock(V); fprintf(stderr,"-- %d",__LINE__); return -1; }
	fat_unlock(V);
    return 0;
}

static int fusefat_rmdir(const char *path) {
    int res;
	File_t F;
	Volume_t *V;
	fusefat_getvolume(V);
	fat_lock(V);
	if ((res =  fat_open(path, &F, V, O_RDWR)) != 0) { fat_unlock(V); fprintf(stderr,"-- %d",__LINE__); return -ENOENT; }
	if ((res =  fat_rmdir(&F)) != 0) { fat_unlock(V); fprintf(stderr,"-- %d",__LINE__); return -1; }
	fat_unlock(V);
    return 0;
}

// rename in libfat has bugs
static int fusefat_rename(const char *from, const char *to) {
    int res;
	Volume_t *V;
	fusefat_getvolume(V);

	fprintf(stderr,"from: %s, to: %s\n");
	fat_lock(V);

	if ((res =  fat_rename(V,from,to)) != 0) { fat_unlock(V); fprintf(stderr,"-- %d",__LINE__); return res; }

	fat_unlock(V);
    return 0;
}

static int fusefat_truncate(const char *path, off_t size) {
    int res;
	File_t F;
	Volume_t *V;
	fusefat_getvolume(V);
	fprintf(stderr,"truncate(%s, %d)\n",path,size);
	fat_lock(V);
    if ((res =  fat_open(path, &F, V, O_RDWR)) != 0) { fat_unlock(V); fprintf(stderr,"-- %d",__LINE__); return -ENOENT; }
    if ((res =  fat_truncate(&F, size)) != 0) { fat_unlock(V); fprintf(stderr,"-- %d",__LINE__); return -1; }
	fat_unlock(V);
    return 0;
}

static int fusefat_utime(const char *path, struct utimbuf *buf) {
    int res;
	File_t F;
	Volume_t *V;
	fusefat_getvolume(V);
	fat_lock(V);
    if ((res =  fat_open(path, &F, V, O_RDONLY)) != 0) { fat_unlock(V); fprintf(stderr,"-- %d",__LINE__); return -ENOENT; }
    if ((res =  fat_utime(&F, buf)) != 0) { fat_unlock(V); fprintf(stderr,"-- %d",__LINE__); return -1; }
	fat_unlock(V);
    return 0;
}

static int fusefat_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    int res, mode;
	File_t *F;
	Volume_t *V;
	fusefat_getvolume(V);
	F = (File_t *) fi->fh;
	fat_lock(V);
	mode = F->Mode;
	F->Mode = O_RDONLY;
//    if ((res =  fat_open(path, &F, V, O_RDONLY)) != 0) { fat_unlock(V); fprintf(stderr,"-- %d",__LINE__); return -ENOENT; }
    if ((res =  fat_seek(F, offset, SEEK_SET)) != offset) { fat_unlock(V); fprintf(stderr,"-- %d",__LINE__); return -1; }
	if ((FAT32_ISEOC(F->CurClus)) || FAT32_ISFREE(F->CurClus)) { fat_unlock(V); fprintf(stderr,"-- %d",__LINE__); return -1; }
	
    if ((res =  fat_read_data(V, &(F->CurClus), &(F->CurOff), buf, size )) <= 0) { fat_unlock(V); fprintf(stderr,"-- %d",__LINE__); return -1; }
	F->CurAbsOff += res;
	F->Mode = mode;
	fat_unlock(V);
    return res;
}

static int fusefat_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    int res;
	File_t *F;
	Volume_t *V;
	fusefat_getvolume(V);
	F=(File_t *)fi->fh;
	//if ((fi->flags & O_RDONLY) == O_RDONLY) { fprintf(stderr,"fusefat_write(): file opened in read only mode\n");; return -1; }
	
	fat_lock(V);
//    if ((res =  fat_open(path, &F, V, O_RDWR)) != 0) { fat_unlock(V); fprintf(stderr,"-- %d",__LINE__); return -ENOENT; }
    if ((res =  fat_seek(F, offset, SEEK_SET)) < 0) { fat_unlock(V); fprintf(stderr,"-- %d",__LINE__); return -1; }
    if ((res =  fat_write_data(V, F,&(F->CurClus), &(F->CurOff), buf, size )) != size) { 
		fat_unlock(V); fprintf(stderr,"fat_write_data() error\n");fprintf(stderr,"-- %d",__LINE__); return -1; }
	if ((res =  fat_update_file(F)) != 0) { fat_unlock(V); fprintf(stderr,"fat_update_file() error\n"); fprintf(stderr,"-- %d",__LINE__); return -1; }
	fat_unlock(V);
    return size;
}

static int fusefat_statvfs(const char *path, struct statvfs *stbuf) {
    int res;
	Volume_t *V;
	fusefat_getvolume(V);
	fat_lock(V);
	fat_statvfs(V, stbuf);
	fat_unlock(V);
    return 0;
}

static int fusefat_fsync(const char *path, int isdatasync, struct fuse_file_info *fi) {
    /* Just a stub.  This method is optional and can safely be left
       unimplemented */

    (void) path;
    (void) isdatasync;
    (void) fi;
    return 0;
}

static struct fuse_operations fusefat_oper = {
//	.init		=	,
//	.destroy	=	,
//	.lookup		=	NULL,
//	.forget		= 	NULL,		// forget an opened fh
    .getattr	= fusefat_getattr,
    .access		= fusefat_access,		// check file access permission
//    .readlink	= fusefat_readlink,	
    .readdir	= fusefat_readdir,
    .mknod		= fusefat_mknod,
//	.create = ,		
    .mkdir		= fusefat_mkdir,
//    .symlink	= fusefat_symlink,
    .unlink		= fusefat_unlink,		// remove a file
    .rmdir		= fusefat_rmdir,
    .rename		= fusefat_rename,
//    .link	= fusefat_link,
//    .chmod	= NULL,
//    .chown	= NULL,
    .truncate	= fusefat_truncate,
//    .utimens	= fusefat_utimens,
	.utime	= fusefat_utime,
    .open	= fusefat_open,
	.opendir= NULL,
    .read	= fusefat_read,
    .write	= fusefat_write,
    .statfs	= fusefat_statvfs,
    .release	= fusefat_release,	//we should avoid to delete a file if multiple processes are using it.
	.releasedir = NULL,
    .fsync	= fusefat_fsync	//sync
};

int main(int argc, char *argv[])
{
    Volume_t fat32_volume;
	Volume_t *V = &fat32_volume;

    struct fuse_chan *fuse_fd;

	char *pathname ;
	char *mountpoint;
	
	int res;

	pathname=argv[1];
	argv[1]=argv[0];
	
	if (argc < 3) { 
		fprintf(stderr,"usage: ./fusefat [fuse opts] mountpoint filesystem\n");
		return -1;
	}
	if ((res = fat_partition_init(V,pathname)) < 0) return -1;		
	
 //   umask(0);
    res =  fuse_main(--argc, ++argv, &fusefat_oper, V);
	
	res = fat_partition_finalize(V);
	return res;
}
