//
// C Interface: cramfs
//
// Description: 
//
//
// Author: Dmitry Morozhnikov <dmiceman@mail.ru>, (C) 2005
//
// Copyright: See COPYING file that comes with this distribution
//
//

#ifndef __CRAMFS_H_
#define __CRAMFS_H_

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <utime.h>
#include <linux/cramfs_fs.h>
#include <glib.h>
#include <pthread.h>
#include <fuse.h>

typedef int (*cramfs_dir_fill_t) (void *buf, const char *name,
    const struct stat *stat, off_t off);

typedef struct _cramfs_context {
    char *imagefile;
    int fd;
    struct cramfs_super super;
} cramfs_context;

typedef struct _cramfs_inode_context {
    int ino;
    struct cramfs_inode *inode;
} cramfs_inode_context;

typedef struct  {
   cramfs_context context;
   cramfs_inode_context *root_context;
   GHashTable *lookup_table;
   GHashTable *negative_lookup_table;
   char *negative_value;
   int last_node;
   pthread_mutex_t main_mutex;
   pthread_mutex_t fd_mutex;
   int error;
} cramfs_data;

#define PAGE_CACHE_SIZE (4096)

void cramfs_real_init(cramfs_data *c);
int cramfs_real_opendir(const char *path);
int cramfs_real_readdir(const char *path, void *buf, cramfs_dir_fill_t filler);
int cramfs_real_getattr(const char *path, struct stat *stbuf);
int cramfs_real_readlink(const char *path, char *target, size_t size);
int cramfs_real_open(const char *path);
int cramfs_real_read(const char *path, char *buf, size_t size, off_t offset);
int cramfs_real_statfs(struct statfs *stbuf);

#endif // __CRAMFS_H_
