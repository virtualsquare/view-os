/***************************************************************************
 *   Copyright (C) 2005 by Dmitry Morozhnikov   *
 *   dmiceman@mail.ru   *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 ***************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <linux/stat.h>

#include <linux/cramfs_fs.h>

#define FUSE_USE_VERSION 25


#include <zlib.h>

#include "cramfs.h"

#define UNUSED(x) x __attribute__((unused))

#if ( FUSE_MINOR_VERSION <= 5 )
 cramfs_data *cramfs_data_info=NULL;
#endif

static int cramfs_getattr(const char *path, struct stat *stbuf)
{

    return cramfs_real_getattr(path, stbuf);
}

static int cramfs_readlink(const char *path, char *target, size_t size) {

    return cramfs_real_readlink(path, target, size);
};

static int cramfs_open(const char *path, struct fuse_file_info *UNUSED(fi))
{
    return cramfs_real_open(path);
}

static int cramfs_read(const char *path, char *buf, size_t size,
                     off_t offset, struct fuse_file_info *UNUSED(fi))
{
    return cramfs_real_read(path, buf, size, offset);
}

static int cramfs_flush(const char *UNUSED(path), struct fuse_file_info *UNUSED(fi)) {
    return 0;
};

static void* cramfs_init() {
   struct fuse_context *mycontext;
   mycontext=fuse_get_context();
/* temporary solution waiting for FUSE 2.6 */
#if ( FUSE_MINOR_VERSION <= 5 )
  if (mycontext->private_data==NULL) mycontext->private_data=(void*) cramfs_data_info;
#endif
   return mycontext->private_data;
};


static int cramfs_opendir(const char *path, struct fuse_file_info *UNUSED(fi)) {
    return cramfs_real_opendir(path);
};

static int cramfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t UNUSED(offset),
    struct fuse_file_info *UNUSED(fi)) {
    return cramfs_real_readdir(path, buf, filler);
};

static int cramfs_statfs(const char *UNUSED(path), struct statfs *stbuf)
{
    return cramfs_real_statfs(stbuf);
}

static struct fuse_operations cramfs_oper = {
    .getattr    = cramfs_getattr,
    .readlink   = cramfs_readlink,
    .open       = cramfs_open,
    .read       = cramfs_read,
    .flush      = cramfs_flush,
    .init       = cramfs_init,
    .opendir    = cramfs_opendir,
    .readdir    = cramfs_readdir,
    .statfs     = cramfs_statfs,
};

int main(int argc, char *argv[])
{
    if(argc < 3) {
        printf("Version: %s\nUsage: %s <cramfs_image_file> <mount_point> [<FUSE library options>]\n", 
            "20050922", 
            argv[0]);
        exit(EINVAL);
    };
    
    char *imagefile = argv[1];

    char **nargv = (char **) malloc(argc * sizeof(char *));
    int nargc = argc - 1;
    
    nargv[0] = argv[0];
    
    int i;
    int res=0;

    for(i = 0; i < nargc; i++) {
        nargv[i + 1] = argv[i + 2];
    };

    cramfs_data *info;
    info=malloc(sizeof(cramfs_data));
    memset (info,0,sizeof(cramfs_data));
    info->negative_value = "not exists";
    info->error=0;
    info->context.imagefile=imagefile;
    pthread_mutex_init(&info->fd_mutex,NULL);
    pthread_mutex_init(&info->main_mutex,NULL);
    cramfs_real_init(info);
    if (info->error) res=info->error;
    else {
#if ( FUSE_MINOR_VERSION > 5 )
    res=fuse_main(nargc, nargv, &cramfs_oper,(void*)info);
#else
   /*waiting for fuse2.6*/
    cramfs_data_info=info;
    res=fuse_main(nargc, nargv, &cramfs_oper);
#endif
    }
   free(info);
   return res;
}
