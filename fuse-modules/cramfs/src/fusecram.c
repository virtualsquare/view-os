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

//#define FUSE_USE_VERSION 26
#include <fuse.h>

#include <zlib.h>

#include "cramfs.h"
#include "v2fuseutils.h"

#define UNUSED(x) x __attribute__((unused))

#define CONTEXT (fuse_get_context()->private_data)

static int cramfs_getattr(const char *path, struct stat *stbuf)
{
    return cramfs_real_getattr(CONTEXT, path, stbuf);
}

static int cramfs_readlink(const char *path, char *target, size_t size) {
    return cramfs_real_readlink(CONTEXT, path, target, size);
};

static int cramfs_open(const char *path, struct fuse_file_info *UNUSED(fi))
{
    return cramfs_real_open(CONTEXT, path);
}

static int cramfs_read(const char *path, char *buf, size_t size,
                     off_t offset, struct fuse_file_info *UNUSED(fi))
{
    return cramfs_real_read(CONTEXT, path, buf, size, offset);
}

static int cramfs_flush(const char *UNUSED(path), struct fuse_file_info *UNUSED(fi)) {
    return 0;
};


/*
static void* cramfs_init(struct fuse_conn_info *conn) {
	struct fuse_context *mycontext=fuse_get_context();
	char *imagefile=mycontext->private_data;
	return cramfs_real_init(imagefile);
};
*/
static void* cramfs_init(struct fuse_conn_info *conn) {
	return fuse_get_context()->private_data;
}

static int cramfs_opendir(const char *path, struct fuse_file_info *UNUSED(fi)) {
    return cramfs_real_opendir(CONTEXT, path);
};

static int cramfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t UNUSED(offset),
    struct fuse_file_info *UNUSED(fi)) {
    return cramfs_real_readdir(CONTEXT, path, buf, filler);
};

static int cramfs_statfs(const char *UNUSED(path), struct statvfs *stbuf)
{
    return cramfs_real_statvfs(CONTEXT, stbuf);
}

static void cramfs_destroy(void *context)
{
	  cramfs_real_fini(context);
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
    .destroy    = cramfs_destroy,
};

int main(int argc, char *argv[])
{
		void *context;

		if (argc < 3)
			v2f_usage(argv[0],&cramfs_oper);

		v2f_rearrangeargv(argc,argv);

		context=cramfs_real_init(argv[1]);
    
		if (context)
			return fuse_main(--argc, ++argv, &cramfs_oper, context);
		else
			return -1;
}
