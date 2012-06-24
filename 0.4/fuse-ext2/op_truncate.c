/**
 * Copyright (c) 2008-2010 Alper Akcan <alper.akcan@gmail.com>
 * Copyright (c) 2009-2010 Renzo Davoli <renzo@cs.unibo.it>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (in the main directory of the fuse-ext2
 * distribution in the file COPYING); if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "fuse-ext2.h"

int op_truncate(const char *path, off_t length)
{
	int rt;
	struct ext2_vnode *vnode;
	ext2_filsys e2fs;
	FUSE_EXT2_LOCK;
	e2fs	= current_ext2fs();

	debugf("enter");
	debugf("path = %s", path);

	rt = do_check(path);
	if (rt != 0) {
		debugf("do_check(%s); failed", path);
		goto err;
	}
	vnode = do_open(e2fs, path, O_WRONLY);
	if (vnode == NULL) {
		debugf("do_open(%s); failed", path);
		rt = -ENOENT;
		goto err;
	}

	rt = vnode_file_set_size(vnode, length);
	if (rt) {
		vnode_file_close(vnode);
		debugf("ext2fs_file_set_size(vnode, %d); failed", length);
		goto err;
	}

	rt = vnode_file_close(vnode);
	if (rt != 0) {
		debugf("do_release(vnode); failed");
		goto err;
	}

	debugf("leave");
	FUSE_EXT2_UNLOCK;
	return 0;
err:
	FUSE_EXT2_UNLOCK;
	return rt;
}

int op_ftruncate(const char *path, off_t length, struct fuse_file_info *fi)
{
	size_t rt;
	FUSE_EXT2_LOCK;

	debugf("enter");
	debugf("path = %s", path);

	rt = vnode_file_set_size(EXT2FS_VNODE(fi->fh), length);

	debugf("leave");
	FUSE_EXT2_UNLOCK;
	return rt;
}
