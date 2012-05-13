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

struct ext2_vnode * do_open (ext2_filsys e2fs, const char *path, int flags)
{
	ext2_ino_t ino;
	struct ext2_vnode *vnode;
	int rt;

	debugf("enter");
	debugf("path = %s", path);

	rt = do_readvnode(e2fs, path, &ino, &vnode, OPEN_FILE | flags);
	if (rt) {
		debugf("do_readvnode(%s, &ino, &vnode); failed", path);
		return NULL;
	}

	debugf("leave");
	return vnode;
}

int op_open (const char *path, struct fuse_file_info *fi)
{
	struct ext2_vnode * vnode;
	ext2_filsys e2fs;
	FUSE_EXT2_LOCK;
	e2fs	= current_ext2fs();

	debugf("enter");
	debugf("path = %s", path);

	vnode = do_open(e2fs, path, fi->flags);
	if (vnode == NULL) {
		debugf("do_open(%s); failed", path);
		FUSE_EXT2_UNLOCK;
		return -ENOENT;
	}
	fi->fh = (unsigned long) vnode;

	debugf("leave");
	FUSE_EXT2_UNLOCK;
	return 0;
}
