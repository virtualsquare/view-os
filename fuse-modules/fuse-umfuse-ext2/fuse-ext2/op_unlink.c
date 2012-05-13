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

int op_unlink (const char *path)
{
	int rt;
	errcode_t rc;

	char *p_path;
	char *r_path;

	ext2_ino_t p_ino;
	struct ext2_inode p_inode;
	ext2_ino_t r_ino;
	struct ext2_vnode *r_vnode;
	struct ext2_inode *r_inode;

	ext2_filsys e2fs;
	FUSE_EXT2_LOCK;
	e2fs	= current_ext2fs();

	debugf("enter");
	debugf("path = %s", path);

	rt=do_check_split(path, &p_path, &r_path);
	if (rt != 0) {
		debugf("do_check_split: failed");
		goto err;
	}

	debugf("parent: %s, child: %s", p_path, r_path);

	rt = do_readinode(e2fs, p_path, &p_ino, &p_inode);
	if (rt) {
		debugf("do_readinode(%s, &p_ino, &p_inode); failed", p_path);
		goto err_free_split;
	}
	rt = do_readvnode(e2fs, path, &r_ino, &r_vnode, DONT_OPEN_FILE);
	if (rt) {
		debugf("do_readvnode(%s, &r_ino, &r_vnode); failed", path);
		goto err_free_split;
	}
	r_inode = vnode2inode(r_vnode);

	if(LINUX_S_ISDIR(r_inode->i_mode)) {
		debugf("%s is a directory", path);
		vnode_put(r_vnode,0);
		rt = -EISDIR;
		goto err_free_split;
	}

	rc = ext2fs_unlink(e2fs, p_ino, r_path, r_ino, 0);
	if (rc) {
		debugf("ext2fs_unlink(e2fs, %d, %s, %d, 0); failed", p_ino, r_path, r_ino);
		vnode_put(r_vnode,0);
		rt = -EIO;
		goto err_free_split;
	}

	if (r_inode->i_links_count > 0) {
		r_inode->i_links_count -= 1;
	}

	p_inode.i_ctime = p_inode.i_mtime = e2fs->now ? e2fs->now : time(NULL);

	rc = ext2fs_write_inode(e2fs, p_ino, &p_inode);
	if (rc) {
		debugf("ext2fs_write_inode(e2fs, p_ino, &p_inode); failed");
		vnode_put(r_vnode,1);
		rt = -EIO;
		goto err_free_split;
	}

	r_inode->i_ctime = e2fs->now ? e2fs->now : time(NULL);
	rc = vnode_put(r_vnode,1);
	if (rc) {
		debugf("vnode_put(r_vnode,1); failed");
		rt = -EIO;
		goto err_free_split;
	}

	free_split(p_path, r_path);
	debugf("leave");
	FUSE_EXT2_UNLOCK;
	return 0;
err_free_split:
	free_split(p_path, r_path);
err:
	FUSE_EXT2_UNLOCK;
	return rt;
}
