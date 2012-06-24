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

//#define VNODE_DEBUG

#define VNODE_HASH_SIZE 256
#define VNODE_HASH_MASK (VNODE_HASH_SIZE-1)

#if !defined(VNODE_DEBUG)
#undef debugf
#define debugf(a...) do { } while (0)
#endif

struct ext2_vnode {
	struct ext2_inode *inode;
	ext2_filsys e2fs;
	ext2_ino_t ino;
	ext2_file_t efile;
	int count;
	int flags;
	struct ext2_vnode **pprevhash,*nexthash;
};

static struct ext2_vnode *ht_head[VNODE_HASH_SIZE];

static inline struct ext2_vnode * vnode_alloc (int openfile)
{
	return (struct ext2_vnode *) malloc(sizeof(struct ext2_vnode) +
			((openfile == OPEN_FILE)?0:sizeof(struct ext2_inode)));
}

static inline void vnode_free (struct ext2_vnode *vnode)
{
	free(vnode);
}

static inline int vnode_hash_key (ext2_filsys e2fs, ext2_ino_t ino)
{
	return ((int) e2fs + ino) & VNODE_HASH_MASK;
}

struct ext2_inode *vnode2inode(struct ext2_vnode *vnode) {
	return vnode->inode;
}

static struct ext2_vnode * vnode_get_private (ext2_filsys e2fs, ext2_ino_t ino, int openfile)
{
	int hash_key = vnode_hash_key(e2fs,ino);
	struct ext2_vnode *rv = ht_head[hash_key];

	while (rv != NULL && rv->ino != ino) {
		rv = rv->nexthash;
	}
	if (rv != NULL) {
		if (openfile == OPEN_FILE && rv->efile == NULL) {
			debugf("This should never happen, vnode reopen of close file");
			return NULL;
		}
		rv->count++;
		debugf("increased hash:%p use count:%d efile:%p", rv, rv->count, rv->efile);
		return rv;
	} else {
		struct ext2_vnode *new = vnode_alloc(openfile);
		if (new != NULL) {
			errcode_t rc;
			if (openfile == OPEN_FILE) {
				if ((rc=ext2fs_file_open(e2fs, ino,
						((e2fs->flags & EXT2_FLAG_RW)? O_RDWR | EXT2_FILE_WRITE : O_RDONLY),
						&new->efile)) == 0) 
					new->inode=ext2fs_file_get_inode(new->efile);
				debugf("OPEN_FILE ok=%d %p %p",rc,new->inode,new->efile);
			}
			else {
				new->inode = (struct ext2_inode *) (new + 1);
				new->efile = NULL;
				rc = ext2fs_read_inode(e2fs, ino, new->inode);
				debugf("DONT_OPEN_FILE ok=%d %p %p",rc,new->inode,new->efile);
			}
			if (rc != 0) {
				vnode_free(new);
				debugf("leave error");
				return NULL;
			}
			new->e2fs = e2fs;
			new->ino = ino;
			new->count = 1;
			new->flags = 0;
			if (ht_head[hash_key] != NULL) {
				ht_head[hash_key]->pprevhash = &(new->nexthash);
			}
			new->nexthash = ht_head[hash_key];
			new->pprevhash = &(ht_head[hash_key]);
			ht_head[hash_key] = new;
			debugf("added hash:%p", new);
		}
		debugf("leave efile:%p", new->efile);
		return new;
	}
}

struct ext2_vnode * vnode_get (ext2_filsys e2fs, ext2_ino_t ino)
{
	return vnode_get_private(e2fs, ino, DONT_OPEN_FILE);
}

int vnode_put (struct ext2_vnode *vnode, int dirty)
{
	int rt = 0;
	vnode->count--;
	if (vnode->count <= 0) {
		struct ext2_inode tmpinode = *(vnode->inode);
		if (vnode->inode->i_links_count < 1) {
			rt = do_killfilebyinode(vnode->e2fs, vnode->ino, &tmpinode);
		} else if (dirty && (vnode->e2fs->flags & EXT2_FLAG_RW)) {
			rt = ext2fs_write_inode(vnode->e2fs, vnode->ino, vnode->inode);
		}
		if (rt) {
			debugf("vnode_put() close file failed");
			return -EIO;
		}
		if (vnode->efile != NULL) { /* open file */
			debugf("closing file:%p", vnode);
			rt=ext2fs_file_close(vnode->efile);

			if (rt) {
				debugf("vnode_put() close file failed");
				return -EIO;
			}
		}
		debugf("deleting hash:%p", vnode);
		*(vnode->pprevhash) = vnode->nexthash;
		if (vnode->nexthash) {
			vnode->nexthash->pprevhash = vnode->pprevhash;
		}
		vnode_free(vnode);
	} else if (dirty) {
		rt = ext2fs_write_inode(vnode->e2fs, vnode->ino, vnode->inode);
	}
	return rt;
}

static inline void vnode_access(struct ext2_vnode *vnode)
{
	ext2_filsys e2fs=vnode->e2fs;
	struct ext2_inode * inode=vnode->inode;

	inode->i_atime = e2fs->now ? e2fs->now : time(NULL);
}

static inline void vnode_modify(struct ext2_vnode *vnode)
{
	ext2_filsys e2fs=vnode->e2fs;
	struct ext2_inode * inode=vnode->inode;

	inode->i_mtime = inode->i_atime = e2fs->now ? e2fs->now : time(NULL);
}

struct ext2_vnode * vnode_file_open(ext2_filsys e2fs, ext2_ino_t ino, int flags)
{
	struct ext2_vnode *vnode=vnode_get_private(e2fs, ino, OPEN_FILE);
	if (vnode != NULL) {
		vnode_access(vnode);
		vnode->flags |= (flags & O_ACCMODE);
	}
	return vnode;
}

int vnode_file_read(struct ext2_vnode *vnode, char *buf, size_t size, off_t offset) 
{
	ext2_file_t efile=vnode->efile;
	errcode_t rc;
	__u64 pos;
	unsigned int bytes;
	debugf("vnode_file_read");
	if (efile == NULL) {
		return -EIO;
	}

	rc = ext2fs_file_llseek(efile, offset, SEEK_SET, &pos);
	if (rc) {
		return -EINVAL;
	}

	rc = ext2fs_file_read(efile, buf, size, &bytes);
	if (rc) {
		return -EIO;
	}

	vnode_access(vnode);

	debugf("leave");
	return bytes;
}

int vnode_file_write(struct ext2_vnode *vnode, const char *buf, size_t size, off_t offset) 
{
	ext2_file_t efile=vnode->efile;
	int rt;
	const char *tmp;
	unsigned int wr;
	unsigned long long npos;
	unsigned long long fsize;

	debugf("enter");
	if (efile == NULL) {
		return -EIO;
	}

	/* TODO 4 dirty = 1 */
	rt = ext2fs_file_get_lsize(efile, &fsize);
	if (rt != 0) {
		debugf("ext2fs_file_get_lsize(efile, &fsize); failed");
		return rt;
	}

	if (offset + size > fsize) {
		rt = ext2fs_file_set_size2(efile, offset + size);
		if (rt) {
			debugf("extfs_file_set_size(efile, %lld); failed", offset + size);
			return rt;
		}
	}

	rt = ext2fs_file_llseek(efile, offset, SEEK_SET, &npos);
	if (rt) {
		debugf("ext2fs_file_lseek(efile, %lld, SEEK_SET, &npos); failed", offset);
		return rt;
	}

	for (rt = 0, wr = 0, tmp = buf; size > 0 && rt == 0; size -= wr, tmp += wr) {
		debugf("size: %u, written: %u", size, wr);
		rt = ext2fs_file_write(efile, tmp, size, &wr);
	}
	if (rt) {
		debugf("ext2fs_file_write(edile, tmp, size, &wr); failed");
		return rt;
	}

	vnode_modify(vnode);
	/* TODO 4 can we skip this? it wastes time in case of massive use of the FS */
	rt = ext2fs_file_flush(efile); 
	if (rt) {
		debugf("ext2_file_flush(efile); failed");
		return rt;
	}

	debugf("leave");
	return wr;
}

int vnode_file_set_size(struct ext2_vnode *vnode, __u64 size)
{
	ext2_file_t efile=vnode->efile;
	errcode_t rt;

	debugf("enter");

	rt = ext2fs_file_set_size2(efile, size);

	vnode_modify(vnode);

	debugf("leave");
	return rt;
}

int vnode_file_flush(struct ext2_vnode *vnode)
{
	ext2_file_t efile=vnode->efile;
	errcode_t rc;

	debugf("enter %p",efile);
	if (efile == NULL) {
		return -ENOENT;
	}

	rc = ext2fs_file_flush(efile);

	if (rc) {
		return -EIO;
	}

	debugf("leave");
	return 0;
}

int vnode_file_close(struct ext2_vnode *vnode)
{
	errcode_t rc;

	debugf("enter");
	if (vnode == NULL) {
		return -ENOENT;
	}

	rc = vnode_put(vnode, (vnode->flags & O_ACCMODE));

	debugf("leave");
	return rc;
}

