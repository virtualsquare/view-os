/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   umviewos -> fuse gateway 
 *   open file hash table (to rename open deleted files)
 *   
 *   Copyright 2009 Renzo Davoli University of Bologna - Italy
 *   
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License, version 2, as
 *   published by the Free Software Foundation.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <umfuse_node.h>

#define NODE_HASH_SIZE 128
#define NODE_HASH_MASK (NODE_HASH_SIZE-1)

static struct fuse_node *node_head[NODE_HASH_SIZE];

static inline struct fuse_node *node_alloc() {
	     return (struct fuse_node *)malloc(sizeof (struct fuse_node));
}

static inline void node_free(struct fuse_node *vnode) {
	  free(vnode);
}

static inline long vnode_hash_sum(void *fuse, char *path) {
	long sum = (long) fuse;
	while (*path != 0) {
		sum ^= ((sum << 5) + (sum >> 2) + *path);
		path++;
	}
	return sum;
}

static inline int vnode_hash_mod(long sum)
{
	return sum & NODE_HASH_MASK;
}	

static inline struct fuse_node *node_find(void *fuse, char *path, 
		long hashsum, int hashkey)
{
	struct fuse_node *scan=node_head[hashkey];
	//printk("node_find %s\n",path);
	while (scan != NULL) {
	//printk("node_find_scan %s\n",path,scan->path);
		if (scan->hashsum == hashsum && scan->fuse == fuse &&
				strcmp(scan->path, path) == 0)
			return scan;
		scan=scan->nexthash;
	}
	return NULL;
}

struct fuse_node *node_add(void *fuse, char *path)
{
	long hashsum = vnode_hash_sum(fuse, path);
	int hashkey = vnode_hash_mod(hashsum);
	struct fuse_node *new = node_find(fuse, path, hashsum, hashkey);
	//printk("+%s %ld %d %p\n",path,hashsum,hashkey,new);
	if (new != NULL) 
		new->open_count++;
	else {
		new = node_alloc();
		if (new != NULL) {
			new->fuse=fuse;
			new->hashsum=hashsum;
			new->open_count=1;
			new->path=strdup(path);
			if (node_head[hashkey] != NULL)
				node_head[hashkey]->pprevhash = &(new->nexthash);
			new->nexthash = node_head[hashkey];
			new->pprevhash = &(node_head[hashkey]);
			node_head[hashkey] = new;
		}
	}
	return new;
}

struct fuse_node *node_search(void *fuse, char *path)
{
	long hashsum = vnode_hash_sum(fuse, path);
	int hashkey = vnode_hash_mod(hashsum);
	struct fuse_node *rv=node_find(fuse, path, hashsum, hashkey);
	//printk("%s %ld %d %p\n",path,hashsum,hashkey,rv);
	return rv;
}

void node_del(struct fuse_node *old)
{
	if (old) {
		old->open_count--;
		if (old->open_count == 0) {
			free(old->path);
			*(old->pprevhash)=old->nexthash;
			if (old->nexthash)
				old->nexthash->pprevhash=old->pprevhash;
		}
	}
}

void node_newpath(struct fuse_node *node, char *newpath)
{
	long hashsum = vnode_hash_sum(node->fuse, newpath);
	int hashkey = vnode_hash_mod(hashsum);
	/* delete the node from its old position in the hash table */
	*(node->pprevhash)=node->nexthash;
	if (node->nexthash)
		node->nexthash->pprevhash=node->pprevhash;
	/* change path and hashsum */
	free(node->path);
	node->path=strdup(newpath);
	node->hashsum=hashsum;
	/* add it by its new hashkey */
	if (node_head[hashkey] != NULL)
		node_head[hashkey]->pprevhash = &(node->nexthash);
	node->nexthash = node_head[hashkey];
	node->pprevhash = &(node_head[hashkey]);
	node_head[hashkey] = node;
}

char *node_hiddenpath(struct fuse_node *node)
{
	char *name;
	static unsigned long hiddencount;
	asprintf(&name,"/.fuse%010lu%010lu",(unsigned long)node->fuse,hiddencount++);
	return name;
}
