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

#ifndef _UMFUSE_OFHT_H
#define _UMFUSE_OFHT_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

struct fuse_node {
	char *path;
	void *fuse;
	long hashsum;
	int open_count;
	struct fuse_node **pprevhash,*nexthash;
};

struct fuse_node *node_add(void *fuse, char *path);
struct fuse_node *node_search(void *fuse, char *path);
void node_del(struct fuse_node *old);
void node_newpath(struct fuse_node *node, char *newpath);
char *node_hiddenpath(struct fuse_node *node);
static inline int node_hiddenpathcheck(struct fuse_node *node)
{
	char check[17];
	snprintf(check,17,"/.fuse%010u",(unsigned)node->fuse);
	return (strncmp(node->path,check,16) == 0);
}

#endif
