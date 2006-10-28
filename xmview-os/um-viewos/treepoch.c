/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   treepoch.c: management of epoch count for nesting 
 *   (TODO mgmt of tree for partial nesting, i.e. running a umview inside another umview)
 *   
 *   Copyright 2006 Renzo Davoli University of Bologna - Italy
 *   Some code Copyright 2006 Andrea Gasparini University of Bologna - Italy
 *   
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 *   $Id$
 *
 */   
#include <assert.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <bits/wordsize.h>
#include <stdio.h>
#include "treepoch.h"
#include "sctab.h"

/* a treepoch is a binary tree. 
 * each node represent a temporal interval of common history between
 * umview istances.
 * The two subtree of a node are named 0-subtree and 1-subtree, thus a
 * binary number is naturally assigned to each node.
 * (LSB is root choice)
 *
 * When a new istance starts two nodes get created in the treepoch
 * the 0-subtree represents the original istance after while the 1-subtree
 * represents the new istance.
 *
 * Each node is timestamped with its starting epoch.
 * Processes are always assigned to the leaves.
 *
 */

#if (__WORDSIZE == 32 )          /* 32 bits */
# define __LOG_WORDSIZE (5)
# define __WORDSIZEMASK 0x1f
#elif (__WORDSIZE == 64)           /* 64 bits */
# define __LOG_WORDSIZE (6)
# define __WORDSIZEMASK 0x3f
#else
# error sorry this program has been tested only on 32 or 64 bit machines
#endif

#define MAXDEPTH (sizeof(long) * 8) 

#define DEPTH_BYTES ((MAXDEPTH + 7)/8)
#define DEPTH_WORDS ((DEPTH_BYTES + sizeof(long) - 1)/sizeof(long))

struct treepoch {
	struct treepoch *parent;	
	struct treepoch *sub[2]; /*structure pointers*/
	epoch_t rise;            /*when this element was created */
	unsigned long nproc;     /* number of processes in this node */
	unsigned long nref;      /* number of references to this node */
	unsigned short subheight;/* height of the subtree rooted here*/
	unsigned short len;      /* len of the string (distance to the root) */
	unsigned long bitstr[DEPTH_WORDS]; /*bitstring of this node*/
};

static struct treepoch *te_root; /* root of the treepoch structure */
/*
static struct treepoch tst_useless={
	.len=__SHRT_MAX__,
};
*/

/* epoch now is a (long long) counter, it is used to timestamp all the state
 * changes in the system */
static epoch_t epoch_now=2; 
/* mutex for multithreading */
static pthread_mutex_t epoch_mutex = PTHREAD_MUTEX_INITIALIZER;

/* bit string management, the string is splitted into word-sized elements */
static int getbit(unsigned long *v,short b)
{
	return (v && (v[b >> __LOG_WORDSIZE] & (1<< (b & __WORDSIZEMASK))));
}

static void setbit(unsigned long *v,short b,int val)
{
	if (v) {
		if (val)
			v[b >> __LOG_WORDSIZE] |= (1<< (b & __WORDSIZEMASK));
		else
			v[b >> __LOG_WORDSIZE] &= ~(1<< (b & __WORDSIZEMASK));
	}
}

/* TRUE if two strings differs up to the "len"th element */
static int diffbitstr(unsigned long *a,unsigned long *b,short len)
{
	int i;
	int w=len >> __LOG_WORDSIZE;
	unsigned long mask= (1<<(len & __WORDSIZEMASK)) - 1;
	int rv=0;
	for (i=0;i<w && rv;i++)
		rv = (a[i] != b[i]);
	if (mask && !rv)
		rv = ((a[i] & mask) != (b[i] & mask));
	//fprint2("DIFF %x %x %d -> %d\n",a[0],b[0],len,rv);
	return rv;
}

/* one tick of the global timestap clock epoch_now */
static epoch_t new_epoch(){
	epoch_t tmp;
	pthread_mutex_lock(&epoch_mutex);
	tmp=epoch_now;
	epoch_now++;
	pthread_mutex_unlock(&epoch_mutex);
	//fprint2("NEW EPOCH %lld\n",epoch_now);
	return tmp;
}

epoch_t get_epoch(){
	return epoch_now;
}

/* it is > 0 if the operation time is consistent with the service time.
 * in such a case it returns the epoch of the matching */
epoch_t tst_matchingepoch(struct timestamp *service_tst)
{
	/* if service_tst refers to a dead branch service_tst->epoch is updated*/
	struct timestamp *process_tst=um_x_gettst();
	/*fprint2("SE = %lld - PE = %lld\n",service_tst->epoch,process_tst->epoch);*/
	while (service_tst->treepoch->parent && service_tst->treepoch->nproc==0) 
		service_tst->treepoch = service_tst->treepoch->parent;
	//fprint2("MATCH up %lld %lld\n",service_tst->epoch,service_tst->treepoch->rise);
	while (service_tst->epoch < service_tst->treepoch->rise) 
		service_tst->treepoch = service_tst->treepoch->parent;
	/* process_tst->treepoch is NULL only for garbage collection final calls. Always match! */
	if (process_tst)
	{
		/* if service_tst->treepoch is a  subset of  process_tst->treepoch
		 * return service_tst->epoch */
		if (service_tst->treepoch->len > process_tst->treepoch->len ||
				diffbitstr(service_tst->treepoch->bitstr,process_tst->treepoch->bitstr,service_tst->treepoch->len))
			return 0;
		else if (service_tst->epoch < process_tst->epoch)
			return service_tst->epoch;
		else
			return 0;
	} else
		return service_tst->epoch;
}

/* create a complete timestamp of an event */
struct timestamp tst_timestamp() 
{
	struct timestamp *process_tst=um_x_gettst();
	struct timestamp rv;
	rv.treepoch=process_tst->treepoch;
	rv.epoch=new_epoch();
	return rv;
}

/* update the treepoch: substring and len are updated towards the leaves
 * by a recursive depth first search */
static void de_update_substr(struct treepoch *node,int v01)
{
	if (node) {
		node->len=node->parent->len;
		setbit(node->bitstr,node->len,v01);
		(node->len)++;
		de_update_substr(node->sub[0],0);
		de_update_substr(node->sub[1],1);
	}
}

/* update the treepoch: the subtree height must be updated towards the root:
 * this recursive scan terminates when the root has been reached or
 * when the other subtree is deeper */
static void de_update_height(struct treepoch *node,short subheight)
{
	subheight++;
	/* XXX does this work correctly when deleting levels? */
	if (node && node->subheight < subheight) {
		node->subheight=subheight;
		de_update_height(node->parent,subheight);
	}
}

#if 0
/* just for debugging */
static void te_printtree(struct treepoch *node,int l)
{
	if (node != NULL) {
		fprint2("%d-printtree par %p np%d h%d l%d >%x\n",l,node,node->nproc,node->subheight,node->len,node->bitstr[0]);
		te_printtree(node->sub[0],l+1);
		te_printtree(node->sub[1],l+1);
	}
}
#endif

/* delete a process form the treepoch */
static void te_delproc(struct treepoch *node)
{
	if (node != NULL){
		struct treepoch *parent=node->parent;
		/* if there are no more processes depending on this node */
		if (--node->nproc == 0 && parent) {
			/* treepoch node removal */
			struct treepoch *other;
			/* other is the "surviving" branch from the parent */
			other=(node==parent->sub[0])?parent->sub[1]:parent->sub[0];
			/* internal nodes have always two branches (sub[0] != NULL & sub[1] != NULL) */
			/* two nodes of the treepoch gets deleted, the empty leaf and its
			 * parent, the other branch root node gets the role of the former 
			 * parent */
			/* cancellando X (parent is A, deleted, and other is B)
			 *        |                 |
			 *        A                 B
			 *       / \               / \
			 *      X   B
			 *         / \
			 */         
			other->parent=parent->parent;
			/* the timestamp of the new parent is the timestamp of the old parent */
			other->rise=parent->rise;
			/* special case: root of treepoch redefined */
			if (other->parent ==NULL)
				te_root=other;
			else
			/* normal case: set the pointer of grandparent's son to 'other' */
				other->parent->sub[getbit(parent->bitstr,parent->len-1)]=other;
			other->len=parent->len;
			/* copy the string of parent (other takes the role of its parent) */
			memcpy(&other->bitstr,&parent->bitstr,DEPTH_WORDS*sizeof(long));
			/* the node is kept for lazy garbage collection */
			node->parent=other;
			/* update the structure */
			de_update_substr(other->sub[0],0);
			de_update_substr(other->sub[1],1);
			de_update_height(other->parent,other->subheight);
			/*te_printtree(te_root,0);*/
		}
		/* nproc must be updated also on the ancestors */
		te_delproc(parent);
	}
}

/* add a new process (nproc++ for the node and for all its ancestors)*/
static void te_newproc(struct treepoch *node)
{
	if (node != NULL){
		node->nproc++;
		te_newproc(node->parent);
	}
}

/* interface function: generate a new fork */
struct timestamp tst_newfork(struct timestamp *old_tst)
{
	struct timestamp rv;
	struct treepoch *new_te;
	assert ((old_tst != NULL && old_tst->treepoch != NULL) || te_root == NULL);
	//fprint2("FORK \n");
	/* if there is one process only no fork takes place */
	if (old_tst && (old_tst->treepoch->nproc == 1 ||
	/* if the branch has already reached the max height no fork*/
				(old_tst->treepoch->subheight + old_tst->treepoch->len) >= MAXDEPTH)) 
		return *old_tst; 
	else {
		new_te=calloc(1,sizeof(struct treepoch));
		assert(new_te);
		rv.treepoch=new_te;
		/* a new fork *is* a relevant event for the system timestamping */
		rv.epoch=new_te->rise=new_epoch();
		if (te_root == NULL) {
			/* special case: first node= root */
			te_root=new_te;
		} else {
			/* treepoch creation */
			/* when a treepoch forks two nodes get created. ex:old_te forks:
			 *  |            |
			 *old_te      par_te
			 *              / \
			 *         old_te new_te
			 */
			struct treepoch *old_te=old_tst->treepoch;
			struct treepoch *par_te=calloc(1,sizeof(struct treepoch));
			assert(old_te);
			assert(par_te);
			/* old and new have the timestamp of the fork, while par_te
			 * gets the old timestamp of old_te */
			par_te->rise=old_te->rise;
			old_te->rise=new_te->rise;
			/* the new fork has a process (the caller), old_te has lost
			 * one process */
			par_te->nproc=old_te->nproc;
			old_te->nproc=old_te->nproc-1;
			new_te->nproc=1;
			par_te->nref=2;
			new_te->nref=0;
			/* re-link the binary tree structure */
			par_te->sub[0]=old_te;
			par_te->sub[1]=new_te;
			par_te->parent=old_te->parent;
			old_te->parent=new_te->parent=par_te;
			/* update the grandparent's son pointer */
			if (par_te->parent ==NULL) 
				te_root=par_te;
			else
				par_te->parent->sub[getbit(old_te->bitstr,old_te->len-1)]=par_te;
			/* update the bit strings */
			par_te->len=old_te->len;
			memcpy(&par_te->bitstr,&old_te->bitstr,DEPTH_WORDS*sizeof(long));
			memcpy(&new_te->bitstr,&old_te->bitstr,DEPTH_WORDS*sizeof(long));
			new_te->subheight=0;
			par_te->subheight=old_te->subheight+1;
			/* update strings (in the subtree) and height towards the ancestors */
			de_update_substr(old_te,0);
			de_update_substr(new_te,1);
			de_update_height(par_te->parent,par_te->subheight);
			/*te_printtree(te_root,0);*/
		}
		return rv;
	}
}

/* interface functions: add a process/delete a process */
struct timestamp tst_newproc(struct timestamp *parent_tst)
{
	struct timestamp rv;
	rv=*parent_tst;
	te_newproc(rv.treepoch);
	//fprint2("NEW PROC %p %d %d %x\n",rv.treepoch,rv.treepoch->nproc,rv.treepoch->len,rv.treepoch->bitstr[0]);
	return rv;
}

void tst_delproc(struct timestamp *parent_tst)
{
	//fprint2("DEL PROC %p %d %d %x\n",parent_tst->treepoch,parent_tst->treepoch->nproc,parent_tst->treepoch->len,parent_tst->treepoch->bitstr[0]);
	te_delproc(parent_tst->treepoch);
}
