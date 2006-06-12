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
	struct treepoch *sub[2];
	epoch_t rise;
	unsigned long nproc;
	unsigned long nref;
	unsigned short subheight;
	unsigned short len;
	unsigned long bitstr[DEPTH_WORDS];
};

static struct treepoch *te_root;
/*
static struct treepoch tst_useless={
	.len=__SHRT_MAX__,
};
*/

static epoch_t epoch_now=2;
static pthread_mutex_t epoch_mutex = PTHREAD_MUTEX_INITIALIZER;

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

struct timestamp tst_timestamp() 
{
	struct timestamp *process_tst=um_x_gettst();
	struct timestamp rv;
	rv.treepoch=process_tst->treepoch;
	rv.epoch=new_epoch();
	return rv;
}

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

static void de_update_height(struct treepoch *node,short subheight)
{
	subheight++;
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

static void te_delproc(struct treepoch *node)
{
	if (node != NULL){
		struct treepoch *parent=node->parent;
		if (--node->nproc == 0 && parent) {
			/* treepoch node removal */
			struct treepoch *other;
			other=(node==parent->sub[0])?parent->sub[1]:parent->sub[0];
			/* internal nodes have always two branches (sub[0] != NULL & sub[1] != NULL) */
			other->parent=parent->parent;
			other->rise=parent->rise;
			if (other->parent ==NULL)
				te_root=other;
			else
				//other->parent->sub[getbit(parent->bitstr,parent->len-1)]=other;
				other->parent->sub[getbit(parent->bitstr,parent->len-1)]=other;
			other->len=parent->len;
			memcpy(&other->bitstr,&parent->bitstr,DEPTH_WORDS*sizeof(long));
			node->parent=other;
			de_update_substr(other->sub[0],0);
			de_update_substr(other->sub[1],1);
			de_update_height(other->parent,other->subheight);
			/*te_printtree(te_root,0);*/
		}
		te_delproc(parent);
	}
}

static void te_newproc(struct treepoch *node)
{
	if (node != NULL){
		node->nproc++;
		te_newproc(node->parent);
	}
}

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
		rv.epoch=new_te->rise=new_epoch();
		if (te_root == NULL) {
			te_root=new_te;
		} else {
			/* treepoch creation */
			struct treepoch *old_te=old_tst->treepoch;
			struct treepoch *par_te=calloc(1,sizeof(struct treepoch));
			assert(old_te);
			assert(par_te);
			par_te->rise=old_te->rise;
			old_te->rise=new_te->rise;
			par_te->nproc=old_te->nproc;
			old_te->nproc=old_te->nproc-1;
			new_te->nproc=1;
			par_te->nref=2;
			new_te->nref=0;
			par_te->sub[0]=old_te;
			par_te->sub[1]=new_te;
			par_te->parent=old_te->parent;
			old_te->parent=new_te->parent=par_te;
			if (par_te->parent ==NULL) 
				te_root=par_te;
			else
				par_te->parent->sub[getbit(old_te->bitstr,old_te->len-1)]=par_te;
			par_te->len=old_te->len;
			memcpy(&par_te->bitstr,&old_te->bitstr,DEPTH_WORDS*sizeof(long));
			memcpy(&new_te->bitstr,&old_te->bitstr,DEPTH_WORDS*sizeof(long));
			new_te->subheight=0;
			par_te->subheight=old_te->subheight+1;
			de_update_substr(old_te,0);
			de_update_substr(new_te,1);
			de_update_height(par_te->parent,par_te->subheight);
			/*te_printtree(te_root,0);*/
		}
		return rv;
	}
}

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
