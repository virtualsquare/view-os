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
#define MAXDEPTH (sizeof(long) * 8) 

#define DEPTH_BYTES ((MAXDEPTH + 7)/8)
#define DEPTH_WORDS ((DEPTH_BYTES + sizeof(long) - 1)/sizeof(long))

struct treepoch {
	struct treepoch *parent;
	struct treepoch *sub0;
	struct treepoch *sub1;
	epoch_t rise;
	unsigned long nproc;
	unsigned long nref;
	unsigned short len;
	unsigned long bitstr[DEPTH_WORDS];
};

static struct treepoch *te_root;
static struct treepoch tst_useless={
	.len=__SHRT_MAX__,
};


static epoch_t epoch_now=2;
static pthread_mutex_t epoch_mutex = PTHREAD_MUTEX_INITIALIZER;

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
	/* if service_tst->treepoch is a  subset of  process_tst->treepoch
	 * return service_tst->epoch */
	/* if service_tst refers to a dead branch service_tst->epoch is updated*/
	struct timestamp *process_tst=um_x_gettst();
	fprint2("SE = %lld - PE = %lld\n",service_tst->epoch,process_tst->epoch);
	if (service_tst->epoch < process_tst->epoch)
		return service_tst->epoch;
	else
		return 0;
}

struct timestamp tst_timestamp() 
{
	struct timestamp *process_tst=um_x_gettst();
	struct timestamp rv;
	rv.treepoch=process_tst->treepoch;
	rv.epoch=new_epoch();
	return rv;
}

static void te_delproc(struct treepoch *node)
{
	if (node != NULL){
		struct treepoch *parent=node->parent;
		if (--node->nproc == 0) {
			/* treepoch node removal */
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

struct timestamp tst_newproc(struct timestamp *parent_tst,int newinstance)
{
	struct timestamp rv;
	if (newinstance) {
		struct treepoch *new_te;
		new_te=calloc(1,sizeof(struct treepoch));
		assert(new_te);
		if (te_root == NULL) {
			te_root=new_te;
		} else {
			/* treepoch creation */
		}
		rv.treepoch=new_te;
		rv.epoch=new_te->rise=new_epoch();
	} else
		rv=*parent_tst;
	te_newproc(rv.treepoch);
	return rv;
}

void tst_delproc(struct timestamp *parent_tst)
{
	te_delproc(parent_tst->treepoch);
}
