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
 *   $Id$
 *
 */   

#ifndef _TREEPOCH_H
#define _TREEPOCH_H
 
typedef long long epoch_t;
typedef epoch_t (*epochfun)();

struct treepoch;
struct timestamp {
	epoch_t epoch;
	struct treepoch *treepoch;
};

epoch_t get_epoch();

epoch_t tst_matchingepoch(struct timestamp *service_tst);
struct timestamp tst_timestamp();

struct timestamp tst_newfork(struct timestamp *old_tst);

/*these should be transformed into constructors/destructors */
struct timestamp tst_newproc(struct timestamp *parent_tst);
	
void tst_delproc(struct timestamp *parent_tst);

#endif
