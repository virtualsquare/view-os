/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   hashtab.h: hashtable management, fast search for module services.
 *   
 *   Copyright 2008,2009 Renzo Davoli University of Bologna - Italy
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
 *   $Id: services.h 468 2008-04-23 22:08:52Z rd235 $
 *
 */

#ifndef _HASHTAB_H
#define _HASHTAB_H
#include "treepoch.h"
#include "services.h"

struct ht_elem;
/* modules can define check functions to test for exceptions */
typedef int (* checkfun_t)(int type, void *arg, int arglen,
		struct ht_elem *ht);
#define NEGATIVE_MOUNT ((checkfun_t) 1)
#define HT_ERR ((struct ht_elem *) 1)

/* add a path to the hashtable (this creates an entry for the mounttab) */
struct ht_elem *ht_tab_pathadd(unsigned char type, const char *source,
		const char *path, const char *fstype, 
		unsigned long mountflags, const char *flags,
		struct service *service, unsigned char trailingnumbers,
		checkfun_t checkfun, void *private_data);

/* add a generic element to the hashtable */
struct ht_elem *ht_tab_add(unsigned char type,void *obj,int objlen,
		struct service *service, checkfun_t checkfun, void *private_data);

int isnosys(sysfun f);
struct ht_elem *ht_check(int type, void *arg, struct stat64 *st, int setepoch);
sysfun ht_syscall(struct ht_elem *hte, int scno);
sysfun ht_socketcall(struct ht_elem *hte, int scno);
sysfun ht_virsyscall(struct ht_elem *hte, int scno);
sysfun ht_ioctlparms(struct ht_elem *hte);
sysfun ht_event_subscribe(struct ht_elem *hte);

void ht_tab_invalidate(struct ht_elem *hte); 
int ht_tab_del(struct ht_elem *mp); 

void ht_tab_getmtab(FILE *f);

void forall_ht_tab_service_do(unsigned char type,
		struct service *service,
		void (*fun)(struct ht_elem *ht, void *arg),
		void *arg);

void forall_ht_tab_do(unsigned char type,
		void (*fun)(struct ht_elem *ht, void *arg),
		void *arg);

void forall_ht_tab_del_invalid(unsigned char type);

void *ht_get_private_data(struct ht_elem *hte);
void ht_set_private_data(struct ht_elem *hte,void *private_data);
char *ht_servicename(struct ht_elem *hte);
void ht_count_plus1(struct ht_elem *hte);
void ht_count_minus1(struct ht_elem *hte);
int ht_get_count(struct ht_elem *hte);

#endif
