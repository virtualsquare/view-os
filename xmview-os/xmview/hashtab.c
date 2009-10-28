/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   hashtab.c: main hash table
 *   
 *   Copyright 2009 Renzo Davoli University of Bologna - Italy
 *   Credit: this ideas were tested on a preliminary version by 
 *   Marcello Stanisci.
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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <pthread.h>
#include <sctab.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <limits.h>
#include <unistd.h>
#include "hashtab.h"

/* struct ht_elem:
	 @obj: hash key
	 @mtabline: mount tab line
	 @type: type (see CHECK* in services.c)
	 @trailingnumbers: boolean, match pathnames with trailing numbers
	 @invalid: boolean, the element is logially deleted
	 @service: service associated to this item
	 @private_data: opaque container for module data
	 @objlen: len of the hash key
	 @hashsum: hash sum for quick negative matching
	 @count: usage coune
	 @confirmfun: confirmation function for exceptions
	 @prev/next/pprevhash,nexthash: addresses for list linking
	 */
struct ht_elem {
	void *obj;
	char *mtabline;
	unsigned long mountflags;
	struct timestamp tst;
	unsigned char type;
	unsigned char trailingnumbers;
	unsigned char invalid;
	struct service *service;
	struct ht_elem *service_hte;
	void *private_data;
	int objlen;
	long hashsum;
	int count;
	confirmfun_t confirmfun;
	struct ht_elem *prev,*next,**pprevhash,*nexthash;
};

/* it must be a power of two (masks are used instead of modulo) */
#define MNTTAB_HASH_SIZE 512
#define MNTTAB_HASH_MASK (MNTTAB_HASH_SIZE-1)

static struct ht_elem *ht_hash[MNTTAB_HASH_SIZE]; 
static struct ht_elem *ht_hash0[NCHECKS]; 
static struct ht_elem *ht_head[NCHECKS];
//static struct ht_elem *ht_free;
static pthread_rwlock_t ht_tab_rwlock = PTHREAD_RWLOCK_INITIALIZER;

/* alloc/free of ht_elem */
static inline struct ht_elem *ht_tab_alloc() {
	 return (struct ht_elem *)malloc(sizeof (struct ht_elem));
}

static inline void ht_tab_free(struct ht_elem *ht) {
	free(ht->obj);
	if (ht->mtabline)
		free(ht->mtabline);
	free(ht);
}

/* hash function */
/* hash sum and mod are separate functions:
	 hash sums are used to quicly elimiate false positives,
	 intermediate results can be completed during the scan */
static inline long hashadd (long prevhash, char c) {
	return prevhash ^ ((prevhash << 5) + (prevhash >> 2) + c); 
}

static inline int hashmod (long hashsum) {
	return hashsum & MNTTAB_HASH_MASK;
}

static inline long hashsum (unsigned char type,const char *c,int len) {
	long sum=type;
	int i;
	for (i=0;i<len;i++,c++)
		sum=hashadd(sum,*c);
	return sum;
}

/* CARROT magagement:
	 a carrot is a list of virtualization layers lying under a path
	 the list is sorted from the newest to the oldest
	 a carrot contains all the layers up to the newest which do not
	 have exceptions */
static inline int ht_elem_has_exceptions(struct ht_elem *elem)
{
	return (elem->confirmfun != NULL);
}

struct carrot {
	struct ht_elem *elem;
	epoch_t time;
	struct carrot *next;
};

static struct carrot *carrot_fhead;

static inline struct carrot *carrot_alloc(void) {
	struct carrot *rv=NULL;
	if (carrot_fhead != NULL) {
		rv=carrot_fhead;
		carrot_fhead=rv->next;
		rv->next=NULL;
	} else /* XXX maybe we can allocate groups of carrot elems */
		rv=malloc(sizeof(struct carrot));
	return rv;
}

static void carrot_free(struct carrot *old) {
	if (old != NULL) {
		struct carrot *scan;
		for (scan=old;scan->next!=NULL;scan=scan->next)
			;
		scan->next=carrot_fhead;
		carrot_fhead=old;
	}
}

static struct carrot *carrot_insert(struct carrot *head, struct ht_elem *elem,  epoch_t time) {
	if (head==NULL ||	/* empty carrot */
			head->time < time) { /* this is newer */
		if (head==NULL || ht_elem_has_exceptions(elem)) {
			struct carrot *rv;
			rv=carrot_alloc();
			rv->elem=elem;
			rv->time=time;
			rv->next=head;
			return rv;
		} else {
			head->elem=elem;
			head->time=time;
			carrot_free(head->next);
			head->next=NULL;
			return head;
		}
	} else {
		if (ht_elem_has_exceptions(head->elem)) 
			head->next=carrot_insert(head->next,elem,time);
		return head;
	}		
}

static struct carrot *carrot_delete(struct carrot *head, struct ht_elem *elem) {
	if (head==NULL)
		return NULL;
	else {
		if (head->elem==elem) {
			struct carrot *tail=head->next;
			head->next=NULL;
			carrot_free(head);
			return tail;
		} else {
			head->next=carrot_delete(head->next,elem);
			return head;
		}
	}
}

/* true if there are only trailing numbers (and there is at least one) */
/* View-OS permits "mount" of things like /dev/hda[0-9]* */
static inline int trailnum(char *s)
{
	/* "at least one" the first element needs a special case.
     performance:  >'9' is the most frequent case, <'0' are quite rare
		 in pathnames, the end of string is more common */
	if (*s > '9' || *s == 0 || *s < '0')
		return 0;
	for (s++;*s;s++) 
		if (*s > '9' || *s < '0')
			return 0;
	return 1;
}

/* during the scan: search in the hash table if this returns 1 */
static inline int ht_scan_stop(unsigned char type, char *objc, int len, int exact) {
	switch (type) {
		case CHECKPATH:
			return (*objc == 0  /* this is the end of a string */
					|| (!exact /* or when subtring match are allowed */
						&& (*objc=='/' /* test the match if the current char is '/' */
				/* or if there are trailing numbers e.g. /dev/hda1, hda2 etc */
							|| trailnum(objc))));
		case CHECKBINFMT:
			return (*objc == 0  /* this is the end of a string */
					|| (!exact /* or when subtring match are allowed */
						&& *objc=='/')); /* test the match if the current char is '/' */
		case CHECKSOCKET:
		case CHECKCHRDEVICE:
		case CHECKBLKDEVICE:
		case CHECKSC: /* array of int, or null keys */
			return ((len % sizeof(int))==0);
		case CHECKFSALIAS: /* end of string */
			return (*objc == 0);
		case CHECKMODULE:
			if (exact)
				return (*objc == 0);
			else
				return 1; /* CHECKFSTYPE char by char */
		default:
			return 0;
	}
}

/* terminate the scan */
static inline int ht_scan_terminate(unsigned char type, char *objc, int len, int objlen) {
	switch (type) {
		case CHECKPATH:
		case CHECKBINFMT:
		case CHECKFSALIAS:
		case CHECKMODULE:
			return (*objc == 0);
		case CHECKSOCKET:
		case CHECKCHRDEVICE:
		case CHECKBLKDEVICE:
		case CHECKSC:
			return (len==objlen);
		default:
			return 0;
	}
}
static inline int call_confirmfun(int (*confirmfun)(),unsigned char type,void *checkobj,int len,struct ht_elem *ht) {
	epoch_t epoch=um_setnestepoch(ht->tst.epoch);
	struct ht_elem *ht_old=um_mod_get_hte();
	um_mod_set_hte(ht);
	int rv=confirmfun(type,checkobj,len,ht);
	um_setnestepoch(epoch);
	um_mod_set_hte(ht_old);
	return rv;
}

/* unified search, specific searches are defined in hashtab.h as 
	 inline functions (for performance) */
static struct ht_elem *ht_tab_internal_search(unsigned char type, void *obj, int objlen, void *checkobj, struct timestamp *tst, int exact) 
{
	struct ht_elem *rv=NULL;
	char *objc=obj;
	long sum=type;
	long hash;
	struct carrot *carh=NULL;
	struct ht_elem *ht;
	int len=0;
	pthread_rwlock_rdlock(&ht_tab_rwlock);
	while (1) {
		if (ht_scan_stop(type, objc, len, exact)) {
			hash=hashmod(sum);
			ht=(len)?ht_hash[hash]:ht_hash0[type];
			/* if (type== XXXXXX )
				 printk("CHECK %s %ld %d %p\n",obj,sum,hash,ht); */
			while (ht != NULL) {
				epoch_t e;
				/* if (type== XXXXXXX && type==ht->type)
					 printk("CHECK %s %s\n",obj,ht->obj); */
				if (type==ht->type &&
						sum==ht->hashsum &&
						(ht->objlen >= len) &&
						memcmp(obj,ht->obj,len)==0 &&
						(ht->trailingnumbers || !trailnum(objc)) &&
						(tst->epoch > ht->tst.epoch) &&
						(e=tst_matchingepoch(&(ht->tst))) > 0 &&
						(ht->invalid == 0)) {
					/*carrot add*/
					if (ht->confirmfun == NEGATIVE_MOUNT)
						carh=carrot_delete(carh, ht->private_data);
					else
						carh=carrot_insert(carh, ht, e); 
				}
				ht=ht->nexthash;
			}
			if (ht_scan_terminate(type, objc, len, objlen))
				break;
		}
		sum=hashadd(sum,*objc);
		objc++;
		len++;
	}
	if (carh != NULL) {
		struct carrot *curcar=carh;
		for (curcar=carh; curcar!=NULL;curcar=curcar->next) {
			ht=curcar->elem;
			if (ht->confirmfun==NULL || call_confirmfun(ht->confirmfun,type,checkobj,len,ht))
				break;
		}
		if (curcar != NULL)
			rv=curcar->elem;
		carrot_free(carh);
	}
	pthread_rwlock_unlock(&ht_tab_rwlock);
	/*printk("ht_tab_search %s %p\n",(char *)obj,rv);*/
	return rv;
}

static inline struct ht_elem *ht_tab_pathsearch(unsigned char type, void *obj, 
		struct timestamp *tst, int exact) {
	return ht_tab_internal_search(type,obj,0,obj,tst,exact);
}

static inline struct ht_elem *ht_tab_binfmtsearch(unsigned char type, 
		struct binfmt_req *req, struct timestamp *tst, int exact) {
	return ht_tab_internal_search(type,req->path,0,req,tst,exact);
}

static inline struct ht_elem *ht_tab_search(unsigned char type, void *obj, 
		int objlen, struct timestamp *tst, int exact) {
	return ht_tab_internal_search(type,obj,objlen,obj,tst,exact);
}

/* for debugging: otherwise strings are not null terminated, so cannot 
	 be printed*/
#if 0
static inline int ht_is_obj_string(unsigned char type) {
	switch (type) {
		case CHECKPATH:
		case CHECKFSTYPE:
		case CHECKFSALIAS:
		case CHECKMODULE:
			return 1;
		default:
			return 0;
	}
}
#endif
/* during normal operation it is safe to keep strings without the final NULL */
#define ht_is_obj_string(X) 0 

/* generic add of ht element */
static struct ht_elem *internal_ht_tab_add(unsigned char type, 
		const void *obj, 
		int objlen,
		unsigned long mountflags,
		char *mtabline,
		struct service *service, 
		unsigned char trailingnumbers,
		confirmfun_t confirmfun,
		void *private_data) {
	struct ht_elem *new=ht_tab_alloc();
	assert(type < NCHECKS);
	if (new) {
		if ((new->obj=malloc(objlen+ht_is_obj_string(type))) != NULL) {
			struct ht_elem **hashhead;
			memcpy(new->obj,obj,objlen+ht_is_obj_string(type));
			new->objlen=objlen;
			new->type=type;
			new->mountflags=mountflags;
			new->mtabline=mtabline;
			new->tst=tst_timestamp();
			new->trailingnumbers=trailingnumbers;
			new->invalid=0;
			new->private_data=private_data;
			new->service=service;
			new->service_hte=NULL; /*lazy*/
			new->confirmfun=confirmfun;
			new->count=0;
			new->hashsum=hashsum(type,new->obj,new->objlen);
			if (objlen==0)
				hashhead=&ht_hash0[type];
			else
				hashhead=&ht_hash[hashmod(new->hashsum)]; 
			pthread_rwlock_wrlock(&ht_tab_rwlock);
			if (ht_head[type]) {
				new->next=ht_head[type]->next;
				new->prev=ht_head[type];
				new->next->prev=new;
				new->prev->next=new;
				ht_head[type]=new;
			} else 
				ht_head[type]=new->next=new->prev=new;
			if (*hashhead) 
				(*hashhead)->pprevhash=&(new->nexthash);
			new->nexthash=*hashhead;
			new->pprevhash=hashhead;
			*hashhead=new;
			pthread_rwlock_unlock(&ht_tab_rwlock);
			return new;
		} else {
			free(new);
			return NULL;
		}
	} else
		return NULL;
}

/* add a "normal" item to the hash table:
	 (tralingnumbers=1 causes scan to skip the check) */
struct ht_elem *ht_tab_add(unsigned char type,void *obj,int objlen,
		struct service *service, confirmfun_t confirmfun, void *private_data) {
	return internal_ht_tab_add(type, obj, objlen, 0, NULL,
			service, 1, confirmfun, private_data);
}

static int permanent_mount(const char *opts)
{
	char *match;
	if (opts==NULL)
		return 0;
	return (((match=strstr(opts,"permanent")) != NULL &&
			(match == opts || match[-1]==',') &&
			(match[9] == '\0' || match[9] == ',')) ||
			((match=strstr(opts,"perm")) != NULL &&
			 (match == opts || match[-1]==',') &&
			 (match[4] == '\0' || match[4] == ',')));
}
	
/* add a path to the hashtable (this creates an entry for the mounttab) */
struct ht_elem *ht_tab_pathadd(unsigned char type, const char *source,
		const char *path,
		const char *fstype,
		unsigned long mountflags,
		const char *mountopts,
		struct service *service, 
		unsigned char trailingnumbers,
		confirmfun_t confirmfun,
		void *private_data)
{
	char *mtabline;
	const char *addpath;
	struct ht_elem *rv;
	if (source) {
		char opts[PATH_MAX];
		opts[0]=0;
		if (mountflags & MS_REMOUNT)
			strncat(opts,"remount,",PATH_MAX);
		if (mountflags & MS_RDONLY)
			strncat(opts,"ro,",PATH_MAX);
		if (mountflags & MS_NOATIME)
			strncat(opts,"noatime,",PATH_MAX);
		if (mountflags & MS_NODEV)
			strncat(opts,"nodev,",PATH_MAX);
		if (mountflags & MS_NOEXEC)
			strncat(opts,"noexec,",PATH_MAX);
		if (mountflags & MS_NOSUID)
			strncat(opts,"nosuid,",PATH_MAX);
		if (mountflags & MS_SYNCHRONOUS)
			strncat(opts,"sync,",PATH_MAX);
		if (mountopts && *mountopts)
			strncat(opts,mountopts,PATH_MAX);
		else if (*opts)
			opts[strlen(opts)-1]=0;
		else
			strncpy(opts,"rw",PATH_MAX);
		asprintf(&mtabline,"%s%s %s %s %s 0 %lld",
				(confirmfun==NEGATIVE_MOUNT)?"-":"",
				source,path,fstype,opts,get_epoch());
	} else
		mtabline=NULL;
	if (path[1]=='\0' && path[0]=='/')
		addpath="";
	else
		addpath=path;
	rv=internal_ht_tab_add(type, addpath, strlen(addpath), 
			mountflags, mtabline,
			service, trailingnumbers, confirmfun, private_data);
	if (permanent_mount(mountopts))
		rv->count++;
	if (rv == NULL && mtabline != NULL)
		free(mtabline);
	return rv;
}

/* delete an element from the hash table */
static void ht_tab_del_locked(struct ht_elem *ht) {
	int type=ht->type;
	if (ht == ht_head[type]) {
		if (ht->next == ht)
			ht_head[type]=NULL;
		else
			ht_head[type] = ht->prev;
	}
	ht->prev->next=ht->next;
	ht->next->prev=ht->prev;
	*(ht->pprevhash)=ht->nexthash;
	if (ht->nexthash)
		ht->nexthash->pprevhash=ht->pprevhash;
	ht_tab_free(ht);
}

/* invalidate: the hash table element is not searchable.
	 It will be deleted later */
void ht_tab_invalidate(struct ht_elem *ht) {
	if (ht)
		ht->invalid=1;
}

/* delete an element (using a write lock) */
int ht_tab_del(struct ht_elem *ht) {
	if (ht) {
		if (ht->invalid==0 && ht->service && ht->service->destructor)
			ht->service->destructor(ht->type,ht);
		pthread_rwlock_wrlock(&ht_tab_rwlock);
		ht_tab_del_locked(ht);
		pthread_rwlock_unlock(&ht_tab_rwlock);
		return 0;
	} else
		return -ENOENT;
}

/* searching API */
struct ht_elem *ht_check(int type, void *arg, struct stat64 *st, int setepoch)
{
	struct ht_elem *hte;
	int size=0;
	switch (type) {
		case CHECKPATH:
			hte=ht_tab_pathsearch(type, arg, um_x_gettst(), 0);
			if (st) {
				if (__builtin_expect(S_ISCHR(st->st_mode),0)) {
					struct ht_elem *devhte;
					devhte=ht_tab_search(CHECKCHRDEVICE, &st->st_rdev, 
							sizeof(dev_t), um_x_gettst(),0);
					if (devhte != NULL)
						hte=devhte;
				} else if (__builtin_expect(S_ISBLK(st->st_mode),0)) {
					struct ht_elem *devhte;
					devhte=ht_tab_search(CHECKBLKDEVICE, &st->st_rdev,
							sizeof(dev_t), um_x_gettst(),0);
					if (devhte != NULL)
						hte=devhte;
				}
			}
			break;
		case CHECKPATHEXACT:
			hte=ht_tab_pathsearch(CHECKPATH, arg, um_x_gettst(), 1);
			break;
		case CHECKCHRDEVICE:
		case CHECKBLKDEVICE:
			size++;
		case CHECKSOCKET:
		case CHECKSC:
			size++;
			hte=ht_tab_search(type, arg, size*sizeof(int), um_x_gettst(),0);
			break;
		case CHECKFSALIAS:
		case CHECKMODULE:
			hte=ht_tab_search(type, arg, 0, um_x_gettst(), 1);
			break;
		case CHECKFSTYPE:
			hte=ht_tab_search(CHECKMODULE, arg, 0, um_x_gettst(), 0);
			break;
		case CHECKBINFMT:
			hte=ht_tab_binfmtsearch(type, arg, um_x_gettst(), 0);
			break;
		default:
			hte=NULL;
	}
	if (hte && setepoch)
		um_setnestepoch(hte->tst.epoch);
	return hte;
}

static long errnosys()
{
	errno=ENOSYS;
	return -1;
}

int isnosys(sysfun f)
{
	return (f==errnosys);
}

/* utility functions for sctab wrappers */
sysfun ht_syscall(struct ht_elem *hte, int scno)
{
	if (hte) {
		struct service *s=hte->service;
		assert( s != NULL);
		return (s->um_syscall[scno] == NULL) ? errnosys : s->um_syscall[scno];
	} else
		return NULL;
}

sysfun ht_socketcall(struct ht_elem *hte, int scno)
{
	if (hte) {
		struct service *s=hte->service;
		assert(s != NULL);
		return (s->um_socket[scno] == NULL) ? errnosys : s->um_socket[scno];
	} else
		return NULL;
}

sysfun ht_virsyscall(struct ht_elem *hte, int scno)
{
	if (hte) {
		struct service *s=hte->service;
		assert( s != NULL );
		return (s->um_virsc == NULL || s->um_virsc[scno] == NULL)
			? errnosys : s->um_virsc[scno];
	} else
		return NULL;
}

sysfun ht_ioctlparms(struct ht_elem *hte)
{
	struct service *s=hte->service;
	assert( s != NULL );
	return (s->ioctlparms);
}

sysfun ht_event_subscribe(struct ht_elem *hte)
{
	struct service *s=hte->service;
	assert( s != NULL );
	return (s->event_subscribe);
}

/* reverse scan of hash table elements, useful to close all files  */
static void forall_ht_terminate(unsigned char type) {
	pthread_rwlock_rdlock(&ht_tab_rwlock);
	if (ht_head[type]) {
		struct ht_elem *scanht=ht_head[type];
		struct ht_elem *next=scanht;
		do {
			scanht=next;
			if (scanht->invalid == 0) {
				if (scanht->service != NULL && scanht->service->destructor != NULL)
					scanht->service->destructor(type, scanht);
			}
			next=scanht->prev;
			//printk("SCAN %p %p %s\n",next,scanht,scanht->obj);
		} while (ht_head[type] != NULL && next != ht_head[type]);
	}
	pthread_rwlock_unlock(&ht_tab_rwlock);
}

/* forward scan of all valid ht elems */
void forall_ht_tab_do(unsigned char type,
		void (*fun)(struct ht_elem *ht, void *arg),
		void *arg) {
	pthread_rwlock_rdlock(&ht_tab_rwlock);
	if (ht_head[type]) {
		struct ht_elem *scanht=ht_head[type];
		do {
			scanht=scanht->next;
			if (scanht->invalid == 0) {
				if (tst_matchingepoch(&(scanht->tst)) > 0)
					fun(scanht, arg);
			}
			//printk("SCAN %p %s\n",scanht,scanht->obj);
		} while (ht_head[type] != NULL && scanht != ht_head[type]);
	}
	pthread_rwlock_unlock(&ht_tab_rwlock);
}

/* mount table creation */
static void ht_tab_getmtab_add(struct ht_elem *ht, void *arg) {
	FILE *f=arg;
	if (ht->mtabline) 
		fprintf(f,"%s\n",ht->mtabline);
}

void ht_tab_getmtab(FILE *f) {
	if (f) 
		forall_ht_tab_do(CHECKPATH,ht_tab_getmtab_add,f);
}

void *ht_get_private_data(struct ht_elem *hte)
{
	if (hte)
		return hte->private_data;
	else
		return NULL;
}

void ht_set_private_data(struct ht_elem *hte,void *private_data)
{
	if (hte)
		hte->private_data=private_data;
}

struct ht_elem *ht_search(int type, void *arg, 
		int objlen, struct service *service)
{
	struct ht_elem *hte=ht_check(type,arg,NULL,0);
	if (hte &&
			((objlen > 0 && objlen != hte->objlen) ||
			 (service != NULL && service != hte->service)))
				return NULL;
	return hte;
}

void ht_renew(struct ht_elem *hte)
{
	if (hte)
		hte->tst=tst_timestamp();
}

char *ht_get_servicename(struct ht_elem *hte)
{
	if (hte && hte->service)
		return hte->service->name;
	else
		return NULL;
}

struct service *ht_get_service(struct ht_elem *hte)
{
	if (hte)
		return hte->service;
	else
		return NULL;
}

unsigned long ht_get_mountflags(struct ht_elem *hte)
{
	if (hte)
		return hte->mountflags;
	else
		return NULL;
}

epoch_t ht_get_epoch(struct ht_elem *hte)
{
	/* this check could be eliminated:
		 this function is always called with hte != NULL */
	if (hte)
		return hte->tst.epoch;
	else
		return 0;
}

void ht_count_plus1(struct ht_elem *hte)
{
	if (hte->service_hte == NULL) {
		if (hte->service)
			/*ht_check(CHECKMODULE,hte->service->name,NULL,0);*/
			hte->service_hte=ht_tab_search(CHECKMODULE, hte->service->name, 0, 
					um_x_gettst(), 1);
	}
	if (hte->service_hte) hte->service_hte->count++;
	hte->count++;
}

void ht_count_minus1(struct ht_elem *hte)
{ 
	if (hte->service_hte) hte->service_hte->count--;
	hte->count--;
}

int ht_get_count(struct ht_elem *hte)
{
	return hte->count;
}

void ht_terminate(void)
{
	forall_ht_terminate(CHECKPATH);
}

