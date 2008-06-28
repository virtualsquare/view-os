#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <pthread.h>
#include "hashtab.h"

#define MNTTAB_HASH_SIZE 512
#define MNTTAB_HASH_MASK (MNTTAB_HASH_SIZE-1)

static struct ht_elem *ht_hash[MNTTAB_HASH_SIZE]; 
static struct ht_elem *ht_head;
//static struct ht_elem *ht_free;
static pthread_mutex_t ht_tab_mutex = PTHREAD_MUTEX_INITIALIZER;

static inline struct ht_elem *ht_tab_alloc() {
	 return (struct ht_elem *)malloc(sizeof (struct ht_elem));
}

static void ht_tab_free(struct ht_elem *ht) {
	free(ht);
}

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

static inline int cutdots(char *path)
{
	int l=strlen(path);
	l--;
	if (path[l]=='.') {
		l--;
		if(path[l]=='/') {
			if (l!=0) path[l]=0; else path[l+1]=0;
		} else if (path[l]=='.') {
			l--;
			if(path[l]=='/') {
				while(l>0) {
					l--;
					if (path[l]=='/')
						break;
				}
				if(path[l]=='/') {
					if (l==0) l++;
					path[l]=0; 
				}
			}
		}
	} else
		l++;
	return l;
}

static struct ht_elem *ht_tab_internal_search(unsigned char type, void *hashobj, void *obj, int objlen,
		  struct timestamp *tst)
{
	struct ht_elem *rv=NULL;
	char *objc=hashobj;
	epoch_t maxepoch=0;
	long sum=0;
	long hash;
	struct ht_elem *ht;
	sum=hashsum(type, objc, objlen);
	hash=hashmod(sum);
	pthread_mutex_lock(&ht_tab_mutex);
	ht=ht_hash[hash];
	while (ht != NULL) {
		epoch_t e;
		if (type==ht->type &&
				sum==ht->hashsum &&
				(ht->objlen >= objlen) &&
				memcmp(hashobj,ht->obj,objlen)==0 &&
				(ht->checkfun==NULL || ht->checkfun(type,obj,ht)) && 
				(tst->epoch > ht->tst.epoch) &&
				(e=tst_matchingepoch(&(ht->tst))) > maxepoch) {
			maxepoch=e;
			rv=ht;
		}
		ht=ht->nexthash;
	}
	pthread_mutex_unlock(&ht_tab_mutex);
	return rv;
}

struct ht_elem *ht_tab_search(unsigned char type, void *obj, int objlen,
		  struct timestamp *tst)
{
	return ht_tab_internal_search(type,obj,obj,objlen,tst);
}

struct ht_elem *ht_tab_pathsearch(unsigned char type, char *path, struct timestamp *tst, int exact) {
	int len=cutdots(path);
	struct ht_elem *rv=ht_tab_internal_search(type,path,path,len,tst);
#if 0
	/* debug printf */
	if (rv)
		fprint2("+++ ht_tab_pathsearch %s %x %lld %lld\n",path,rv->service,tst->epoch,rv->tst.epoch);
	else
		fprint2("ht_tab_pathsearch %s %lld NONE\n",path,tst->epoch);
#endif
	if (exact && rv && rv->objlen != len)
		return NULL;
	else
		return rv;
}

struct ht_elem *ht_tab_binfmtsearch(unsigned char type, struct binfmt_req *req,
		  struct timestamp *tst)
{
	return ht_tab_internal_search(type,req->path,req,strlen(req->path),tst);
}

static int internal_ht_tab_add(unsigned char type, 
		const void *obj, 
		int objlen,
		char *mtabline,
		struct timestamp *tst, unsigned char service, 
		checkfun_t checkfun,
		void *private_data) {
	long hashv;
	struct ht_elem *new=ht_tab_alloc();
	if (new) {
		if ((new->obj=malloc(objlen)) != NULL) {
			memcpy(new->obj,obj,objlen);
			new->objlen=objlen;
			new->type=type;
			new->mtabline=mtabline;
			new->tst=*tst;
			new->private_data=private_data;
			new->service=service;
			new->checkfun=checkfun;
			hashv=hashmod(new->hashsum=hashsum(type,new->obj,new->objlen));
			pthread_mutex_lock(&ht_tab_mutex);
			if (ht_head) {
				new->next=ht_head->next;
				new->prev=ht_head;
				new->next->prev=new;
				new->prev->next=new;
				ht_head=new;
			} else 
				ht_head=new->next=new->prev=new;
			if (ht_hash[hashv]) 
				ht_hash[hashv]->pprevhash=&(new->nexthash);
			new->nexthash=ht_hash[hashv];
			new->pprevhash=&ht_hash[hashv];
			ht_hash[hashv]=new;
			pthread_mutex_unlock(&ht_tab_mutex);
			return 0;
		} else {
			free(new);
			return -ENOMEM;
		}
	} else
		return -ENOMEM;
}

int ht_tab_add(unsigned char type,void *obj,int objlen,
		    struct timestamp *tst, unsigned char service, 
				checkfun_t checkfun,
				void *private_data) {
	return internal_ht_tab_add(type, obj, objlen, NULL,
			tst, service, checkfun, private_data);
}

int ht_tab_pathadd(unsigned char type, const char *source,
		const char *path,
		const char *fstype,
		const char *flags,
		struct timestamp *tst, unsigned char service, 
		checkfun_t checkfun,
		void *private_data)
{
	char *mtabline;
	int rv;
	if (source)
		asprintf(&mtabline,"%s %s %s %s 0 %lld",source,path,fstype,flags,tst->epoch);
	else
		mtabline=NULL;
	if (path[1]=='\0' && path[0]=='/')
		rv=internal_ht_tab_add(type, "", 0, mtabline,
				tst, service, checkfun, private_data);
	else
		rv=internal_ht_tab_add(type, path, strlen(path), mtabline,
				tst, service, checkfun, private_data);
	if (rv<0)
		free(mtabline);
	return rv;
}

int ht_tab_del(struct ht_elem *ht) {
	if (ht) {
		pthread_mutex_lock(&ht_tab_mutex);
		if (ht == ht_head) {
			if (ht->next == ht)
				ht_head=NULL;
			else
				ht_head = ht->prev;
		}
		ht->prev->next=ht->next;
		ht->next->prev=ht->prev;
		*(ht->pprevhash)=ht->nexthash;
		if (ht->nexthash)
			ht->nexthash->pprevhash=ht->pprevhash;
		free(ht->obj);
		if (ht->mtabline)
			free(ht->mtabline);
		ht_tab_free(ht);
		pthread_mutex_unlock(&ht_tab_mutex);
		return 0;
	} else
		return -ENOENT;
}

void forall_ht_tab_do(unsigned char type, 
		struct timestamp *tst, unsigned char service,
		void (*fun)(struct ht_elem *ht, void *arg), 
		void *arg) {
	int what=(tst == NULL) | 0x2 * (service != 0);
	pthread_mutex_lock(&ht_tab_mutex);
	if (ht_head) {
		struct ht_elem *scanht=ht_head;
		do {
			scanht=scanht->next;
			if (scanht->type == type) {
				switch (what) {
					case 0 : fun(scanht, arg); break;
					case 1 : if (tst_matchingepoch(tst) > 0)
										 fun(scanht, arg);
									 break;
					case 2 : if (scanht->service == service)
										 fun(scanht, arg);
									 break;
					case 3 : if (tst_matchingepoch(tst) > 0 &&
											 scanht->service == service)
										 fun(scanht, arg);
									 break;
				} 
			}
		} while (scanht != ht_head);
  }
	pthread_mutex_unlock(&ht_tab_mutex);
}

static void ht_tab_getmtab_add(struct ht_elem *ht, void *arg) {
	FILE *f=arg;
	if (ht->mtabline) 
		fprintf(f,"%s\n",ht->mtabline);
}

void ht_tab_getmtab(struct timestamp *tst,char **buf, size_t *size) {
	FILE *f=open_memstream(buf,size);
	if (f) 
		forall_ht_tab_do(CHECKPATH,tst,0,ht_tab_getmtab_add,f);
	fclose(f);
}

