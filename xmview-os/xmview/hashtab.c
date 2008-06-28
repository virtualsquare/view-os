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

static inline long hashsum (const char *c,int len) {
	long sum=0;
	int i;
	for (i=0;i<len;i++,c++)
		sum=hashadd(sum,*c);
	return sum;
}

static int cutdots(char *path)
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

struct ht_elem *ht_tab_mntsearch(char *path, struct timestamp *tst, int exact) {
	struct ht_elem *rv=NULL;
	epoch_t maxepoch=0;
	long sum=0;
	int len=cutdots(path);
	int i;
	pthread_mutex_lock(&ht_tab_mutex);
	for (i=0;i<=len;i++) {
		if (path[i] == '/' || path[i]== '\0') {
			epoch_t e;
			long hash=hashmod(sum);
			//printf("search %s %d %ld\n",path,i,hash);
			struct ht_elem *ht=ht_hash[hash];
			while (ht != NULL) {
				char *htpath=ht->obj;
				if (ht->type==CHECKPATH && 
						sum==ht->hashsum &&
						(ht->objlen == i) &&
						strncmp(path,htpath,i)==0 &&
						(ht->checkfun==NULL || ht->checkfun(CHECKPATH,ht->obj,ht)) && 
						(tst->epoch > ht->tst.epoch) &&
						(e=tst_matchingepoch(&(ht->tst))) > maxepoch) {
					//printf("UPDATED max %s %lld\n",ht->path,ht->tst.epoch);
					maxepoch=e;
					rv=ht;
				}
				ht=ht->nexthash;
			}
		}
		sum=hashadd(sum,path[i]);
	}
	pthread_mutex_unlock(&ht_tab_mutex);
	if (exact && (!rv || strncmp(path,rv->obj,len) != 0))
		return NULL;
	else
		return rv;
}

struct ht_elem *ht_tab_search(unsigned char type, void *obj, int objlen,
		  struct timestamp *tst)
{
	struct ht_elem *rv=NULL;
	char *objc=obj;
	epoch_t maxepoch=0;
	long sum=0;
	long hash;
	struct ht_elem *ht;
	int i;
	for (i=0;i<=objlen;i++) 
		sum=hashadd(sum,objc[i]);
	hash=hashmod(sum);
	pthread_mutex_lock(&ht_tab_mutex);
	ht=ht_hash[hash];
	while (ht != NULL) {
		epoch_t e;
		if (type==ht->type &&
				sum==ht->hashsum &&
				(ht->objlen == objlen) &&
				memcmp(obj,ht->obj,objlen)==0 &&
				(ht->checkfun==NULL || ht->checkfun(CHECKPATH,ht->obj,ht)) && 
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
			hashv=hashmod(new->hashsum=hashsum(new->obj,new->objlen));
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

int ht_tab_mntadd(const char *source,
		const char *path,
		const char *type,
		const char *flags,
		struct timestamp *tst, unsigned char service, 
		checkfun_t checkfun,
		void *private_data)
{
	char *mtabline;
	int rv;
	asprintf(&mtabline,"%s %s %s %s 0 %lld",source,path,type,flags,tst->epoch);
	if (path[1]=='\0' && path[0]=='/')
		rv=internal_ht_tab_add(CHECKPATH, "", 0, mtabline,
				tst, service, checkfun, private_data);
	else
		rv=internal_ht_tab_add(CHECKPATH, path, strlen(path), mtabline,
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

