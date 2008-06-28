#ifndef _MNTTAB_H
#define _MNTTAB_H
#include "treepoch.h"
#include "services.h"

struct ht_elem;
typedef int (* checkfun_t)(int type, void *arg, struct ht_elem *ht);
struct ht_elem {
	void *obj;
	char *mtabline;
	struct timestamp tst;
	unsigned char type;
	service_t service;
	void *private_data;
	int objlen;
	long hashsum;
	checkfun_t checkfun;
	struct ht_elem *prev,*next,**pprevhash,*nexthash;
};

int ht_tab_mntadd(const char *source,
		const char *path,
		const char *type,
		const char *flags,
		struct timestamp *tst, unsigned char service, 
		checkfun_t checkfun,
		void *private_data);

int ht_tab_add(unsigned char type,void *obj,int objlen,
		struct timestamp *tst, unsigned char service, 
		checkfun_t checkfun,
		void *private_data);

struct ht_elem *ht_tab_mntsearch(char *path, 
	struct timestamp *tst, int exact);

struct ht_elem *ht_tab_search(unsigned char type, void *obj, int objlen,
	struct timestamp *tst);

int ht_tab_del(struct ht_elem *mp); 

void ht_tab_getmtab(struct timestamp *tst,char **buf, size_t *size);

void forall_ht_tab_do(unsigned char type, 
	struct timestamp *tst, service_t service,
	void (*fun)(struct ht_elem *mp, void *arg),
	void *arg);

#endif
