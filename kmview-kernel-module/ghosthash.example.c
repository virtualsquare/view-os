/*
 * Example of ghosthash64 library.
 * when DEBUG is set: this is a stand-alone program providing
 * an interactive interface to test the functions:
 * a->add d->delete f->find m->match q->quit
 * e.g.
 *           a /short
 *           a /this/is/a/long/path
 *           f /short
 *           m /short/xxx
 *           f /short/xxx
 *           d /this/is/a/long/path
 *           q q
 * This sequence adds /short and /this/is/a/long/path, search for /short
 * and succeeds is the match /short/xxx ('match' succeeds if the table
 * include a leading substring of the path). The sequence then fails when
 * tries to find /short/xxx, deletes /this/is/a/long/path and quits.
 * 
 * Copyright (C) 2010 Renzo Davoli (renzo@cs.unibo.it)
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  Due to this file being licensed under the GPL there is controversy over
 *  whether this permits you to write a module that #includes this file
 *  without placing your module under the GPL.  Please consult a lawyer for
 *  advice before doing this.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define GH_SIZE 64
#define GH_TERMINATE 255
#define GH_DUMMY 254

#define DEBUG

struct ghosthash64 {
	unsigned char deltalen[GH_SIZE];
	unsigned int hash[GH_SIZE];
};

/* hash function */
/* hash sum and mod are separate functions:
	 hash sums are used to quicly elimiate false positives,
	 intermediate results can be completed during the scan */
static inline unsigned int hashadd (long prevhash, char c) {
	return prevhash ^ ((prevhash << 5) + (prevhash >> 2) + c);
}

static inline unsigned int hashsum (int sum,const char *path,int len) {
	int i;
	for (i=0;i<len;i++,path++)
		sum=hashadd(sum,*path);
	return sum;
}

void ghosthash_new(struct ghosthash64 *gh)
{
	gh->deltalen[0] = GH_TERMINATE;
}

#ifdef DEBUG
printarray(char *s,int n,short *tmplen, unsigned int *tmphash) {
	int i;
	printf("%s->",s);
	for (i=0;i<n;i++) 
		printf("%d.%x:",tmplen[i],tmphash[i]);
	printf("\n");
}
#endif

static int gh2array(struct ghosthash64 *gh, 
		short *tmplen, unsigned int *tmphash)
{
	int i,ntmp;
	short scanlen;
	for (i=0,ntmp=0,scanlen=0;i<GH_SIZE &&
			gh->deltalen[i] != GH_TERMINATE;i++) {
		scanlen += gh->deltalen[i];
		if (gh->deltalen[i] != GH_DUMMY) {
			tmplen[ntmp] = scanlen;
			tmphash[ntmp] = gh->hash[i];
			ntmp++;
		}
	}
#ifdef DEBUG
	printarray("gh2array",ntmp,tmplen,tmphash);
#endif
	return ntmp;
}

static int array2gh(short *tmplen,unsigned int *tmphash,int ntmp,
		struct ghosthash64 *gh)
{
	int ngh;
	if (ntmp > 0) {
		ngh=(tmplen[0]/GH_DUMMY)+1;
		int i,j;
		short scanlen;
#ifdef DEBUG
		printarray("array2gh",ntmp,tmplen,tmphash);
#endif
		for(i=1;i<ntmp;i++)
			ngh+=((tmplen[i]-tmplen[i-1])/GH_DUMMY)+1;
		if (ngh > GH_SIZE)
			return -ENOMEM;
		i=j=scanlen=0;
		while (i<ntmp) {
			if (tmplen[i] - scanlen >= GH_DUMMY) {
				gh->deltalen[j] = GH_DUMMY;
				scanlen += GH_DUMMY;
				gh->hash[j] = -1;
				j++;
			} else {
				gh->deltalen[j] = tmplen[i] - scanlen;
				gh->hash[j] = tmphash[i];
				scanlen=tmplen[i];
				i++;
				j++;
			}
		}
	} else 
		ngh=0;
	if (ngh < GH_SIZE)
		gh->deltalen[ngh] = GH_TERMINATE;
	return ngh;
}

int ghosthash_add(struct ghosthash64 *gh,char *path)
{
	unsigned short ngh;
	unsigned short len=strlen(path);
	unsigned short tmplen[GH_SIZE];
	unsigned int tmphash[GH_SIZE];
	unsigned short ntmp=gh2array(gh,tmplen,tmphash);
	int pos;
	if (ntmp >= GH_SIZE)
		return -ENOMEM;
	for (pos=0;pos<ntmp && tmplen[pos]<len;pos++)
		;
	memmove(&tmplen[pos+1],&tmplen[pos],(ntmp-pos)*sizeof(short));
	memmove(&tmphash[pos+1],&tmphash[pos],(ntmp-pos)*sizeof(int));
	ntmp++;
	tmplen[pos]=len;
	tmphash[pos]=hashsum(0,path,len);
	return array2gh(tmplen, tmphash, ntmp, gh);
}

int ghosthash_del(struct ghosthash64 *gh,char *path)
{
	unsigned short ngh;
	unsigned short len=strlen(path);
	unsigned int hash=hashsum(0,path,len);
	unsigned short tmplen[GH_SIZE];
	unsigned int tmphash[GH_SIZE];
	unsigned short ntmp=gh2array(gh,tmplen,tmphash);
	int pos;
	for (pos=0;pos<ntmp && tmplen[pos]<=len && hash!=tmphash[pos];pos++)
		;
	if (pos<ntmp && len == tmplen[pos] &&  hash == tmphash[pos]) {
		memmove(&tmplen[pos],&tmplen[pos+1],(ntmp-pos-1)*sizeof(short));
		memmove(&tmphash[pos],&tmphash[pos+1],(ntmp-pos-1)*sizeof(int));
		ntmp--;
		return array2gh(tmplen, tmphash, ntmp, gh);
	} else
		return -ENOENT;
}

int ghosthash_search(struct ghosthash64 *gh,char *path)
{
	unsigned short len=strlen(path);
	unsigned int hash=hashsum(0,path,len);
	unsigned short scanlen;
	int i;
	for (i=0,scanlen=gh->deltalen[0]; 
			i<GH_SIZE && gh->deltalen[i] < GH_TERMINATE &&
			scanlen<=len && hash != gh->hash[i];
			scanlen+=gh->deltalen[++i])
		;
	if (scanlen==len && hash == gh->hash[i])
		return 0;
	else
		return -ENOENT;
}

int ghosthash_match(struct ghosthash64 *gh,char *path)
{
	unsigned short len=strlen(path);
	unsigned short scanlen,pos;
	unsigned int scanhash;
	int i;
	for (i=0,scanhash=0,scanlen=pos=0;
			i<GH_SIZE && gh->deltalen[i] < GH_TERMINATE && len>=0;
			i++) {
		if (gh->deltalen[i] > 0) {
			scanhash=hashsum(scanhash,path,gh->deltalen[i]);
			path+=gh->deltalen[i];
			len -=gh->deltalen[i];
		}
#ifdef DEBUG
		printf("match %d %x<>%x\n",len,scanhash,gh->hash[i]);
#endif
		if (len >= 0 && scanhash == gh->hash[i])
			return len;
	}
	return -ENOENT;
}

#ifdef DEBUG
void printgh(struct ghosthash64 *gh)
{
	int i;
	printf("->");
	for (i=0; i<GH_SIZE && gh->deltalen[i] < GH_TERMINATE; i++)
		printf("%d.%u.%x:",i,gh->deltalen[i],gh->hash[i]);
	printf("\n");
}

main()
{
	int rv;
	char path[4096];
	char cmd[10];
	struct ghosthash64 ggh;
	ghosthash_new(&ggh);
	while (1) {
		printgh(&ggh);
		scanf("%s %s",cmd,path);
		switch(*cmd) {
			case 'a': rv=ghosthash_add(&ggh,path);
								break;
			case 'd': rv=ghosthash_del(&ggh,path);
								break;
			case 'f': rv=ghosthash_search(&ggh,path);
								break;
			case 'm': rv=ghosthash_match(&ggh,path);
								break;
			case 'q': exit(0);
								break;
		}
		printf("rv=%x\n",rv);
	}
}
#endif
