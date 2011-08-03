/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   um_mmap: MMAP implementation
 *   
 *   Copyright 2006 Renzo Davoli University of Bologna - Italy
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation version 2 of the License. 
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
 *
 */   
#include <assert.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <linux/unistd.h>
#include <config.h>
#include "defs.h"
#include "gdebug.h"
#include "umproc.h"
#include "hashtab.h"
#include "um_services.h"
#include "sctab.h"
#include "scmap.h"
#include "utils.h"
#include "uid16to32.h"

#ifdef _UM_MMAP

/* one entry per chunk on the mmap secret file */
struct mmap_sf_entry {
	char *path;
	epoch_t epoch;
	time_t mtime;
	struct ht_elem *hte;
	unsigned long prot;
	unsigned long length;
	unsigned long pgoffset;
	unsigned long pgsize;
	unsigned long counter;
	/* lastuse: each use set the MSB, shift right as time flows
	 * (now each time a new file is needed), when 0 is the chunk is considered
	 * useless */
	unsigned long lastuse; 
	struct mmap_sf_entry *next;
};

/* this is the global table used to manage the chunks */
/* the global table is sorted on chunk starting address */
static struct mmap_sf_entry *mmap_sf_head;

/* this is an entry of the *process* mmap table */
/* elements in the process mmap table are unordered */
struct pcb_mmap_entry {
	long start;
	long len;
	struct mmap_sf_entry *sf_entry;
	struct pcb_mmap_entry *next;
};

/* create a new element in the *process* mmap table */
static struct pcb_mmap_entry *pcb_mmap_add(
		struct pcb_mmap_entry *head, unsigned long start, unsigned long len, 
		struct mmap_sf_entry *sf_entry)
{
	struct pcb_mmap_entry *new=malloc(sizeof (struct pcb_mmap_entry));
	//printk("pcb_mmap_add %ld %ld\n",start,len);
	new->start=start;
	new->len=len;
	new->sf_entry=sf_entry;
	new->next=head;
	return new;
}

#if 0
static struct mmap_sf_entry *pcb_mmap_sfsearch(
		struct pcb_mmap_entry *head, unsigned long start, unsigned long len)
{
	while (head) {
		if (head->start == start && head->len == len)
			return head->sf_entry;
		head=head->next;
	}
	return NULL;
}
#endif

static void store_mmap_secret(struct ht_elem *hte,const char *to, unsigned long pgoffset, unsigned long length);
static inline void mmap_sf_del(struct mmap_sf_entry *sf_entry, int error)
{
	sf_entry->counter--;
	if (!error && sf_entry->counter == 0 &&
			sf_entry->prot & PROT_WRITE) {
		store_mmap_secret(sf_entry->hte,sf_entry->path, sf_entry->pgoffset, sf_entry->length);
	}
}

/* delete the first element in the *process* mmap list */
static void pcb_mmap_deletehead(struct pcb_mmap_entry **head,int error)
{
	struct pcb_mmap_entry *this=*head;
	if (this != NULL) {
		mmap_sf_del(this->sf_entry,error);
		*head=this->next; 
		free(this);
	}
}

/* sfsearch: find a mmap chunk in a process mmap table (and move it to head, 
 * to support the deletehead if necessary) */
static int pcb_mmap_sfsearch_n_movetohead(
		struct pcb_mmap_entry **head, unsigned long start, unsigned long len)
{
	struct pcb_mmap_entry **scan=head;
	struct pcb_mmap_entry *this;
	while ((this = *scan) != NULL) {
		//printk("CMP! %p %p %ld %ld\n",this->start,start,this->len,len);
		if (this->start == start && this->len == len) {
			if (*scan != *head) {
				/* it is not already the first one*/
				*scan=this->next; /* delete from its position */
				this->next=*head; /* join the old queue */
				*head=this; /* the new head is this */
			}
			return 1;
		}
		scan=&(this->next);
	}
	return 0;
}

#if 0
static void pcb_mmap_sfsearch_n_delete(
		struct pcb_mmap_entry **head, unsigned long start, unsigned long len)
{
	struct pcb_mmap_entry *this;
	while ((this = *head) != NULL) {
		if (this->start == start && this->len == len) {
			this->sf_entry->counter--;
			*head=this->next;
			free(this);
		}
		head=&(this->next);
	}
}
#endif

/* when a process terminates, all the mmap chunks used by the process
 * have one less refernce.
 * unused chunks (counter==0) will be reused by the insertion.
 * lazy: if the mmap-ed file is needed again (and unchanged) the previous
 * chunk is re-used */
void um_mmap_recdelproc(struct pcb_mmap_entry *head)
{
	if (head) {
		head->sf_entry->counter--;
		um_mmap_recdelproc(head->next);
		free(head);
	}
}

void um_mmap_addproc(struct pcb *pc,int flags,int npcbflag)
{
	if (!npcbflag) 
		pc->um_mmap=NULL;
}

void um_mmap_delproc(struct pcb *pc,int flags,int npcbflag)
{
	if (!npcbflag) {
		um_mmap_recdelproc(pc->um_mmap);
	}
}

/* search for a mmap chunk (given path, epoch, and mtime of the file)
 * XXX why there is not the "bitstring" of the file? */
static struct mmap_sf_entry *mmap_sf_find (
		char *path, epoch_t epoch, time_t mtime, unsigned long pgsize)
{
	struct mmap_sf_entry *scan=mmap_sf_head;
	while (scan) {
		/* integers are faster to compare, it is better to test them first */
		//printk("scan find %s %lld %d %d %x\n",scan->path,scan->epoch,scan->mtime,scan->pgsize,  scan->lastuse);
		if (epoch == scan->epoch &&
				mtime == scan->mtime &&
				pgsize <= scan->pgsize &&
				(strcmp(path,scan->path) == 0)) {
			scan->lastuse |= 1 << (sizeof (unsigned long) * 4 - 1);
			return scan;
		}
		scan = scan->next;
	}
	return NULL;
}

/* LRU approximation: lastuse is a bitstring, when a process uses a chunk
 * the MSB is set, lastuse is right shifted at each attempt to load a
 * mmap-ed file */
static void mmap_compact()
{
	struct mmap_sf_entry *scan=mmap_sf_head;
	/* mark the empty - reusable parts of the file */
	while (scan) {
		/* unused for a long time... free the area */
		if (scan->path && scan->counter == 0 && scan->lastuse == 0) {
			free(scan->path);
			scan->path=NULL;
			scan->epoch=0;
		} else 
			scan->lastuse >>= 1;
		scan = scan->next;
	}
	/* second traversal: compact the free space*/
	scan=mmap_sf_head;
	while (scan) {
		/* this is unused, and the next one is also unused */
		if (!(scan->path) && (scan->next) && !(scan->next->path)) {
			struct mmap_sf_entry *victim=scan->next;
			scan->pgsize += victim->pgsize;
			scan->next = victim->next;
			free(victim);
		} else
			scan = scan->next;
	}
}

/* allocate a free space on the secret file*/
static struct mmap_sf_entry *mmap_sf_allocate (
		char *path, epoch_t epoch, time_t mtime, unsigned long pgsize,
		unsigned long prot,struct ht_elem *hte,unsigned long length)
{
	struct mmap_sf_entry *scan=mmap_sf_head;
	mmap_compact();
	if (!scan) { /* first time! empty list */
		struct mmap_sf_entry *new=malloc(sizeof (struct mmap_sf_entry));
		new->path=NULL;
		new->pgoffset=0;
		new->pgsize=pgsize;
		new->next=NULL;
		mmap_sf_head = scan = new;
	}
	while (scan) {
		/* first fit */
		if (scan->path == NULL && scan->pgsize >= pgsize) {
			if (scan->pgsize > pgsize) {
				/* split the empty space */
				struct mmap_sf_entry *new=malloc(sizeof (struct mmap_sf_entry));
				new->path=NULL;
				new->epoch=0;
				new->mtime=0;
				new->pgoffset=scan->pgoffset+pgsize;
				new->pgsize=scan->pgsize-pgsize;
				new->counter=0;
				new->lastuse=1 << (sizeof(unsigned long) * 4 - 1);
				scan->pgsize=pgsize;
				new->next=scan->next;
				scan->next=new;
			}
			scan->path=strdup(path);
			scan->prot=prot;
			scan->hte=hte;
			scan->length=length;
			scan->epoch=epoch;
			scan->mtime=mtime;
			scan->counter=scan->lastuse=0;
			return scan;
		}
		/* no reusable chunks, allocate new space on the file */
		if (scan->next == NULL) {
			/* the next and last element is unused: resize it */
			if (scan->path == NULL)
				scan->pgsize=pgsize;
			else {
			/* the next/last is used, create an empty element of the right size 
			 * after it */
				struct mmap_sf_entry *new=malloc(sizeof (struct mmap_sf_entry));
				new->path=NULL;
				new->pgoffset=scan->pgoffset+scan->pgsize;
				new->pgsize=pgsize;
				new->next=NULL;
				scan->next = new;
				scan=new;
			}
			/* now there is a new element of the right size for the allocation,
			 * it will be found in the next iteration */
		} else
			scan = scan->next;
	}
	/* this point should never be reached */
	return NULL;
}

/* get the stat info of the mmapped file */
static int um_mmap_getstat(char *filename, struct ht_elem *hte, struct stat64 *buf, struct pcb *pc)
{
 if (hte == NULL)
	 return r_lstat64(filename,buf);
 else
	 return ht_syscall(hte,uscno(NR64_lstat))(filename,buf,-1);
}

/* add_mmap_secret copies the virtual mmap-ed file in a section of the
 * secret file */
static long add_mmap_secret(struct ht_elem *hte,const char *from, unsigned long pgoffset)
{
	char buf[BUFSIZ];
	int fdf;
	int n;
	unsigned long long size=0;
	//printk("add_mmap_secret %s %ld\n",from, pgoffset);
#if __NR__llseek != __NR_doesnotexist
	loff_t result;
	r_llseek(um_mmap_secret, pgoffset >> ((sizeof (long)*8) - um_mmap_pageshift),
			pgoffset << um_mmap_pageshift, &result, SEEK_SET);
#else
	r_lseek(um_mmap_secret,pgoffset << um_mmap_pageshift,SEEK_SET);
#endif
	/* No need for hte search. from is the mmap path so hte and
		 private data is already set for submodules */
	if ((fdf=ht_syscall(hte,uscno(__NR_open))(from,O_RDONLY,0)) < 0)
		return -errno;
	while ((n=ht_syscall(hte,uscno(__NR_read))(fdf,buf,BUFSIZ)) > 0) {
		r_write (um_mmap_secret,buf,n);
		size += n;
	}
	ht_syscall(hte,uscno(__NR_close))(fdf);
	return (size >> um_mmap_pageshift)+1;
}

/* store_mmap_secret copies a section of the secret file back in the
 * virtual file*/
static void store_mmap_secret(struct ht_elem *hte,const char *to, unsigned long pgoffset, unsigned long length)
{
	char buf[BUFSIZ];
	int fdf;
	int n;
	//printk("store_mmap_secret %s %ld %p\n",to, pgoffset,hte);
#if __NR__llseek != __NR_doesnotexist
	loff_t result;
	r_llseek(um_mmap_secret, pgoffset >> ((sizeof (long)*8) - um_mmap_pageshift),
			pgoffset << um_mmap_pageshift, &result, SEEK_SET);
#else
	r_lseek(um_mmap_secret,pgoffset << um_mmap_pageshift,SEEK_SET);
#endif
	/* hte is *not* set. search for "to".*/
#ifdef NDEBUG
	ht_check(CHECKPATH,(void *)to,NULL,0);
#else
	{
		struct ht_elem *shte;
		shte=ht_check(CHECKPATH,(void *)to,NULL,0);
		assert(hte==shte);
	}
#endif
	if ((fdf=ht_syscall(hte,uscno(__NR_open))(to,O_WRONLY | O_TRUNC | O_CREAT,0)) < 0)
		return;
	while (length > 0) {
		n=(length < BUFSIZ)?length:BUFSIZ;
	  n=r_read(um_mmap_secret,buf,n);
	  if (n<=0)
			break;
	  ht_syscall(hte,uscno(__NR_write))(fdf,buf,n);
		length -= n;
	}
	ht_syscall(hte,uscno(__NR_close))(fdf);
	return; 
}

/* both mmap and mmap2 management */
int wrap_in_mmap(int sc_number,struct pcb *pc,
		struct ht_elem *hte, sysfun um_syscall)
{
	unsigned long length=pc->sysargs[1];
	unsigned long prot=pc->sysargs[2];
	// unsigned long flags=pc->sysargs[3];
	unsigned long fd=pc->sysargs[4];
	long offset=pc->sysargs[5];
	unsigned long pgsize;
	struct stat64 sbuf;
	char *path=fd_getpath(pc->fds,fd);
	/*if ((!(flags & MAP_PRIVATE)) && (prot & PROT_WRITE))
		printk("MMAP: %s only MAP_PRIVATE has been implemented\n",path);*/
	/* convert mmap into mmap2 */
	if (sc_number == __NR_mmap)
		offset >>= um_mmap_pageshift;
	/* compute the size in pages */
	pgsize=offset+(length >> um_mmap_pageshift)+1;
	epoch_t nestepoch=um_setnestepoch(0);
	/* get the stat info about the file */
	if (um_mmap_getstat(path, hte, &sbuf, pc) < 0) {
		pc->retval = -1;
		return SC_FAKE;
	} else {
		struct mmap_sf_entry *sf_entry;
		if ((sbuf.st_size >> um_mmap_pageshift) + 1 > pgsize)
			pgsize = (sbuf.st_size >> um_mmap_pageshift) + 1;
		//printk("%s(%s/%o): MMAP SIZE %lld pgsize %ld %ld \n", path, ht_get_servicename(hte), fd,sbuf.st_size,(unsigned long)((sbuf.st_size >> um_mmap_pageshift) + 1),pgsize);
		/* there is already in the secret file? */
		if ((sf_entry=mmap_sf_find(path,nestepoch,sbuf.st_mtime,pgsize)) == NULL) {
			/* NO. must be loaded */
			if ((sf_entry=mmap_sf_allocate(path,nestepoch,sbuf.st_mtime,pgsize,
							prot,hte,length)) == NULL) {
				/* there is something wrong, we cannot allocate space on the secret file*/
				pc->retval = -1;
				return SC_FAKE;
			}
			if (add_mmap_secret(hte, path, sf_entry->pgoffset) <= 0) {
				/* there is something wrong, cannot load the file! */
				pc->retval = -1;
				return SC_FAKE;
			}
		}
		/* add the new item in the *process* mmap table */
		pc->um_mmap = pcb_mmap_add(pc->um_mmap, 0, length, sf_entry);
		sf_entry->counter++;
		pc->retval = 0;
		
		/* rewrite the syscall parms: mmap->mmap2 if needed, using the secret
		 * file at the correct offset */
		
#		if __NR_mmap2 != __NR_doesnotexist
		/* On 32-bit interfaces we convert every call to mmap2 which takes the
		 * offset in pages (not bytes */
		putscno(__NR_mmap2,pc);
		pc->sysargs[4] = um_mmap_secret;
		pc->sysargs[5] = sf_entry->pgoffset+offset;
#		else
		/* If there is no mmap2 (it's probably a 64 bit architecture) we stay
		 * with the original mmap but the offset must be in bytes, rounded up
		 * to a multiple of the page size. */
		pc->sysargs[4] = um_mmap_secret;
		pc->sysargs[5] = (sf_entry->pgoffset + offset) * pgsize;
#		endif
		
		//printk("MMAP2 path %s epoch %lld %ld %ld %ld\n", path, nestepoch, sf_entry->pgoffset, offset,pgsize);
		return SC_CALLONXIT;
	}
}

/* unmap: search the chunk to be unmapped, if found it is moved to the
 * head of the process mmap table */
int wrap_in_munmap(int sc_number,struct pcb *pc,
		struct ht_elem *hte, sysfun um_syscall)
{
	unsigned long start=pc->sysargs[0];
	unsigned long length=pc->sysargs[1];
	
	//printk("======== wrap_in_munmap %lx %ld!!!\n",start,length);
	if (pcb_mmap_sfsearch_n_movetohead(&(pc->um_mmap),start,length))
		return SC_CALLONXIT;
	else
		return STD_BEHAVIOR;
}

/* remap: search the chunk and move it to the head of the process mmap table */
int wrap_in_mremap(int sc_number,struct pcb *pc,
		struct ht_elem *hte, sysfun um_syscall)
{
	unsigned long start=pc->sysargs[0];
	unsigned long length=pc->sysargs[1];
	//unsigned long new_length=pc->sysargs[2];
	//printk("======== wrap_in_mremap %lx %ld!!!\n",start,length,new_length);
	if (pcb_mmap_sfsearch_n_movetohead(&(pc->um_mmap),start,length)) {
		/* TODO check that remap does not overlap next mmap chunk on the secret
		 * file */
		return SC_CALLONXIT;
	} else
		return STD_BEHAVIOR;
}

/* mmap after system call management */
int wrap_out_mmap(int sc_number,struct pcb *pc)
{
	if (pc->retval >= 0) {
		long rv=getrv(pc);
		/* user-mode syscall succeeded */
		if (pc->um_mmap) {
			/* should be always true, just for safety*/
			if (rv != -1)
				/* the new mmap entry is the first. update the user-mode address */
				pc->um_mmap->start=rv;
			else
				/* user mode failed, the mapping must be deleted here, too */
				pcb_mmap_deletehead(&(pc->um_mmap),1);
		}
		return STD_BEHAVIOR;
	} else {
		putrv(pc->retval,pc);
		puterrno(pc->erno,pc);
		return SC_MODICALL;
	}
}

/* unmap after syscall management, delete the element only if the 
 * user mode syscall succeeded */
int wrap_out_munmap(int sc_number,struct pcb *pc)
{
	//printk("======== wrap_out_munmap !!!\n");
	long rv=getrv(pc);
	if (rv != -1) 
		pcb_mmap_deletehead(&(pc->um_mmap),0);	
	return STD_BEHAVIOR;
}

/* unmap after syscall management, change the size only if the 
 * user mode syscall succeeded */
int wrap_out_mremap(int sc_number,struct pcb *pc)
{
	unsigned long new_length=pc->sysargs[2];
	long rv=getrv(pc);
	if (rv != -1 && pc->um_mmap) {
		pc->um_mmap->start=rv;
		pc->um_mmap->len = new_length;
	}
	return STD_BEHAVIOR;
}

#endif
