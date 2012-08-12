/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   utils.c: data exchange routines. (umview-processes)
 *   
 *   Copyright 2005 Renzo Davoli University of Bologna - Italy
 *   Some code has been inherited from strace:
 *   Copyright (c) 1991, 1992 Paul Kranenburg <pk@cs.few.eur.nl>
 *   Copyright (c) 1993 Branko Lankester <branko@hacktic.nl>
 *   Copyright (c) 1993, 1994, 1995, 1996 Rick Sladkey <jrs@world.std.com>
 *   Copyright (c) 1996-1999 Wichert Akkerman <wichert@cistron.nl>
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

#include <signal.h>
#include <sys/syscall.h>
#include <sys/param.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <stdio.h>
#include <string.h>
#include <config.h>
#include "defs.h"
#include "utils.h"
#include "ptrace2.h"

int (*umoven) (struct pcb *pc, long addr, int len, void *_laddr)=umoven_std;
int (*umovestr) (struct pcb *pc, long addr, int len, void *_laddr)=umovestr_std;
int (*ustoren) (struct pcb *pc, long addr, int len, void *_laddr)=ustoren_std;
int (*ustorestr) (struct pcb *pc, long addr, int len, void *_laddr)=ustorestr_std;

/* LOAD data from the process address space */
	int
umoven_std(struct pcb *pc, long addr, int len, void *_laddr)
{
	if (len==0) 
		return 0;
	else 
	{
#ifdef _PROC_MEM_TEST
		/* try to read from the /proc/nnnn/mem file */
		if (pc->memfd >= 0) {
			int sz;
			sz=r_pread64(pc->memfd,_laddr,len,0,addr);
			if (sz>=0)
				return 1;
		} 
#endif
		{
			/* unlucky option: we need to use the standard ptrace,
			 * one syscall per memory word */
			char *laddr=_laddr;
			long n, m;
			//FIXME: started is not changed after check it in "if(started && ..." 
			int started = 0;
			union {
				long val;
				char x[sizeof(long)];
			} u;

			if (addr & (sizeof(long) - 1)) {
				/* addr not a multiple of sizeof(long) */
				n = addr - (addr & -sizeof(long)); /* residue */
				addr &= -sizeof(long); /* residue */
				if (r_ptrace(PTRACE_PEEKDATA, pc->pid, (char *) addr, &u.val) < 0) {
					if (started && (errno==EPERM || errno==EIO)) {
						/* Ran into 'end of memory' - stupid "printpath" */
						return 0;
					}
					/* But if not started, we had a bogus address. */
					/*perror("umoven");*/
					return -1;
				}
				started = 1;
				memcpy(laddr, &u.x[n], m = MIN(sizeof(long) - n, len));
				addr += sizeof(long), laddr += m, len -= m;
			}
			while (len) {
				if (r_ptrace(PTRACE_PEEKDATA, pc->pid, (char *) addr, &u.val) < 0) {
					if (started && (errno==EPERM || errno==EIO)) {
						/* Ran into 'end of memory' - stupid "printpath" */
						return 0;
					}
					/*if (addr != 0)
						perror("umoven");*/
					return -1;
				}
				started = 1;
				memcpy(laddr, u.x, m = MIN(sizeof(long), len));
				addr += sizeof(long), laddr += m, len -= m;
			}
			return 0;
		}
	}
}

/* LOAD data (0 terminated string) from the process address space */
	int
umovestr_std(struct pcb *pc, long addr, int len, void *_laddr)
{
	if (len==0) 
		return 0;
	else
	{
#ifdef _PROC_MEM_TEST
		/* try to read /proc/nnnn/mem */
		if (0 && pc->memfd >= 0) {
			int sz;
			sz=r_pread64(pc->memfd,_laddr,len,0,addr);
			if (sz >= 0)
				return 1;
		} 
#endif
		{
			/* no hope: use standard ptrace */
			char *laddr=_laddr;
			int started = 0;
			long n,m;
			int i;
			union {
				long val;
				char x[sizeof(long)];
			} u;
			if (addr & (sizeof(long) - 1)) {
				/* addr not a multiple of sizeof(long) */
				n = addr - (addr & -sizeof(long)); /* residue */
				addr &= -sizeof(long); /* residue */
				if (r_ptrace(PTRACE_PEEKDATA, pc->pid, (char *)addr, &u.val) < 0) {
					if (started && (errno==EPERM || errno==EIO)) {
						/* Ran into 'end of memory' - stupid "printpath" */
						return 0;
					}
					/*	perror("umovestr");*/
					return -1;
				}
				started = 1;
				memcpy(laddr, &u.x[n], m = MIN(sizeof(long)-n,len));
				while (n & (sizeof(long) - 1))
					if (u.x[n++] == '\0')
						return 0;
				addr += sizeof(long), laddr += m, len -= m;
			}
			while (len) {
				if (r_ptrace(PTRACE_PEEKDATA, pc->pid, (char *)addr, &u.val) < 0) {
					if (started && (errno==EPERM || errno==EIO)) {
						/* Ran into 'end of memory' - stupid "printpath" */
						return 0;
					}
					/*if (addr != 0)
						perror("umovestr");*/
					return -1;
				}
				started = 1;
				memcpy(laddr, u.x, m = MIN(sizeof(long), len));
				for (i = 0; i < sizeof(long); i++)
					if (u.x[i] == '\0')
						return 0;

				addr += sizeof(long), laddr += m, len -= m;
			}
			return 0;
		}
	}
}

/* STORE data into the process address space */
	int
ustoren_std(struct pcb *pc, long addr, int len, void *_laddr)
{
	if (len==0) 
		return 0;
	else
	{
#ifdef _PROC_MEM_TEST
		/* let us try to write on /proc/nnnn/mem */
		/* unfortunately /proc/<pid>/mem does not support writing yet... */
		if (pc->memfd >= 0) {
			int sz;
			sz=r_pwrite64(pc->memfd,_laddr,len,0,addr);
			if (sz>=0)
				return 1;
		} 
#endif
		{
			/* what a pity: there is only standard ptrace */
			char *laddr=_laddr;
			long n, m;
			int started = 0;
			union {
				long val;
				char x[sizeof(long)];
			} u;

			if (addr & (sizeof(long) - 1)) {
				/* addr not a multiple of sizeof(long) */
				n = addr - (addr & -sizeof(long)); /* residue */
				addr &= -sizeof(long); /* residue */
				if (r_ptrace(PTRACE_PEEKDATA, pc->pid, (char *) addr, &u.val) < 0) {
					if (started && (errno==EPERM || errno==EIO)) {
						/* Ran into 'end of memory' - stupid "printpath" */
						return 0;
					}
					/* But if not started, we had a bogus address. */
					/*perror("ustoren1");*/
					return -1;
				}
				started = 1;
				memcpy(&u.x[n], laddr, m = MIN(sizeof(long) - n, len));
				if (r_ptrace(PTRACE_POKEDATA, pc->pid, (char *) addr, u.val) < 0) {
					/*perror("ustoren2");*/
					return -1;
				}
				addr += sizeof(long), laddr += m, len -= m;
			}
			while (len) {
				if (len < sizeof(long)) {
					if (r_ptrace(PTRACE_PEEKDATA, pc->pid, (char *) addr, &u.val) < 0) {
						if (started && (errno==EPERM || errno==EIO)) {
							/* Ran into 'end of memory' - stupid "printpath" */
							return 0;
						}
						if (addr != 0)
							/*perror("ustoren3");*/
							return -1;
					}
				}
				started = 1;
				memcpy(u.x, laddr, m = MIN(sizeof(long), len));
				if (r_ptrace(PTRACE_POKEDATA, pc->pid, (char *) addr, u.val) < 0) {
					/*perror("ustoren4");*/
					return -1;
				}
				addr += sizeof(long), laddr += m, len -= m;
			}
			return 0;
		}
	}
}

/* STORE data (0 terminated string) into the process address space */
	int
ustorestr_std(struct pcb *pc, long addr, int len, void *_laddr)
{
	if (len==0) 
		return 0;
	else
	{
#ifdef _PROC_MEM_TEST
		/* let us try if we can write /proc/nnnn/mem */
		/* /proc/<pid>/mem: linux does not support writing... yet*/
		if (pc->memfd >= 0) {
			int sz;
			sz=r_pwrite64(pc->memfd,_laddr,len,0,addr);
			if (sz >= 0)
				return 1;
		} 
#endif
		{
			/* umph, there is nothing better to do than using a
			 * ptrace call per memory word. Snaily way */
			char *laddr=_laddr;
			int started = 0;
			int i, n, m;
			union {
				long val;
				char x[sizeof(long)];
			} u;

			if (addr & (sizeof(long) - 1)) {
				/* addr not a multiple of sizeof(long) */
				n = addr - (addr & -sizeof(long)); /* residue */
				addr &= -sizeof(long); /* residue */
				if (r_ptrace(PTRACE_PEEKDATA, pc->pid, (char *)addr, &u.val) < 0) {
					if (started && (errno==EPERM || errno==EIO)) {
						/* Ran into 'end of memory' - stupid "printpath" */
						return 0;
					}
					/*perror("ustorestr");*/
					return -1;
				}
				started = 1;
				memcpy(&u.x[n], laddr, m = MIN(sizeof(long)-n,len));
				if (r_ptrace(PTRACE_POKEDATA, pc->pid, (char *) addr, u.val) < 0) {
					/*perror("ustoren");*/
					return -1;
				}
				while (n & (sizeof(long) - 1))
					if (u.x[n++] == '\0')
						return 0;
				addr += sizeof(long), laddr += m, len -= m;
			}
			while (len) {
				for (i = 0; i < sizeof(long); i++) {
					if (laddr[i] == '\0') {
						if (r_ptrace(PTRACE_PEEKDATA, pc->pid, (char *)addr, &u.val) < 0) {
							if (started && (errno==EPERM || errno==EIO)) {
								/* Ran into 'end of memory' - stupid "printpath" */
								return 0;
							}
							/*perror("ustorestr");*/
							return -1;
						}
						break;
					}
				}
				started = 1;
				memcpy(u.x, laddr, m = MIN(sizeof(long), len));
				if (r_ptrace(PTRACE_POKEDATA, pc->pid, (char *) addr, u.val) < 0) {
					/*perror("ustoren");*/
					return -1;
				}
				for (i = 0; i < sizeof(long); i++)
					if (u.x[i] == '\0')
						return 0;

				addr += sizeof(long), laddr += m, len -= m;
			}
			return 0;
		}
	}
}

/* LOAD data from the process address space */
	int
umoven_multi(struct pcb *pc, long addr, int len, void *_laddr)
{
	if (len==0) 
		return 0;
	struct ptrace_multi req[] = {{PTRACE_PEEKCHARDATA, addr, _laddr, len}};
	return r_ptrace(PTRACE_MULTI, pc->pid, req, 1); 
}

/* LOAD data (0 terminated string) from the process address space */
	int
umovestr_multi(struct pcb *pc, long addr, int len, void *_laddr)
{
	if (len==0) 
		return 0;
	struct ptrace_multi req[] = {{PTRACE_PEEKSTRINGDATA, addr, _laddr, len}};
	long rv=r_ptrace(PTRACE_MULTI, pc->pid, req, 1); 
	if (rv >= 0)
		return 0;
	else
		return -1;
}

/* STORE data into the process address space */
	int
ustoren_multi(struct pcb *pc, long addr, int len, void *_laddr)
{
	if (len==0) 
		return 0;
	struct ptrace_multi req[] = {{PTRACE_POKECHARDATA, addr, _laddr, len}};
	return r_ptrace(PTRACE_MULTI, pc->pid, req, 1); 
}

/* STORE data (0 terminated string) into the process address space */
	int
ustorestr_multi(struct pcb *pc, long addr, int len, void *_laddr)
{
	if (len==0) 
		return 0;
	/* ptrace is provided by this kernel -> let's go speedy */
	struct ptrace_multi req[] = {{PTRACE_POKECHARDATA, addr, _laddr, len}};
	return r_ptrace(PTRACE_MULTI, pc->pid, req, 1); 
}

#ifdef _PROCESS_VM_RW
#define CHUNKMASK 4095
int umoven_process_rw(struct pcb *pc, long addr, int len, void *_laddr)
{
	if (len==0)
		return 0;
	else {
		int chunk_len;
		while (len > 0) {
			chunk_len=len;
			long end_in_page = ((addr + chunk_len) & CHUNKMASK);
			long r = chunk_len - end_in_page;
			if (r > 0) /* if chunk_len > end_in_page */
				chunk_len = r; /* chunk_len -= end_in_page */
			struct iovec local={_laddr,chunk_len};
			struct iovec remote={(void *)addr,chunk_len};
			int rv=process_vm_readv(pc->pid, &local, 1, &remote, 1, 0);
			//printf("umoven_process_rw %d %d\n",rv,errno);
			if (rv != chunk_len) return -1;
			len -= chunk_len;
			addr += chunk_len;
			_laddr += chunk_len;
		}
		return 0;
	}
}

int umovestr_process_rw(struct pcb *pc, long addr, int len, void *_laddr)
{
	if (len==0)
		return 0;
	else {
		int chunk_len;
		while (len > 0) {
			chunk_len=len;
			long end_in_page = ((addr + chunk_len) & CHUNKMASK);
			long r = chunk_len - end_in_page;
			if (r > 0) /* if chunk_len > end_in_page */
				chunk_len = r; /* chunk_len -= end_in_page */
			struct iovec local={_laddr,chunk_len};
			struct iovec remote={(void *)addr,chunk_len};
			int rv=process_vm_readv(pc->pid, &local, 1, &remote, 1, 0);
			//printf("umoven_process_rw %d %d\n",rv,errno);
			if (rv != chunk_len) return -1;
			for (r=0; r<chunk_len; r++)
				if (((char *)_laddr)[r] == 0)
					return 0;
			len -= chunk_len;
			addr += chunk_len;
			_laddr += chunk_len;
		}
		return 0;
	}
}

int ustoren_process_rw(struct pcb *pc, long addr, int len, void *_laddr)
{
	if (len==0)
		return 0;
	else {
		struct iovec local={_laddr,len};
		struct iovec remote={(void *)addr,len};
		int rv=process_vm_writev(pc->pid, &local, 1, &remote, 1, 0);
		//printf("ustoren_process_rw %d %d\n",rv,errno);
		return (rv==len)?0:-1;
	}
}

int ustorestr_process_rw(struct pcb *pc, long addr, int len, void *_laddr)
{
	if (len==0)
		return 0;
	else {
		struct iovec local={_laddr,len};
		struct iovec remote={(void *)addr,len};
		int rv=process_vm_writev(pc->pid, &local, 1, &remote, 1, 0);
		//printf("ustorestr_process_rw %d %d\n",rv,errno);
		return (rv>=0)?0:-1;
	}
}
#endif
