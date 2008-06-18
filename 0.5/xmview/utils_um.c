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
//#include <sys/user.h>
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

/* LOAD data from the process address space */
int
umoven(struct pcb *pc, long addr, int len, void *_laddr)
{
	if (len==0) 
		return 0;
	/* ptrace_multi is the quickest way */
	if (has_ptrace_multi) {
		struct ptrace_multi req[] = {{PTRACE_PEEKCHARDATA, addr, _laddr, len}};
		return ptrace(PTRACE_MULTI, pc->pid, req, 1); 
	}
	else {
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
				errno = 0;
				u.val = ptrace(PTRACE_PEEKDATA, pc->pid, (char *) addr, 0);
				if (errno) {
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
				errno = 0;
				u.val = ptrace(PTRACE_PEEKDATA, pc->pid, (char *) addr, 0);
				if (errno) {
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
umovestr(struct pcb *pc, long addr, int len, void *_laddr)
{
	if (len==0) 
		return 0;
	/* quick solution: ptrace_multi is available */
	if (has_ptrace_multi) {
		struct ptrace_multi req[] = {{PTRACE_PEEKSTRINGDATA, addr, _laddr, len}};
		long rv=ptrace(PTRACE_MULTI, pc->pid, req, 1); 
		//fprint2("umovestr %d\n",rv);
		if (rv >= 0)
			return 0;
		else
			return -1;
	}
	else {
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
				errno = 0;
				u.val = ptrace(PTRACE_PEEKDATA, pc->pid, (char *)addr, 0);
				if (errno) {
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
				errno = 0;
				u.val = ptrace(PTRACE_PEEKDATA, pc->pid, (char *)addr, 0);
				if (errno) {
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
ustoren(struct pcb *pc, long addr, int len, void *_laddr)
{
	if (len==0) 
		return 0;
	if (has_ptrace_multi) {
	/* wow: there is ptrace_multi, this is the quicky way */
		struct ptrace_multi req[] = {{PTRACE_POKECHARDATA, addr, _laddr, len}};
		return ptrace(PTRACE_MULTI, pc->pid, req, 1); 
	}
	else {
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
				errno = 0;
				u.val = ptrace(PTRACE_PEEKDATA, pc->pid, (char *) addr, 0);
				if (errno) {
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
				ptrace(PTRACE_POKEDATA, pc->pid, (char *) addr, u.val);
				addr += sizeof(long), laddr += m, len -= m;
				if (errno) {
					/*perror("ustoren2");*/
					return -1;
				}
			}
			while (len) {
				errno = 0;
				if (len < sizeof(long)) {
					u.val = ptrace(PTRACE_PEEKDATA, pc->pid, (char *) addr, 0);
				}
				if (errno) {
					if (started && (errno==EPERM || errno==EIO)) {
						/* Ran into 'end of memory' - stupid "printpath" */
						return 0;
					}
					if (addr != 0)
						/*perror("ustoren3");*/
						return -1;
				}
				started = 1;
				memcpy(u.x, laddr, m = MIN(sizeof(long), len));
				ptrace(PTRACE_POKEDATA, pc->pid, (char *) addr, u.val);
				addr += sizeof(long), laddr += m, len -= m;
				if (errno) {
					/*perror("ustoren4");*/
					return -1;
				}
			}
			return 0;
		}
	}
}

/* STORE data (0 terminated string) into the process address space */
int
ustorestr(struct pcb *pc, long addr, int len, void *_laddr)
{
	if (len==0) 
		return 0;
	if (has_ptrace_multi) {
		/* ptrace is provided by this kernel -> let's go speedy */
		struct ptrace_multi req[] = {{PTRACE_POKECHARDATA, addr, _laddr, len}};
		return ptrace(PTRACE_MULTI, pc->pid, req, 1); 
	}
	else {
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
				errno = 0;
				u.val = ptrace(PTRACE_PEEKDATA, pc->pid, (char *)addr, 0);
				if (errno) {
					if (started && (errno==EPERM || errno==EIO)) {
						/* Ran into 'end of memory' - stupid "printpath" */
						return 0;
					}
					/*perror("ustorestr");*/
					return -1;
				}
				started = 1;
				memcpy(&u.x[n], laddr, m = MIN(sizeof(long)-n,len));
				ptrace(PTRACE_POKEDATA, pc->pid, (char *) addr, u.val);
				if (errno) {
					/*perror("ustoren");*/
					return -1;
				}
				while (n & (sizeof(long) - 1))
					if (u.x[n++] == '\0')
						return 0;
				addr += sizeof(long), laddr += m, len -= m;
			}
			while (len) {
				errno = 0;
				for (i = 0; i < sizeof(long); i++)
					if (laddr[i] == '\0') {
						u.val = ptrace(PTRACE_PEEKDATA, pc->pid, (char *)addr, 0);
						break;
					}
				if (errno) {
					if (started && (errno==EPERM || errno==EIO)) {
						/* Ran into 'end of memory' - stupid "printpath" */
						return 0;
					}
					/*perror("ustorestr");*/
					return -1;
				}
				started = 1;
				memcpy(u.x, laddr, m = MIN(sizeof(long), len));
				ptrace(PTRACE_POKEDATA, pc->pid, (char *) addr, u.val);
				if (errno) {
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
