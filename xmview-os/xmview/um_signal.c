/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   um_signal: basic signal handling (to be completed).
 *   added to manage signals to blocked processes.
 *   
 *   Copyright 2005 Renzo Davoli University of Bologna - Italy
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

#include <config.h>
#include <sys/types.h>
#include <signal.h>
#include <errno.h>
#include "defs.h"
#include "hashtab.h"
#include "mainpoll.h"
#include "capture.h"
#include "sctab.h"

int wrap_in_kill(int sc_number,struct pcb *pc,
		    struct ht_elem *hte, sysfun um_syscall)
{
	long pid=pc->sysargs[0];
	long signo=pc->sysargs[1];
	if (secure) {
		if (capcheck(CAP_KILL,pc)) {
			/* For  a  process  to  have permission to send a signal it must either be
				 privileged (under Linux: have the CAP_KILL capability), or the real  or
				 effective  user  ID of the sending process must equal the real or saved
				 set-user-ID of the target process. */
			struct pcb *target=pid2pcb(pid);
			if (target != NULL) {
				if (pc->ruid != target->ruid && pc->ruid != target->suid &&
						pc->euid != target->ruid && pc->euid != target->suid) {
					/* XXX todo: In the case of SIGCONT it  suffices
						 when the sending and receiving processes belong to the same session. */
					if (signo != SIGCONT) {
						pc->retval=-1;
						pc->erno=EPERM;
						return SC_FAKE;
					}
				}
			} else {
				/* XXX signals to external process: allow or deny? option? */
				/* NOW: CAP_KILL->allow !CAP_KILL->deny */
				pc->retval=-1;
				pc->erno=EPERM;
				return SC_FAKE;
			}
		}
	}
	if (bq_pidwake(pid,signo)) {
		putscno(__NR_getpid,pc);
		return SC_MODICALL;
	} else
		return STD_BEHAVIOR;
}

int wrap_out_kill(int sc_number,struct pcb *pc)
{
	if (pc->retval < 0)
		puterrno(pc->erno,pc);
	return SC_MODICALL;
}
