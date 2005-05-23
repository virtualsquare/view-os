/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   pivoting.h: header for pivoting programming interface
 *   
 *   Copyright 2005 Mattia Belletti
 *   
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 *   $Id$
 *
 */

#ifndef PIVOTING_H_
#define PIVOTING_H_

#include "defs.h"

/**
 * Once a process starts to execute, this function have to be called so that
 * the address of the first instruction of the process is saved. This is used
 * as the pivoting point for injecting syscall code.
 */
int register_first_instruction(struct pcb *pcb);

/**
 * The type of a list of syscall calls. Look functions below
 */
struct pivoting_syscall_list;

/**
 * Create a list of syscall calls of given size.
 */
struct pivoting_syscall_list *create_sc_list(int size);

/**
 * Add given syscall call to the list. Value of unused parameters is ignored.
 * Returns the list itself, or NULL on error and errno set, if it has sense to
 * do so.
 */
struct pivoting_syscall_list *add_sc_to_list(struct pivoting_syscall_list *l,
		int scno,
		int arg1, int arg2, int arg3, int arg4, int arg5, int arg6);

/**
 * Destroy a syscall list.
 */
void destroy_sc_list(struct pivoting_syscall_list *l);

/**
 * The number of a fake, invalid syscall.
 */
#define		BIG_SYSCALL		5000

/**
 * Inject given code into process address space and execute it. Given function
 * will be called in the in/out phase of each syscall instead of the usual
 * wrapper functions, and once more on the last, fake syscall (BIG_SYSCALL), or
 * no function at all will be called if NULL is passed.  Callback functions
 * will be called with syscall number, the phase it has been called on, and the
 * PCB of the process. Additionally, a counter is given to this function, and
 * will be passed to the callback every call, incrementing it by one. This
 * allows to 1) have a big switch which has continous code to handle the code
 * injection (look macros below) and 2) to use the same function more than once
 * for injection (simply by passing the last counter+1 you can have the switch
 * handling all the stuff).
 * Once this is called, process is ready to be PTRACE_SYSCALLed.
 * Returns 0 if ok, 1 on error.
 */
int pivoting_inject(struct pcb *pc, struct pivoting_syscall_list *list,
		pivoting_callback callback, int start_counter);

/**
 * Exactly the contrary of pivoting_inject - that is, removes the syscall call
 * code we injected, and puts the program counter back where it was moved from.
 * This is automatically called by tracehand when the sequence of calls passed
 * to pivoting_inject is ended, so there's no need to worry about it, usually.
 * As usual, returns 0 if ok, != 0 on error.
 */
int pivoting_eject(struct pcb *pc);


#endif
