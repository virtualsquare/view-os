/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   pivoting.c: implementation of pivoting programming interface
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
#include <alloca.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>

#include "gdebug.h"
#include "pivoting.h"
#include "sctab.h"
#include "services.h"
#include "syscall_code.h"
#include "utils.h"

#include "real_syscalls.h"

int register_first_instruction(struct pcb *pcb)
{
	/* save the current address - that is, the address of the first
	 * instruction */
	if(popper(pcb) != 0)
	{
		GPERROR(0, "first popper failed");
		return 1;
	}
	errno = 0;
	/* round up to 4 bytes of alignment */
	pcb->first_instruction_address = (void*)( (getpc(pcb)+3)&(~(long)0xf) );
	if(errno != 0)
	{
		GPERROR(0, "getpc at beginnin of program failed");
		return 1;
	}
	else
	{
		GDEBUG(2, "first instruction address = %p\n", pcb->first_instruction_address);
		return 0;
	}
}

// sc number and 6 arguments
typedef int psl_desc[7];

struct pivoting_syscall_list
{
	int used_num;
	int total_size;
	psl_desc *descs;
};

struct pivoting_syscall_list *create_sc_list(int size)
{
	struct pivoting_syscall_list *psl;
	GDEBUG(2, "create_sc_list(%d)", size);
	psl = malloc(sizeof(struct pivoting_syscall_list));
	if(psl == NULL)
		return NULL;
	psl->used_num = 0;
	psl->total_size = size;
	/* increment size, since we will add one more syscall at the end of the
	 * list */
	psl->descs = malloc(sizeof(psl_desc) * (size+1));
	if(psl->descs == NULL)
		return NULL;
	return psl;
}

struct pivoting_syscall_list *add_sc_to_list(struct pivoting_syscall_list *l,
		int scno,
		int arg1, int arg2, int arg3, int arg4, int arg5, int arg6)
{
	psl_desc *pd;
	GDEBUG(2, "add_sc_to_list(l, scno=%d, args=%x,%x,%x,%x,%x,%x), l->used_num=%d, l->total_size=%d",
			scno,
			arg1, arg2, arg3, arg4, arg5, arg6,
			l->used_num, l->total_size);
	if(l->used_num == l->total_size)
	{
		GDEBUG(0, "Tried to add another syscall to a full list");
		return NULL;
	}
	pd = l->descs+l->used_num;
	(*pd)[0] = scno;
	(*pd)[1] = arg1;
	(*pd)[2] = arg2;
	(*pd)[3] = arg3;
	(*pd)[4] = arg4;
	(*pd)[5] = arg5;
	(*pd)[6] = arg6;
	l->used_num++;
	return l;
}

void destroy_sc_list(struct pivoting_syscall_list *l)
{
	GDEBUG(2, "destroy_sc_list(l)");
	free(l->descs);
	free(l);
}

int pivoting_inject(struct pcb *pc, struct pivoting_syscall_list *list,
		pivoting_callback callback, int start_counter)
{
	char *code;
	int i, argnum;

	GDEBUG(2, "pivoting_inject(pc, list, callback, %d)", start_counter);

	/* add one more fake syscall to the list, increasing the length by hand
	 * (in fact, that much space was allocated at the beginning!) */
	list->total_size++;
	if(add_sc_to_list(list, BIG_SYSCALL, 0, 0, 0, 0, 0, 0) != list)
	{
		GPERROR(0, "add_sc_to_list(list, BIG_SYSCALL, ...)");
		return 1;
	}

	/* save the code which we will overwrite - one more then the counter
	 * because we also have the fake syscall 5000 */
	int code_to_save_len = ASM_SYSCALL_LENGTH * list->used_num;
	GDEBUG(3, "code_to_save_len=%d", code_to_save_len);

	/* check that we are not already in pivoting */
	assert(pc->saved_code == NULL);

	/* save registers */
	memcpy(pc->saved_regs_pivoting, pc->saved_regs, sizeof(pc->saved_regs));

	/* save code */
	/* TODO: here we save the code, and then write over it, and then write
	 * a register; it can be done with a single PTRACE_MULTI, if enabled */
	pc->saved_code = malloc(code_to_save_len+8);
	if(pc->saved_code == NULL)
	{
		GPERROR(0, "malloc() for allocating saved_code");
		return 1;
	}
	if(umoven(pc->pid, (long)pc->first_instruction_address, code_to_save_len+8, pc->saved_code) != 0)
	{
		GPERROR(0, "umoven()");
		return 1;
	}
	pc->saved_code_length = code_to_save_len;

	/* debug */
	{
#define len 1000
		char data[len];
		char *pdata = data;
		int i;
		char hdigit[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8',
			'9', 'a', 'b', 'c', 'd', 'e', 'f' };
		for(i = 0; i < code_to_save_len+8; i++)
		{
			pdata[0] = hdigit[(pc->saved_code[i]>>4)&0xf];
			pdata[1] = hdigit[pc->saved_code[i]&0xf];
			pdata[2] = ' ';
			pdata[3] = '\0';
			pdata += 3;
		}
		GDEBUG(3, "saved code: %s", data);
#undef len
	}

	/* prepare the code in our address space */
	code = alloca(code_to_save_len);
	for(i = 0; i < list->used_num; i++)
	{
		/* copy code with arguments set to zero */
/*                GDEBUG(3, "copy code data to %p", code + i*ASM_SYSCALL_LENGTH);*/
		memcpy(code + i*ASM_SYSCALL_LENGTH, asm_syscall, ASM_SYSCALL_LENGTH);
		/* write arguments */
		for(argnum = 0; argnum < 7; argnum++)
			*((int*)(code + i*ASM_SYSCALL_LENGTH + asm_syscall_args[argnum])) = (list->descs[i])[argnum];
	}

	/* debug */
	{
#define len 1000
		char data[len];
		char *pdata = data;
		int i;
		char hdigit[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8',
			'9', 'a', 'b', 'c', 'd', 'e', 'f' };
		for(i = 0; i < code_to_save_len; i++)
		{
			pdata[0] = hdigit[(code[i]>>4)&0xf];
			pdata[1] = hdigit[code[i]&0xf];
			pdata[2] = ' ';
			pdata[3] = '\0';
			pdata += 3;
		}
		GDEBUG(3, "written code: %s", data);
#undef len
	}

	/* write it in the process address space */
	if(ustoren(pc->pid, (long)pc->first_instruction_address, code_to_save_len, code) != 0)
	{
		GPERROR(0, "ustoren()");
		return 1;
	}

	/* put new program counter */
	putpc((long)pc->first_instruction_address, pc);

	/* save the counter */
	pc->counter = start_counter;

	/* save the pivoting callback */
	pc->piv_callback = callback;

	/* now the process is in a pivoting status: mark the fact */
	pc->flags |= PCB_INPIVOTING;

	{
		int _pc;
		int data;
		/*if(popper(pc) < 0)
			GPERROR(0, "saving register");*/
		_pc = getpc(pc);
		umoven(pc->pid, _pc, 4, &data);
		GDEBUG(3, "pc=%x, instruction=%x", _pc, data);
	}

	/* everything ok */
	return 0;
}

int pivoting_eject(struct pcb *pc)
{
	assert(pc->flags & PCB_INPIVOTING);
	assert(pc->saved_code != NULL);

	/* puts the code back to its right place */
	if(ustoren(pc->pid, (long)pc->first_instruction_address, pc->saved_code_length, pc->saved_code) != 0)
	{
		GPERROR(0, "ustoren");
		return 1;
	}

	/* debug */
	{
#define len 1000
		char data[len];
		char *pdata = data;
		int i;
		char hdigit[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8',
			'9', 'a', 'b', 'c', 'd', 'e', 'f' };
		char *code;

		code = alloca(pc->saved_code_length);
		if(umoven(pc->pid, (long)pc->first_instruction_address, pc->saved_code_length, code) != 0)
			GPERROR(0, "umoven debug");

		for(i = 0; i < pc->saved_code_length; i++)
		{
			pdata[0] = hdigit[(code[i]>>4)&0xf];
			pdata[1] = hdigit[code[i]&0xf];
			pdata[2] = ' ';
			pdata[3] = '\0';
			pdata += 3;
		}
		GDEBUG(3, "recovered code: %s", data);
#undef len
	}
	/* frees allocated place */
	free(pc->saved_code);
	pc->saved_code = NULL;

	/* restore registers */
	memcpy(pc->saved_regs, pc->saved_regs_pivoting, sizeof(pc->saved_regs));

	/* puts the pc back to its place too */
	/*putpc((long)pc->saved_address, pc);*/

	/* change the status back to "non-pivoted" */
	pc->flags &= ~PCB_INPIVOTING;

	GDEBUG(3, "end with success");
	return 0;
}

#ifdef PIVOTING_TEST
pivoting_callback getpid_callback;
int wrap_in_getpid(int sc_number,struct pcb *pc,struct pcb_ext *pcdata,
		                service_t sercode, intfun syscall)
{
	return SC_FAKE;
}

int wrap_out_getpid(int sc_number,struct pcb *pc,struct pcb_ext *pcdata)
{

	int data = (int)'a' + ((int)'b' << 8) + ((int)'\n' << 16) + ((int)'\0' << 24);
	int dest;
	struct pivoting_syscall_list *l = create_sc_list(3);

	GDEBUG(2, "wrap_out_getpid called");

	/* mette la stringa nello stack del processo */
	errno = 0;
	dest = getsp(pc);
	dest -= sizeof(data);
	GDEBUG(3, "saving data @ %p", (void*)dest);
	if(dest == -1 && errno != 0)
	{ GPERROR(2, "getsp"); exit(1); }
	errno = 0;
	if(ustoren(pc->pid, dest, 4, &data) != 0)
	{ GPERROR(2, "ustoren abcd"); exit(1); }

	if(add_sc_to_list(l, __NR_write, 1, dest, 4, 0, 0, 0) == NULL ||
			add_sc_to_list(l, __NR_mkdir, dest, 4, 0, 0, 0, 0) == NULL ||
			add_sc_to_list(l, __NR_write, 1, dest, 4, 0, 0, 0) == NULL)
	{
		GPERROR(2, "add_sc_to_list() failed");
		exit(1);
	}

	pivoting_inject(pc, l, getpid_callback, 0);
	
	destroy_sc_list(l);

	return 0;
}

/*int wrap_out_getpid(int sc_number,struct pcb *pc,struct pcb_ext *pcdata) {return 0;}*/

void getpid_callback(int scno, enum phase p, struct pcb *pc, int counter)
{
	switch(counter)
	{
		case 0:
			GDEBUG(2, "step 0: ``wrap_in_write''");
			break;
		case 1:
			GDEBUG(2, "step 1: ``wrap_out_write''");
			break;
		case 2:
			GDEBUG(2, "step 2: ``wrap_in_mkdir''");
			break;
		case 3:
			GDEBUG(2, "step 3: ``wrap_out_mkdir''");
			break;
		case 4:
			GDEBUG(2, "step 4: ``wrap_in_write''");
			break;
		case 5:
			GDEBUG(2, "step 5: ``wrap_out_write''");
			break;
		case 6:
			GDEBUG(2, "step 6: fake syscall");
			break;
		default:
			GDEBUG(2, "this step should have not been reached!");
			break;
	}
}

#endif
