/** @file
 *
 * Dynamic memory manager
 *
 */

/* 
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
 * All rights reserved. 
 * 
 * Redistribution and use in source and binary forms, with or without modification, 
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED 
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT 
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, 
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT 
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING 
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY 
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 * 
 * Author: Adam Dunkels <adam@sics.se>
 *
 */

#include <string.h>
#include <stdlib.h>

#include "lwip/arch.h"
#include "lwip/opt.h"
#include "lwip/def.h"
#include "lwip/mem.h"

#include "lwip/sys.h"

#include "lwip/stats.h"

/*
 * FIX: If you want to use these functions malloc() and free() 
 *      implementation MUST be thread safe.
 */

#ifndef DEBUGMEM
void
mem_init(void)
{
}

void
mem_free(void *rmem)
{
	free(rmem);
}

void *
mem_reallocm(void *rmem, mem_size_t newsize)
{
	return (realloc(rmem,newsize));
}

void *
mem_realloc(void *rmem, mem_size_t newsize)
{
	return (realloc(rmem,newsize));
}

void *
mem_malloc(mem_size_t size)
{
	return (malloc(size));
}
#else
struct mem_check {
	void *addr;
	char *file;
	int line; /*positive if allocated */
};

struct mem_stat {
	int count;
	char *file;
	int line; /*positive if allocated */
};

#define MEMCHECKSIZE 32768
#define STATSIZE 1024
struct mem_check table[MEMCHECKSIZE];
struct mem_stat stat[STATSIZE];

	void
mem_d_init(char *__file,int __line)
{
}

	void
mem_d_free(void *rmem,char *__file,int __line)
{
	int i;
	for (i=0; i<MEMCHECKSIZE; i++) {
		if (table[i].addr == rmem) {
			if (table[i].line < 0) {
				fprintf(stderr, "MALLOC DOUBLE FREE %s %d and %s %d\n",__file,__line,
						table[i].file, -table[i].line);
			} 
			table[i].file=__file;
			table[i].line= - __line;
			break;
		}
		if (table[i].addr == 0) {
			fprintf(stderr, "MALLOC FREE not allocated addr %s %d\n",__file,__line);
			break;
		}
	}
	free(rmem);
}

	void *
mem_d_malloc(mem_size_t size,char *__file,int __line)
{
	void *rv = malloc(size);

	if (rv < 0) 
		fprintf(stderr, "MALLOC FAILED! %s %d\n",__file,__line);
	else {
		int i;
		for (i=0; i<MEMCHECKSIZE; i++) {
			if (table[i].addr == rv) {
				if (table[i].line > 0) {
					fprintf(stderr, "MALLOC DOUBLE ALLOCATION %s %d and %s %d\n",__file,__line,
							table[i].file, table[i].line);
				}
				table[i].file=__file;
				table[i].line=__line;
				break;
			}
			if (table[i].addr == 0) {
				table[i].addr=rv;
				table[i].file=__file;
				table[i].line=__line;
				if ((i % 1024) == 1023) {
					int allocated, freed;
					int j;
					for (i=0; i<STATSIZE; i++)
						stat[i].count = 0;
					for (i=allocated=freed=0; i<MEMCHECKSIZE; i++) {
						if (table[i].line > 0) {
							for (j=0; j<STATSIZE; j++) {
								if (stat[j].count == 0) {
									stat[j].count = 1;
									stat[j].file = table[i].file;
									stat[j].line = table[i].line;
									break;
								}
								if (stat[j].file == table[i].file &&
										stat[j].line == table[i].line) {
									stat[j].count++;
									break;
								}
							}
							allocated++;
						}
						if (table[i].line < 0)
							freed++;
						if (table[i].addr == 0)
							break;
					}
					fprintf(stderr, "allocated %d addresses %d/%d\n",i,allocated,freed);
					for (j=0;j<STATSIZE && stat[j].count>0 ;j++)
						fprintf(stderr, " count %d file %s line %d\n",stat[j].count,stat[j].file,stat[j].line);
				}
				break;
			}
		}
	}
	return rv;
}

	void *
mem_d_realloc(void *rmem, mem_size_t newsize,char *__file,int __line)
{
	if (rmem == NULL) 
		return mem_d_malloc(newsize, __file, __line);
	else {
		int i;
		void *rv=realloc(rmem,newsize);
		for (i=0; i<MEMCHECKSIZE; i++) {
			if (table[i].addr == rv) {
				if (table[i].line > 0) {
					fprintf(stderr, "REALLOC DOUBLE ALLOCATION %s %d and %s %d\n",__file,__line,
							table[i].file, table[i].line);
				}
				table[i].file=__file;
				table[i].line=__line;
				break;
			}
			if (table[i].addr == rmem) {
				if (table[i].line < 0) {
					fprintf(stderr, "REALLOC FREED ADDR %s %d and %s %d\n",__file,__line,
							table[i].file, -table[i].line); 
				}                           
				table[i].file=__file;
				table[i].line=__line;
				table[i].addr=rv;
				break;                          
			}                                       
			if (table[i].addr == 0) {
				fprintf(stderr, "REALLOC not allocated addr %s %d\n",__file,__line);
				break;                                        
			}                                                     
		} 
		return rv;
	}
}

	void *
mem_d_reallocm(void *rmem, mem_size_t newsize,char *__file,int __line)
{
	return mem_d_realloc(rmem,newsize,__file,__line);
}

#endif
