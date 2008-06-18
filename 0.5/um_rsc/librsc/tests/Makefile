#   
#   This is part of Remote System Call (RSC) Library.
#
#   Makefile: tests makefile
#   
#   Copyright (C) 2007 Andrea Forni
#   
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License, version 2, as
#   published by the Free Software Foundation.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License along
#   with this program; if not, write to the Free Software Foundation, Inc.,
#   51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA.
#

LIB_RSC_DIR = ../
RSC_LIB = $(LIB_RSC_DIR)librsc.a
CC = gcc
CFLAGS = -Wall -g -O0 -I../include/ -I../src/include/ -Itools/ -DRSCDEBUG
tools_sources = $(shell ls tools/*.c)
sources_no_main = tests.c $(shell ls test_*.c)
sources = $(sources_no_main) $(tools_sources)
.PHONY: clean tgz send run send sppc s64 tags


all: tags client server run

run: tags selftests 
	./selftests


$(RSC_LIB):
	make -C ${LIB_RSC_DIR} TEST='true'

selftests: selftests.c ${sources:.c=.o} $(RSC_LIB) 
	$(CC) $(CFLAGS) -o $@ $^ -lpthread

client: client.c ${sources:.c=.o} $(RSC_LIB) 
	$(CC) $(CFLAGS) -o $@ $^ -lpthread

server: server.c  ${sources:.c=.o} $(RSC_LIB) 
	$(CC) $(CFLAGS) -o $@ $^ -lpthread

tags:
	ctags-exuberant -R ../

%.d: %.c
	set -e; $(CC) -MM $(CFLAGS) $< \
		| sed 's/\($*\)\.o[ :]*/\1.o $@ : /g' > $@; \
		[ -s $@ ] || rm -f $@
include $(this_dir_sources:.c=.d)


cleanlib: clean
	make -C ../ clean
clean: 
	rm -f *.o *.d selftests server client tools/*.o tools/*.d
