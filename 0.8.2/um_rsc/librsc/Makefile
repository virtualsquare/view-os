#   
#   This is part of Remote System Call (RSC) Library.
#
#   Makefile: library makefile
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


# If RELEASE is false, the sources are compiled with debug prints
# and some static functions become global functions, in this way
# they can be tested.
RELEASE = true
# If TEST is true, the sources are compiled as if RELEASE = false
# but without debug prints 
TEST = false

MAKE_OVERRIDING_VARS=
CC = gcc
sources = $(shell ls src/*.c)

ifeq ($(TEST), true)
MAKE_OVERRIDING_VARS += "RSCDEBUGLEVEL=0"
RELEASE = false
endif


.PHONY: clean librsc.a
ifeq ($(RELEASE), true)

all: librsc.a 

else
MAKE_OVERRIDING_VARS += "RELEASE=false"
.PHONY: tags
all: librsc.a 

tags:
	ctags-exuberant -R .
endif

librsc.a:
	make -C src/ $(MAKE_OVERRIDING_VARS)
	rm -f $@
	ar rcs $@ ${sources:.c=.o}

clean:
	make -C tests/ clean
	make -C src/ clean	RELEASE=$(RELEASE)
	rm -f tags cscope.out
	rm -f librsc.a 
