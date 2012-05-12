#   
#   This is part of Remote System Call (RSC) Library.
#
#   Makefile: library sources makefile
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

RSCDEBUGLEVEL = 2
RELEASE = false
C_DEBUG_FLAGS = -O0 -g -ggdb -DRSCDEBUG -DRSC_DEBUG_LEVEL=$(RSCDEBUGLEVEL) 
CFLAGS = -fPIC -Wall -I ../include/ -I ./include/ 
sources = $(shell ls *.c)

.PHONY: all clean

ifeq ($(RELEASE), false)

CFLAGS += ${C_DEBUG_FLAGS}
.PHONY: tags
all: $(sources:.c=.o)
tags:
	ctags-exuberant -R ../
else
CFLAGS += -O3
all: $(sources:.c=.o)
endif # ifeq ($(RELEASE), false)


%.d: %.c
	set -e; $(CC) -MM $(CFLAGS) $< \
		| sed 's/\($*\)\.o[ :]*/\1.o $@ : /g' > $@; \
		[ -s $@ ] || rm -f $@

include $(sources:.c=.d)

clean:
	rm -fr *.o *.d tags
