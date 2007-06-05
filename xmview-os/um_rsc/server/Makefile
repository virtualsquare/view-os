#   
#   This is part of um-ViewOS
#   The user-mode implementation of OSVIEW -- A Process with a View
#
#   Makefile: UMView RSC server makefile
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

CC = gcc

RELEASE = true
DEBUGLEVEL = 2
C_DEBUG_FLAGS = -O0 -g -ggdb -DGDEBUG_ENABLED -DGDEBUG_LEVEL=$(DEBUGLEVEL)
C_BASE_FLAGS =  -O0 -g -ggdb -Wall -I ../librsc/include/ -I ../../include/ -I ../../
CFLAGS = $(C_BASE_FLAGS)
RSC_LIB = ../librsc/librsc.a

sources = rsc_server.c gdebug.c pollfd_info.c

.PHONY: all clean rsc_server

ifeq ($(RELEASE), true)
CFLAGS += -O3

all: rsc_server

else
CFLAGS += -O0 $(C_DEBUG_FLAGS)

all: rsc_server tags
clean_lib:
	make -C ../librsc/ clean

.PHNOY: tags
tags:
	ctags-exuberant -R ../../
endif

rsc_server: $(sources:.c=.o) ${RSC_LIB}
	$(CC) -o $@ $^ -ldl -lpthread 

${RSC_LIB}:
	make -C ../librsc/

%.d: %.c
	set -e; $(CC) -MM $(CFLAGS) $< \
		| sed 's/\($*\)\.o[ :]*/\1.o $@ : /g' > $@; \
		[ -s $@ ] || rm -f $@

include $(sources:.c=.d)

clean:
	rm -fr *.so rsc_server $(sources:.c=.o) $(sources:.c=.d) tags
