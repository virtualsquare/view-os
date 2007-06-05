#   
#   This is part of um-ViewOS
#   The user-mode implementation of OSVIEW -- A Process with a View
#
#   Makefile: global makefile
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

.PHONY: all server module librsc clean tags
RELEASE=true

all: librsc server module tags

server:
	make -C server/ all RELEASE=$(RELEASE)

module:
	make -C module/ all RELEASE=$(RELEASE)

librsc:
	make -C librsc/ all RELEASE=$(RELEASE)

tags:
	ctags-exuberant -R .

clean:
	make -C server/ clean RELEASE=$(RELEASE)
	make -C module/ clean RELEASE=$(RELEASE)
	make -C librsc/ clean RELEASE=$(RELEASE)
	rm -fr tags
