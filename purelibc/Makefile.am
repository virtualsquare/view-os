lib_LTLIBRARIES = libpurelibc.la
include_HEADERS = purelibc.h

CFLAGS=-g -Wall -O0

libpurelibc_la_SOURCES = dir.c exec.c kernel_termios.ppc.h purelibc.h socketcalls.c stdio.c syscalls.c 
libpurelibc_la_CFLAGS = -g -ggdb -D_GNU_SOURCE
libpurelibc_la_LDFLAGS = -export-dynamic -module -version-info 1:0:0 -Xcompiler -nostartfiles

extraclean: distclean
	rm -rf ltmain.sh config.sub config.guess aclocal.m4 configure config.h.in autom4te.cache install-sh missing compile depcomp Makefile.in
