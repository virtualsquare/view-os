moddir = $(libdir)/umview/modules

DEVELFLAGS =

AM_CFLAGS = -ggdb
AM_LDFLAGS = -module -avoid-version -export-dynamic
AM_LIBTOOLFLAGS = --tag=disable-static
AM_CPPFLAGS = -I$(includedir)/umview -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE $(DEVELFLAGS)

bin_PROGRAMS = fuseext2
mod_LTLIBRARIES = umfuseext2.la

dist_man1_MANS = fuseext2.1

fuseext2_SOURCES = fuseext2.c bindir.h v2fuseutils.c v2fuseutils.h
fuseext2_LDFLAGS = -lfuse -lext2fs
# Leave this also if it seems a no-op
fuseext2_CFLAGS = $(AM_CFLAGS)

umfuseext2_la_SOURCES = fuseext2.c bindir.h v2fuseutils.c v2fuseutils.h
umfuseext2_la_LDFLAGS = $(AM_LDFLAGS) -lumlib -lfuse -lext2fs

install-data-hook:
	cd "$(DESTDIR)/$(moddir)" && rm -f $(mod_LTLIBRARIES)

extraclean: maintainer-clean
	rm -rf aclocal.m4 autom4te.cache autoscan.log configure.scan \
	config.h.in* configure depcomp install-sh Makefile.in \
	config.guess config.sub \
	ltmain.sh missing `find . -name Makefile.in` \
	fuse-umfuse-*.tar.gz \
	fuse-umfuse-*.tar.bz2

