moddir = $(libdir)/umview/modules

DEVELFLAGS =

AM_CFLAGS = -ggdb
AM_LDFLAGS = -module -avoid-version -export-dynamic
AM_LIBTOOLFLAGS = --tag=disable-static
AM_CPPFLAGS = -I$(includedir)/umview -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE $(DEVELFLAGS)

bin_PROGRAMS = fuseiso9660
mod_LTLIBRARIES = umfuseiso9660.la

dist_man1_MANS = fuseiso9660.1

fuseiso9660_SOURCES = fuseiso9660.c zisofs.h v2fuseutils.c v2fuseutils.h
fuseiso9660_LDFLAGS = -lfuse -lz -liso9660 -lcdio
# Leave this also if it seems a no-op
fuseiso9660_CFLAGS = $(AM_CFLAGS)

umfuseiso9660_la_SOURCES = fuseiso9660.c zisofs.h v2fuseutils.c v2fuseutils.h
umfuseiso9660_la_LDFLAGS = $(AM_LDFLAGS) -lz -liso9660

install-data-hook:
	cd "$(DESTDIR)/$(moddir)" && rm -f $(mod_LTLIBRARIES)

extraclean: maintainer-clean
	rm -rf aclocal.m4 autom4te.cache autoscan.log configure.scan \
	config.h.in* configure depcomp install-sh Makefile.in \
	config.guess config.sub \
	ltmain.sh missing `find . -name Makefile.in` \
	fuse-umfuse-*.tar.gz \
	fuse-umfuse-*.tar.bz2

