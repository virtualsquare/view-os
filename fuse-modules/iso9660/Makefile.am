bin_PROGRAMS=fuseiso9660 
noinst_PROGRAMS=umfuseiso9660

AM_CFLAGS=-fPIC -ggdb -D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=26 -I/usr/local/include

umfuseiso9660_LDFLAGS= -shared -nostartfiles -liso9660 -lfuse -lz
umfuseiso9660_SOURCES=fuseiso9660.c

fuseiso9660_SOURCES=fuseiso9660.c zlibiso.h
fuseiso9660_LDFLAGS=-lfuse -liso9660 -lz

install-exec-hook:
	$(INSTALL) umfuseiso9660 $(prefix)/lib
