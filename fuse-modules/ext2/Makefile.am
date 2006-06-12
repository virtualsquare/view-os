
bin_PROGRAMS=fuseext2 
noinst_PROGRAMS=umfuseext2


AM_CFLAGS=-fPIC -ggdb -D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=26 -I/usr/local/include

umfuseext2_LDFLAGS= -shared -nostartfiles -lext2fs -lfuse
umfuseext2_SOURCES=fuseext2.c bindir.h

fuseext2_SOURCES=fuseext2.c
fuseext2_LDFLAGS=-lfuse -lext2fs


install-exec-hook:
	$(INSTALL) umfuseext2 $(prefix)/lib
