ifeq ($(RELEASE),true)
DEVELFLAGS=
else
DEVELFLAGS=-D__UMFUSE_EXPERIMENTAL__
endif

CFLAGS=-I../include -fPIC -D_GNU_SOURCE -ggdb -D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=26 -rdynamic $(DEVELFLAGS)
#CFLAGS=-I../include -D_GNU_SOURCE -ggdb -D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=25 -rdynamic $(DEVELFLAGS)
#CFLAGS=-I../include -D_GNU_SOURCE -ggdb -D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=25 -rdynamic -D__UMFUSE_DEBUG__ -D__UMFUSE_DEBUG_LEVEL__=10

ALL=umfuse.so

all: $(ALL)

umfuse.so: umfuse.o umfusestd.o umfuseargs.o ../um_lib/libumlib.a
	$(CC) -shared -o $@ $< umfusestd.o umfuseargs.o ../um_lib/libumlib.a -lpthread

umfuse.o: umfuse.c ../include/module.h ../include/libummod.h umfusestd.h

umfusestd.o: umfusestd.c 

umfuseargs.o: umfuseargs.c  umfusestd.h

cleanall:
	rm -rf $(ALL) *.o

clean: cleanall

install: all
	install $(ALL) ${libdir}
