
CBASEFLAGS=-I../include -fPIC -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=26 -rdynamic $(DEVELFLAGS)
#CFLAGS=-I../include -D_GNU_SOURCE -ggdb -D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=25 -rdynamic $(DEVELFLAGS)
#CFLAGS=-I../include -D_GNU_SOURCE -ggdb -D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=25 -rdynamic -D__UMFUSE_DEBUG__ -D__UMFUSE_DEBUG_LEVEL__=10
CDEBUGFLAGS=-g3 -ggdb3 -DGDEBUG_ENABLED -DGDEBUG_LEVEL=$(DEBUGLEVEL)

ALL=umfuse.so


ifeq ($(RELEASE),true)
DEVELFLAGS=
CFLAGS=$(CBASEFLAGS) $(DEVELFLAGS)

all: $(ALL)
debug: clean
	$(MAKE) CFLAGS="$(CBASEFLAGS) $(CDEBUGFLAGS)"
else
DEVELFLAGS=-D__UMFUSE_EXPERIMENTAL__
CFLAGS=$(CBASEFLAGS) $(CDEBUGFLAGS) $(DEVELFLAGS)

all: $(ALL)
nodebug: clean
	$(MAKE) CFLAGS="$(CBASEFLAGS)"
endif



umfuse.so: umfuse.o umfusestd.o umfuseargs.o ../um_lib/libumlib.a
	$(CC) -shared -o $@ $< umfusestd.o umfuseargs.o ../um_lib/libumlib.a -lpthread

umfuse.o: umfuse.c ../include/module.h ../include/libummod.h umfusestd.h

umfusestd.o: umfusestd.c 

umfuseargs.o: umfuseargs.c  umfusestd.h

distclean: clean

cleanall:
	rm -rf $(ALL) *.o

clean: cleanall

install: all
	install $(ALL) ${libdir}
	install umfuse.1viewos ${mandir}/man1
