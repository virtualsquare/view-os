DEBUGLEVEL?=4
CBASEFLAGS=-fPIC -I../include -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -Wall -rdynamic
CDEBUGFLAGS=-g -ggdb -DGDEBUG_ENABLED -DGDEBUG_LEVEL=$(DEBUGLEVEL)

ALL=viewfs.so

ifeq ($(RELEASE),true)

# Release version (default is nodebug)
CFLAGS=$(CBASEFLAGS)
all: $(ALL)

debug: clean
	$(MAKE) CFLAGS="$(CBASEFLAGS) $(CDEBUGFLAGS)"

else

# Development version (default is debug)
CFLAGS=$(CBASEFLAGS) $(CDEBUGFLAGS)
all: $(ALL)

nodebug: clean
	$(MAKE) CFLAGS="$(CBASEFLAGS)"

endif


viewfs.so: viewfs.o ../um_lib/libumlib.a
	$(CC) -shared -o $@ $+

viewfs.o: viewfs.c ../include/module.h ../include/libummod.h

distclean: clean

cleanall:
	rm -rf $(ALL) *.o

clean: cleanall

install: all
