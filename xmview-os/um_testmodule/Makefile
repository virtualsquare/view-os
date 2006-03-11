DEBUGLEVEL?=4
CBASEFLAGS=-fPIC -I../include -I../gdebug -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -Wall -rdynamic
CDEBUGFLAGS=-g -ggdb -DGDEBUG_ENABLED -DGDEBUG_LEVEL=$(DEBUGLEVEL)

ALL=testmodule.so testmodul2.so unreal.so real.so sockettest.so sockip.so viewfs.so

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


testmodule.so: testmodule.o
	$(CC) -shared -o $@ $<

testmodul2.so: testmodul2.o
	$(CC) -shared -o $@ $<

unreal.so: unreal.o ../um_lib/libumlib.a
	$(CC) -shared -o $@ $+

real.so: real.o ../um_lib/libumlib.a
	$(CC) -shared -o $@ $+

sockettest.so: sockettest.o ../um_lib/libumlib.a
	$(CC) -shared -o $@ $+

sockip.so: sockip.o ../um_lib/libumlib.a
	$(CC) -shared -o $@ $+

#viewfs.so: viewfs.o ../um_lib/libumlib.a ../gdebug/gdebug.o
viewfs.so: viewfs.o ../um_lib/libumlib.a
	$(CC) -shared -o $@ $+

testmodule.o: testmodule.c ../include/module.h

testmodul2.o: testmodul2.c ../include/module.h

unreal.o: unreal.c ../include/module.h ../include/libummod.h

real.o: real.c ../include/module.h ../include/libummod.h

sockettest.o: sockettest.c ../include/module.h ../include/libummod.h

sockip.o: sockip.c ../include/module.h ../include/libummod.h

viewfs.o: viewfs.c ../include/module.h ../include/libummod.h

cleanall:
	rm -rf $(ALL) *.o

clean: cleanall

install: all
