CFLAGS=-I../include -D_GNU_SOURCE -ggdb -D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=22 -rdynamic

ALL=testmodule.so testmodul2.so unreal.so real.so sockettest.so sockip.so

all: $(ALL)

testmodule.so: testmodule.o
	$(CC) -shared -o $@ $<

testmodul2.so: testmodul2.o
	$(CC) -shared -o $@ $<

unreal.so: unreal.o ../um_lib/libumlib.a
	$(CC) -shared -o $@ $< ../um_lib/libumlib.a

real.so: real.o ../um_lib/libumlib.a
	$(CC) -shared -o $@ $< ../um_lib/libumlib.a

sockettest.so: sockettest.o ../um_lib/libumlib.a
	$(CC) -shared -o $@ $< ../um_lib/libumlib.a

sockip.so: sockip.o ../um_lib/libumlib.a
	$(CC) -shared -o $@ $< ../um_lib/libumlib.a

testmodule.o: testmodule.c ../include/module.h

testmodul2.o: testmodul2.c ../include/module.h

unreal.o: unreal.c ../include/module.h ../include/libummod.h

real.o: real.c ../include/module.h ../include/libummod.h

sockettest.o: sockettest.c ../include/module.h ../include/libummod.h

sockip.o: sockip.c ../include/module.h ../include/libummod.h

cleanall:
	rm -rf $(ALL) *.o

clean: cleanall

install: all
