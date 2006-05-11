DEVELFLAGS=
#DEVELFLAGS=-D__UMDEV_DEBUG__

CFLAGS=-I../include -D_GNU_SOURCE -ggdb -rdynamic $(DEVELFLAGS)

ALL=umbinfmt.so

all: $(ALL)

umbinfmt.so: umbinfmt.o ../um_lib/libumlib.a
	$(CC) -shared -rdynamic -o $@ $< ../um_lib/libumlib.a -lpthread

umbinfmt.o: umbinfmt.c ../include/module.h ../include/libummod.h 

distclean: clean

cleanall:
	rm -rf $(ALL) *.o

clean: cleanall

install: all
	install $(ALL) ${libdir}
