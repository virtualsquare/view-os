CFLAGS=-ggdb -fPIC -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -I/usr/local/include -I../include 
LOADLIBES = -L/usr/local/lib

ALL = umdevtap

all: $(ALL)

umdevtap.o: umdevtap.c

umdevtap: umdevtap.o 
	gcc -shared -o umdevtap -lvdeplug umdevtap.o  

install: all
	install $(ALL) ${libdir}

distclean: clean

clean:
	rm -rf *.o $(ALL)
