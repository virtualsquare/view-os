CFLAGS=-ggdb -fPIC -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -I/usr/local/include -I../include 
LOADLIBES = -L/usr/local/lib

ALL = umdevmbr

all: $(ALL)

undevmbr.o: umdevmbr.c mbr.h

mbr.o: mbr.c mbr.h

umdevmbr: umdevmbr.o mbr.o
	gcc -shared -o umdevmbr umdevmbr.o mbr.o

install: all
	install $(ALL) ${libdir}

distclean: clean

clean:
	rm -rf *.o $(ALL)
