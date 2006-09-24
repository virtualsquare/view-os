CFLAGS=-ggdb -fPIC -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -I/usr/local/include -I../include 
LOADLIBES = -L/usr/local/lib

ALL = umdevmbr umdevramdisk

all: $(ALL)

undevmbr.o: umdevmbr.c mbr.h

mbr.o: mbr.c mbr.h

undevramdisk.o: umdevramdisk.c 

umdevmbr: umdevmbr.o mbr.o
	gcc -shared -o umdevmbr umdevmbr.o mbr.o

umdevramdisk: umdevramdisk.o 
	gcc -shared -o umdevramdisk umdevramdisk.o

install: all
	install $(ALL) ${libdir}

distclean: clean

clean:
	rm -rf *.o $(ALL)
