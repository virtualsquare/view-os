CFLAGS=-ggdb -fPIC -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -I/usr/local/include -I../include 
LOADLIBES = -L/usr/local/lib
##LOADLIBES = -lfuse -lext2fs -lz /usr/lib/libiso9660.so

ALL = umdevnull umdevtrivhd

all: $(ALL)

undevnull.o: umdevnull.c 

umdevnull: umdevnull.o
	gcc -shared -o umdevnull umdevnull.o 

umdevtrivhd.o: umdevtrivhd.c

umdevtrivhd: umdevtrivhd.o
	gcc -shared -o umdevtrivhd umdevtrivhd.o 

#test umdev: not installed
install: all

clean:
	rm -rf *.o $(ALL)
