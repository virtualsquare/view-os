CFLAGS=-fPIC -I../include 

all: libumlib.a

libumlib.a: um_lib.o libummod.o
	rm -f libumlib.a
	ar rcs libumlib.a um_lib.o libummod.o
	ranlib libumlib.a

um_lib.o: um_lib.c

libummod.o: libummod.c

distclean: clean

clean: 
	rm -f libumlib.a um_lib.o libummod.o

install: all
	install libumlib.a ${libdir}
