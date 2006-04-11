libdir=/usr/local/lib

CFLAGS=-ggdb -D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=26 -I/usr/local/include
##CFLAGS=-ggdb -D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=25
LOADLIBES = -L/usr/local/lib -lfuse -lext2fs -liso9660 -lz
##LOADLIBES = -lfuse -lext2fs -lz /usr/lib/libiso9660.so

ALL = hello umfusehello fuseext2 umfuseext2 fuseiso9660 umfuseiso9660 fusexmp umfusexmp
#ALL = hello fuseext2 fuseiso9660 fusexmp

all: $(ALL)

fuseext2.o: fuseext2.c 

fuseext2: fuseext2.o

umfuseext2: fuseext2.o
	gcc -shared -nostartfiles -o umfuseext2 fuseext2.o /usr/lib/libext2fs.so

fuseiso9660.o: fuseiso9660.c

fuseiso9660: fuseiso9660.o

umfuseiso9660: fuseiso9660.o zisofs.h
#	gcc -shared -nostartfiles -o umfuseiso9660 fuseiso9660.o /usr/local/lib/libiso9660.so /usr/local/lib/libcdio.so /usr/lib/libm.so
#	gcc -shared -nostartfiles -o umfuseiso9660 fuseiso9660.o /usr/lib/libiso9660.so /usr/lib/libcdio.so /usr/lib/libm.so
	gcc -shared -nostartfiles -o umfuseiso9660 fuseiso9660.o /usr/lib/libiso9660.so /usr/lib/libcdio.so /usr/lib/libz.so /usr/lib/libm.so

hello.o: hello.c

umfusehello: hello.o
	gcc -shared -nostartfiles -o umfusehello hello.o 

fusexmp.o: fusexmp.c

umfusexmp: fusexmp.o
	gcc -shared -nostartfiles -o umfusexmp fusexmp.o 

clean:
	rm -rf $(ALL) *.o

install: all
	install umfusehello ${libdir}
	install umfusexmp ${libdir}
	install umfuseiso9660 ${libdir}
	install umfuseext2 ${libdir}
