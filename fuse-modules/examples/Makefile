CFLAGS=-ggdb -D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=26 -I/usr/local/include
##CFLAGS=-ggdb -D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=25
LOADLIBES = -L/usr/local/lib -lfuse -lext2fs -liso9660 -lz
##LOADLIBES = -lfuse -lext2fs -lz /usr/lib/libiso9660.so

ALL = hello umfusehello fusexmp umfusexmp
#ALL = hello fuseext2 fuseiso9660 fusexmp

all: $(ALL)

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
