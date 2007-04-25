# Makefile (to be converted in an AutoMakefile soon)
# Renzo Davoli 2007

CFLAGS=-ggdb -DFATWRITE  -DFUSE_USE_VERSION=26 -D_FILE_OFFSET_BITS=64 -I/usr/include/glib-2.0 -I/usr/lib/glib-2.0/include  -Wall
LIBS=-pthread -lglib-2.0 -lfuse
LIBFAT_OBJS=libfat.o utf16be.o utf16le.o utf8.o simple_fold.o

ALL: libfat.a libfat.so fusefat umfusefat

libfat.a: ${LIBFAT_OBJS}
	rm -f libfat.a
	ar rcs libfat.a ${LIBFAT_OBJS} 
	ranlib libfat.a

libfat.so: ${LIBFAT_OBJS}
	gcc -shared -nostartfiles -o libfat.so ${LIBFAT_OBJS}

libfat.o: libfat.c libfat.h bits/libfat.h

utf8.o: utf8.c

utf16be.o: utf16be.c

utf16le.o: utf16le.c

simple_fold.o: simple_fold.c

fusefat.o: fusefat.c 

v2fuseutils.o: v2fuseutils.c

fusefat: fusefat.o libfat.a v2fuseutils.o
	$(CC) -o fusefat ${LIBS} fusefat.o libfat.a v2fuseutils.o

umfusefat:  fusefat.o libfat.a v2fuseutils.o
	$(CC) -o umfusefat ${LIBS} -shared -nostartfiles fusefat.o libfat.a v2fuseutils.o

clean:
	rm -f ${LIBFAT_OBJS} libfat.a fusefat umfusefat libfat.so fusefat.o v2fuseutils.o
