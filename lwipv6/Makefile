prefix = /usr/local
bindir = ${prefix}/bin
libdir = ${prefix}/lib
mandir = ${prefix}/man
includedir = ${prefix}/include

export bindir libdir mandir includedir

all:
	make -C lwip-contrib/ports/unix/proj/lib all

clean:
	make -C lwip-contrib/ports/unix/proj/lib clean

${libdir}:
	mkdir -p ${libdir}

install: ${libdir}
	install lwip-contrib/ports/unix/proj/lib/liblwip.so ${libdir}
	install lwip-contrib/ports/unix/include/lwipv6.h ${includedir}
	

