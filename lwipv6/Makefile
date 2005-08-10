prefix = /usr/local
bindir = ${prefix}/bin
libdir = ${prefix}/lib
mandir = ${prefix}/man
export bindir libdir mandir

all:
	make -C lwip-contrib/ports/unix/proj/lib all

clean:
	make -C lwip-contrib/ports/unix/proj/lib clean

${libdir}:
	mkdir -p ${libdir}

install: ${libdir}
	install lwip-contrib/ports/unix/proj/lib/liblwip.so ${libdir}
	

