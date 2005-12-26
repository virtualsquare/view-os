prefix = /usr/local
bindir = ${prefix}/bin
libdir = ${prefix}/lib
mandir = ${prefix}/man
includedir = ${prefix}/include

export bindir libdir mandir includedir

all:
	make -C lwip-contrib/ports/unix/proj/lib all

# added by Diego Billi
allstatic:
	make -C lwip-contrib/ports/unix/proj/lib allstatic

clean:
	make -C lwip-contrib/ports/unix/proj/lib clean

${libdir}:
	mkdir -p ${libdir}

install: ${libdir}
	install lwip-contrib/ports/unix/proj/lib/liblwip.so ${libdir}
	install lwip-contrib/ports/unix/include/lwipv6.h ${includedir}
	install lwip-contrib/ports/unix/proj/lib/liblwip.a ${libdir}

# added by Diego Billi 
installstatic: ${libdir}
	install lwip-contrib/ports/unix/proj/lib/liblwip.a ${libdir}
	
# added by Diego Billi
help:
	@echo -e "Lwipv6 targets:"
	@echo -e "all - Compile LwipV6 as dynamic Library (.so)"
	@echo -e "allstatic - Complile LwipV6 as static library (.a) "
	@echo -e "clean - Clean LwipV6 source tree"
	@echo -e ${libdir}   " - Create LwipV6 installation directory "
	@echo -e "install - Install LwipV6 dinamic library in " ${libdir}
	@echo -e "installstatic - Install LwipV6 static library in " ${libdir}

