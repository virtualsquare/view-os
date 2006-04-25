ifeq ($(LIBDIR),)
LIBDIR=/usr/local/lib
endif

CFLAGS= -fPIC -g -ggdb -D_GNU_SOURCE
OBJS=syscalls.o socketcalls.o exec.o dir.o stdio.o
VERSION=0.1
LIBNAME=pure_libc

$(LIBNAME).$(VERSION).so: $(OBJS)
	gcc -shared -nostartfiles -o $@ $(OBJS)

syscalls.o: syscalls.c pure_libc.h

socketcalls.o: socketcalls.c pure_libc.h

exec.o: exec.c

dir.o: dir.c

stdio.o: stdio.c

install: $(LIBNAME).$(VERSION).so
	install $(LIBNAME).$(VERSION).so $(LIBDIR)
	rm -rf $(LIBDIR)/lib$(LIBNAME).so
	ln -s $(LIBDIR)/$(LIBNAME).$(VERSION).so $(LIBDIR)/lib$(LIBNAME).so

clean:
	rm -rf *.o $(LIBNAME).$(VERSION).so
