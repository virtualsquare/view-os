LDFLAGS= -L../um_lib 
LOADLIBES= -lumlib

ALL= um_add_service um_mov_service um_ls_service um_lock_service um_del_service
ALLMAN= um_add_service.1 um_mov_service.1 um_ls_service.1 um_lock_service.1 um_del_service.1

all: $(ALL)

um_add_service: um_add_service.o ../um_lib/libumlib.a

um_mov_service: um_mov_service.o ../um_lib/libumlib.a

um_ls_service: um_ls_service.o ../um_lib/libumlib.a

um_lock_service: um_lock_service.o ../um_lib/libumlib.a

um_del_service: um_del_service.o ../um_lib/libumlib.a

distclean: clean

cleanall:
	rm -f $(ALL)

clean: cleanall
	rm -f *.o

install: all
	install $(ALL) ${bindir}
	install $(ALLMAN) ${mandir}/man1
