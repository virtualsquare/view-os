ifndef ($(bindir))
bindir=/usr/local/bin
endif
ifndef ($(mandir))
mandir=/usr/local/man
endif

RELEASE=false
DEBUGLEVEL=0
#CBASEFLAGS=-Wall -D_GNU_SOURCE -I../include -DINSTALLDIR=\"$(bindir)\" -D_PROC_MEM_TEST
#CBASEFLAGS=-Wall -D_GNU_SOURCE -I../include -DINSTALLDIR=\"$(bindir)\" -D_USE_PSELECT -D_UM_MMAP
CBASEFLAGS=-Wall -D_GNU_SOURCE -I../include -DINSTALLDIR=\"$(bindir)\" -D_UM_MMAP -D_USE_PSELECT
CDEBUGFLAGS=-g3 -ggdb3 -DGDEBUG_ENABLED -DGDEBUG_LEVEL=$(DEBUGLEVEL)
CPPFLAGS+=-I../include

#OBJS=gdebug.o capture_sc.o canonicalize.o utils.o umproc.o services.o sctab.o umview.o um_services.o scmap.o um_basicio.o um_plusio.o um_socket.o um_wdm.o um_select.o um_ioctl.o ptrace_multi_test.o um_exec.o

OBJS=capture_sc.o canonicalize.o utils.o umproc.o services.o sctab.o umview.o um_services.o scmap.o um_basicio.o um_plusio.o um_socket.o um_wdm.o um_select.o um_ioctl.o ptrace_multi_test.o um_exec.o capture_nested.o treepoch.o um_mmap.o mainpoll.o pcb.o um_signal.o um_time.o um_uname.o

PCB_MODULES=pcb.00.capture.h pcb.00.mainpoll.h pcb.01.sctab.h pcb.02.umproc.h pcb.03.mmap.h pcb.04.select.h

LDFLAGS=-rdynamic -L../gdebug

LOADLIBES=-ldl -lpthread -lgdebug

ifeq ($(RELEASE),true)

# Release version (default is nodebug)
CFLAGS=$(CBASEFLAGS) 
all: $(OBJS) umview umbinwrap

debug: clean
	$(MAKE) CFLAGS="$(CBASEFLAGS) $(CDEBUGFLAGS)"

else

# Development version (default is debug)
CFLAGS=$(CBASEFLAGS) $(CDEBUGFLAGS)
all: $(OBJS) umview umbinwrap

nodebug: clean
	$(MAKE) CFLAGS="$(CBASEFLAGS)"

endif

pcb-all.h: $(PCB_MODULES)
	echo "/* DO NOT EDIT. File Automagically generated */" > pcb-all.h
	cat $(PCB_MODULES) >> pcb-all.h

umview: $(OBJS)

%.d: %.c
#	@[[ ! -e syscallnames.h ]] && touch -t 197001010100.00 syscallnames.h || true
	@set -e; $(CC) -MM $(CPPFLAGS) $(@:.d=.c) | sed 's/\($*\)\.o[ :]*/\1.o $@ : /g' > $@; [ -s $@ ] || rm -f $@

ifeq ($(PIVOTING),true)

syscall_code.c syscall_code.h: compile_code.sh
	./compile_code.sh syscall_code.h syscall_code.c

endif

-include $(OBJS:.o=.d)

clean:	
	rm -f *.o
	rm -f umview
	rm -f umbinwrap

distclean: clean
	rm -f *.d
	rm -f syscall_code.h syscall_code.c

install: all
	install umview ${bindir}
	install umbinwrap ${bindir}
	install umview.1 ${mandir}/man1

.PHONY: all clean install distclean 
