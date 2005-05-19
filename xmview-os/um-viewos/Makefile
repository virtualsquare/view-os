DEBUGLEVEL=2
CBASEFLAGS=-Wall -D_GNU_SOURCE
CDEBUGFLAGS=-g -ggdb -DGDEBUG_ENABLED -DGDEBUG_LEVEL=$(DEBUGLEVEL)


OBJS=gdebug.o capture_sc.o canonicalize.o utils.o umproc.o services.o sctab.o umview.o um_services.o scmap.o um_basicio.o um_plusio.o um_socket.o um_wdm.o um_select.o um_ioctl.o ptrace_multi_test.o

LDFLAGS=-rdynamic

LOADLIBES=-ldl -lpthread

ifeq ($(RELEASE),true)

# Release version (default is nodebug)
CFLAGS=$(CBASEFLAGS)
all: $(OBJS) umview

debug: clean
	$(MAKE) CFLAGS="$(CBASEFLAGS) $(CDEBUGFLAGS)"

else

# Development version (default is debug)
CFLAGS=$(CBASEFLAGS) $(CDEBUGFLAGS)
all: $(OBJS) umview

nodebug: clean
	$(MAKE) CFLAGS="$(CBASEFLAGS)"

endif

umview: $(OBJS)

syscallnames.h: syscallnames.sh
	./syscallnames.sh

%.d: %.c
	@[[ ! -e syscallnames.h ]] && touch -t 197001010100.00 syscallnames.h || true
	@set -e; $(CC) -MM $(CPPFLAGS) $(@:.d=.c) | sed 's/\($*\)\.o[ :]*/\1.o $@ : /g' > $@; [ -s $@ ] || rm -f $@

-include $(OBJS:.o=.d)

clean:	
	rm -f *.o
	rm -f umview

distclean: clean
	rm -f *.d
	rm -f syscallnames.h

install: all
	install umview ${bindir}

.PHONY: all clean install distclean 
