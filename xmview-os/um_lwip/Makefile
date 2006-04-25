
ifeq ($(RELEASE),true)
LWIPDIR=
else
LWIPDIR=../../LWIPV6
endif

LWIPSRCDIR=$(LWIPDIR)/lwip-v6/src
LWIPCONTRIBDIR=$(LWIPDIR)/lwip-contrib/ports/unix

CFLAGS=-D_GNU_SOURCE -ggdb -D_FILE_OFFSET_BITS=64 -rdynamic -I$(LWIPSRCDIR)/include -I$(LWIPSRCDIR)/include/ipv6 -I$(LWIPCONTRIBDIR)/include

ALL=lwipv6.so

ifeq ($(LWIPDIR),)
all:
	@echo "***********************************************************************"
	@echo "To compile um_lwip, please get and unpack lwipv6 and restart make with:"
	@echo ""
	@echo "make LWIPDIR=/some/directory/lwipv6-x.y"
	@echo "***********************************************************************"
else
all: $(ALL)
endif

lwipv6.so: lwipv6.o
	$(CC) -shared -o $@ $<

lwipv6.o: lwipv6.c module.h 

cleanall:
	rm -rf $(ALL) *.o

clean: cleanall

install: all
	install $(ALL) ${libdir}

.PHONY: all clean cleanall install
