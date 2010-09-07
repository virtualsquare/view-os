#=======================================================================
#
#  uNat (userspace NAT) Makefile
#  Diego Billi (c) 2005-2006 - GPL
#
#=======================================================================

CC = gcc
LD = gcc
RM = rm 

CPPFLAGS =
CFLAGS = -Wall -O2 -ggdb
CFLAGS:=$(CFLAGS) -DVDE 

# You MUST set these flags also in the LWIV6a Makefile
CFLAGS:=$(CFLAGS) -DIPv6_AUTO_CONFIGURATION
CFLAGS:=$(CFLAGS) -DLWIP_USERFILTER 
CFLAGS:=$(CFLAGS) -DLWIP_NAT 
#CFLAGS:=$(CFLAGS) -DLWIP_DEBUG


LDFLAGS=-lpthread

LDOPTS = 

#=======================================================================
# Lwip-v6 Files
#=======================================================================

LWIPMAINDIR=../lwipv6

CONTRIBDIR=$(LWIPMAINDIR)/lwip-contrib
LWIPARCH=$(CONTRIBDIR)/ports/unix
LWIPDIR=$(LWIPMAINDIR)/lwip-v6/src
LWIPFILTERDIR=$(LWIPDIR)/userfilter

LWIPLIBSTATIC=$(CONTRIBDIR)/ports/unix/proj/lib/liblwip.a

CFLAGS:=$(CFLAGS) \
	-I$(LWIPDIR)/include \
	-I$(LWIPDIR)/include/ipv6 \
	-I$(LWIPARCH)/include \
	-I$(LWIPARCH)/proj/lib \
	-I$(LWIPDIR)/include/userfilter \
	-Iapps -I. 

#=======================================================================
# uNAT files
#=======================================================================

UNATDIR = .

CFLAGS:=$(CFLAGS) -I$(UNATDIR)/include

UNATFILES=$(UNATDIR)/src/main.c $(UNATDIR)/src/commands.c 

UNATOBJS=$(notdir $(UNATFILES:.c=.o))

#=======================================================================
# Targets
#=======================================================================

all: unatd 
.PHONY: all clean help 

unatd: $(UNATOBJS) 
	@echo $(LWIPLIBSTATIC)
	@echo $(UNATOBJS) 
	$(CC) $(CFLAGS) $(LDFLAGS) -o unatd $(UNATOBJS) -llwipv6

main.o: $(UNATDIR)/src/main.c
	$(CC) $(CFLAGS) -c $(UNATDIR)/src/main.c
	
commands.o: $(UNATDIR)/src/commands.c
	$(CC) $(CFLAGS) -c $(UNATDIR)/src/commands.c

# Goes into LWIPV6a folder and compile the static library
$(LWIPLIBSTATIC): 
	@( cd $(LWIPMAINDIR); make allstatic )

clean:
	$(RM) -f $(UNATOBJS) unatd *~

help:
	@echo "Targets:"
	@echo "unatd - Compile uNAT  daemon"
	@echo "clean - Clean directory"
	@echo "help  - Print this help"
