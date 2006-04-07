#
# Copyright (c) 2001, 2002 Swedish Institute of Computer Science.
# All rights reserved. 
# 
# Redistribution and use in source and binary forms, with or without modification, 
# are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
# 3. The name of the author may not be used to endorse or promote products
#    derived from this software without specific prior written permission. 
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED 
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT 
# SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, 
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT 
# OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING 
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY 
# OF SUCH DAMAGE.
#
# This file is part of the lwIP TCP/IP stack.
# 
# Author: Adam Dunkels <adam@sics.se>
#

#=============================================================================
# Directories
#=============================================================================

CONTRIBDIR=../../../..
LWIPARCH=$(CONTRIBDIR)/ports/unix

#Set this to where you have the lwip core module checked out from CVS
#default assumes it's a dir named lwip at the same level as the contrib module
LWIPDIR=$(CONTRIBDIR)/../lwip-v6/src

# added by Diego Billi
LWIPFILTERDIR=$(LWIPDIR)/userfilter

#=============================================================================
# Defines
#=============================================================================

CCDEP=gcc
CC=gcc
#CFLAGS=-g -Wall -fPIC -DIPv4 -DLWIP_DEBUG 
#CFLAGS=-g -Wall -fPIC -DIPv6 -DLWIP_DEBUG -DLWIP_NL -DLWIP_PACKET -DRD235LIB -DLWIP_COMPAT_SOCKETS=0

CFLAGS=-g -Wall -fPIC
CFLAGS:=$(CFLAGS) -DIPv6
CFLAGS:=$(CFLAGS) -DIPv4_CHECK_CHECKSUM 
CFLAGS:=$(CFLAGS) -DIPv4_FRAGMENTATION
CFLAGS:=$(CFLAGS) -DIPv6_FRAGMENTATION
#CFLAGS:=$(CFLAGS) -DIPv6_AUTO_CONFIGURATION
#CFLAGS:=$(CFLAGS) -DIPv6_PMTU_DISCOVERY   not working yet
CFLAGS:=$(CFLAGS) -DLWIP_NL    
CFLAGS:=$(CFLAGS) -DLWIP_PACKET 
CFLAGS:=$(CFLAGS) -DRD235LIB 
CFLAGS:=$(CFLAGS) -DLWIP_COMPAT_SOCKETS=0 
CFLAGS:=$(CFLAGS) -DLWIP_DEBUG 


# added by Diego Billi
CFLAGS:=$(CFLAGS) -DLWIP_USERFILTER 
#CFLAGS:=$(CFLAGS) -DLWIP_NAT 

CFLAGS:=$(CFLAGS) \
	-I$(LWIPDIR)/include \
	-I$(LWIPARCH)/include \
	-I$(LWIPDIR)/include/ipv6 \
	-Iapps -I.

# added by Diego Billi
CFLAGS:=$(CFLAGS) \
	-I$(LWIPDIR)/include/userfilter 

# added by Diego Billi
ARFLAGS=rs

#=============================================================================
# Files
#=============================================================================

# COREFILES, CORE4FILES: The minimum set of files needed for lwIP.
# COREFILES= 
#COREFILES=$(LWIPDIR)/core/mem_malloc.c $(LWIPDIR)/core/memp_malloc.c
COREFILES=$(LWIPDIR)/core/mem_malloc.c \
	$(LWIPDIR)/core/memp_dynmalloc.c \
	$(LWIPDIR)/core/netif.c \
	$(LWIPDIR)/core/pbufnopool.c \
	$(LWIPDIR)/core/stats.c \
	$(LWIPDIR)/core/sys.c \
        $(LWIPDIR)/core/tcp.c \
	$(LWIPDIR)/core/tcp_in.c \
        $(LWIPDIR)/core/tcp_out.c \
	$(LWIPDIR)/core/udp.c \
	$(LWIPDIR)/core/raw.c \
	$(LWIPDIR)/core/packet.c

CORE6FILES=$(wildcard $(LWIPDIR)/core/ipv6/*.c) $(LWIPDIR)/core/inet6.c

# APIFILES: The files which implement the sequential and socket APIs.
APIFILES=$(LWIPDIR)/api/api_lib.c \
	$(LWIPDIR)/api/api_msg.c \
	$(LWIPDIR)/api/tcpip.c \
	$(LWIPDIR)/api/err.c \
	$(LWIPDIR)/api/sockets.c\
	$(LWIPDIR)/api/netlink.c

# NETIFFILES: Files implementing various generic network interface functions.'
NETIFFILES=$(LWIPDIR)/netif/loopif.c \
	$(LWIPDIR)/netif/etharp.c

# ARCHFILES: Architecture specific files.
#ARCHFILES=$(wildcard $(LWIPDIR)/arch/$(LWIPARCH)/*.c $(LWIPDIR)/arch/$(LWIPARCH)/netif/*.c)
ARCHFILES=$(LWIPARCH)/sys_arch_pipe.c \
	$(LWIPARCH)/netif/vdeif.c \
	$(LWIPARCH)/netif/tapif.c \
	$(LWIPARCH)/netif/tunif.c

# File of Userfilter syb-sytem (LWIP_USERFILTER)
LWIPFILTERFILES=$(LWIPFILTERDIR)/userfilter.c 

# Files of the NAT sub-system (LWIP_NAT)
LWIPFILTERFILES:=$(LWIPFILTERFILES) $(LWIPFILTERDIR)/nat/nat.c 
LWIPFILTERFILES:=$(LWIPFILTERFILES) $(LWIPFILTERDIR)/nat/nat_rules.c 
LWIPFILTERFILES:=$(LWIPFILTERFILES) $(LWIPFILTERDIR)/nat/nat_tables.c 
LWIPFILTERFILES:=$(LWIPFILTERFILES) $(LWIPFILTERDIR)/nat/nat_track_proto_tcp.c 
LWIPFILTERFILES:=$(LWIPFILTERFILES) $(LWIPFILTERDIR)/nat/nat_track_proto_udp.c 
LWIPFILTERFILES:=$(LWIPFILTERFILES) $(LWIPFILTERDIR)/nat/nat_track_proto_icmp4.c 
LWIPFILTERFILES:=$(LWIPFILTERFILES) $(LWIPFILTERDIR)/nat/nat_track_proto_generic.c 


#=============================================================================
# Objects
#=============================================================================

# LWIPFILES: All the above.
#LWIPFILES=$(COREFILES) $(CORE6FILES) $(APIFILES) $(NETIFFILES) $(ARCHFILES)
LWIPFILES=$(COREFILES) $(CORE6FILES) $(APIFILES) $(NETIFFILES) $(ARCHFILES)  $(LWIPFILTERFILES)
LWIPFILESW=$(wildcard $(LWIPFILES))
LWIPOBJS=$(notdir $(LWIPFILESW:.c=.o))

#=============================================================================
# Targets
#=============================================================================

LWIPLIB=liblwip.so

# added by Diego Billi
STATICLWIPLIB=liblwip.a


%.o:
	$(CC) $(CFLAGS) -c $(<:.o=.c)

all: $(LWIPLIB) 
.PHONY: all

# added by Diego Billi
allstatic: $(STATICLWIPLIB)
.PHONY: allstatic

clean:
#	rm -f *.o $(LWIPLIB) *.s .depend* *.core core
	rm -f *.o $(LWIPLIB) *.s .depend* *.core core $(STATICLWIPLIB)

depend dep: .depend

include .depend

$(LWIPLIB): $(LWIPOBJS) unixlib.o
	$(CC) -g -nostartfiles -shared -o $@ $^

# added by Diego Billi
# NB: unixlib.o should not be included, it's used only by ViewOS 
# project. It's here only for debug.
$(STATICLWIPLIB): $(LWIPOBJS) unixlib.o
	$(AR) $(ARFLAGS) $(STATICLWIPLIB) $?

.depend: unixlib.c $(LWIPFILES)
	$(CCDEP) $(CFLAGS) -MM $^ > .depend || rm -f .depend




