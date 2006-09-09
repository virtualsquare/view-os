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

# Architecture directories
LWIPARCH=$(CONTRIBDIR)/ports/unix

#Set this to where you have the lwip core module checked out from CVS
#default assumes it's a dir named lwip at the same level as the contrib module
LWIPDIR=$(CONTRIBDIR)/../lwip-v6/src

# Add on
LWIPFILTERDIR=$(LWIPDIR)/userfilter
LWIPRADVDIR=$(LWIPDIR)/radv

#=============================================================================
# Defines
#=============================================================================

CCDEP=gcc
CC=gcc

CFLAGS=-g -Wall -fPIC

# Remove these for the makefile. 
# They are supposed to be declared in opt.h or lwipopts.h
#
#CFLAGS:=$(CFLAGS) -DLWIP_DEBUG 
#CFLAGS:=$(CFLAGS) -DLWIP_NL=1
#CFLAGS:=$(CFLAGS) -DLWIP_PACKET=1
#CFLAGS:=$(CFLAGS) -DRD235LIB=1
#CFLAGS:=$(CFLAGS) -DLWIP_COMPAT_SOCKETS=0 
#CFLAGS:=$(CFLAGS) -DIPv6
#CFLAGS:=$(CFLAGS) -DIPv4_CHECK_CHECKSUM=1
#CFLAGS:=$(CFLAGS) -DIPv4_FRAGMENTATION=1
#CFLAGS:=$(CFLAGS) -DIPv6_FRAGMENTATION=1
#CFLAGS:=$(CFLAGS) -DIPv6_AUTO_CONFIGURATION=1
#CFLAGS:=$(CFLAGS) -DIPv6_ROUTER_ADVERTISEMENT=0
#CFLAGS:=$(CFLAGS) -DIPv6_RADVCONF=0
#CFLAGS:=$(CFLAGS) -DLWIP_USERFILTER=0
#CFLAGS:=$(CFLAGS) -DLWIP_NAT=0

ARFLAGS=rs

#=============================================================================
# Headers 
#=============================================================================

#
# Architecture dependent
#
CFLAGS:=$(CFLAGS) -I$(LWIPARCH)/include   

#
# Core
#
CFLAGS:=$(CFLAGS)             \
	-I$(LWIPDIR)/include      \
	-I$(LWIPDIR)/include/ipv6 \
	-Iapps \
	-I.

#
# Add ons
#
CFLAGS:=$(CFLAGS) -I$(LWIPDIR)/include/userfilter 

CFLAGS:=$(CFLAGS) -I$(LWIPDIR)/include/radv


#=============================================================================
# Stack Core Sources
#=============================================================================

# COREFILES, CORE4FILES: The minimum set of files needed for lwIP.

#
# Different implementations of memory manager
#
#COREFILES=$(LWIPDIR)/core/mem.c $(LWIPDIR)/core/memp.c
#COREFILES=$(LWIPDIR)/core/mem_malloc.c $(LWIPDIR)/core/memp_dynmalloc.c 
COREFILES=$(LWIPDIR)/core/mem_malloc.c $(LWIPDIR)/core/memp_malloc.c

#
# Different implementation of 'pbuf' manager
#
#COREFILES:=$(COREFILES) $(LWIPDIR)/core/pbuf.c 
COREFILES:=$(COREFILES) $(LWIPDIR)/core/pbufnopool.c 

#
# Stack Core files 
#
COREFILES:=$(COREFILES)       \
	$(LWIPDIR)/core/netif.c   \
	$(LWIPDIR)/core/stats.c   \
	$(LWIPDIR)/core/sys.c     \
	$(LWIPDIR)/core/tcp.c     \
	$(LWIPDIR)/core/tcp_in.c  \
	$(LWIPDIR)/core/tcp_out.c \
	$(LWIPDIR)/core/udp.c     \
	$(LWIPDIR)/core/raw.c     \
	$(LWIPDIR)/core/packet.c  \
	$(LWIPDIR)/core/dhcp.c     

CORE6FILES=$(wildcard $(LWIPDIR)/core/ipv6/*.c) $(LWIPDIR)/core/inet6.c

#
# APIFILES: The files which implement the sequential and socket APIs.
#
APIFILES=$(LWIPDIR)/api/api_lib.c \
	$(LWIPDIR)/api/api_msg.c  \
	$(LWIPDIR)/api/tcpip.c    \
	$(LWIPDIR)/api/err.c      \
	$(LWIPDIR)/api/netlink.c

#
# Different implementations of Socket API. 
# - renzosockets.c needs RD235LIB to be defined
#
#APIFILES:=$(APIFILES) $(LWIPDIR)/api/renzosockets.c
APIFILES:=$(APIFILES) $(LWIPDIR)/api/sockets.c

#
# NETIFFILES: Files implementing various generic network interface functions.'
#
NETIFFILES=$(LWIPDIR)/netif/loopif.c \
	$(LWIPDIR)/netif/etharp.c

#=============================================================================
# Architecture specific files
#=============================================================================

# ARCHFILES: Architecture specific files.
#ARCHFILES=$(wildcard $(LWIPDIR)/arch/$(LWIPARCH)/*.c $(LWIPDIR)/arch/$(LWIPARCH)/netif/*.c)

#
# Different implementation of architecture backend
#
#ARCHFILES=$(LWIPARCH)/sys_arch_pipe.c 
ARCHFILES=$(LWIPARCH)/sys_arch.c 

ARCHFILES:=$(ARCHFILES)	$(LWIPARCH)/netif/vdeif.c 
ARCHFILES:=$(ARCHFILES)	$(LWIPARCH)/netif/tapif.c 
ARCHFILES:=$(ARCHFILES)	$(LWIPARCH)/netif/tunif.c


#=============================================================================
# Add on
#=============================================================================

# RADVFILES: Router Advertisement configuration loader (IPv6_RADVCONF)
RADVFILES=$(LWIPRADVDIR)/radvconf.c

# File of Userfilter syb-sytem (LWIP_USERFILTER)
LWIPFILTERFILES=$(LWIPFILTERDIR)/userfilter.c 

# Files of the NAT sub-system (LWIP_NAT)
LWIPFILTERFILES:=$(LWIPFILTERFILES)                \
	$(LWIPFILTERDIR)/nat/nat.c                     \
	$(LWIPFILTERDIR)/nat/nat_rules.c               \
	$(LWIPFILTERDIR)/nat/nat_tables.c              \
	$(LWIPFILTERDIR)/nat/nat_track_proto_tcp.c     \
	$(LWIPFILTERDIR)/nat/nat_track_proto_udp.c     \
	$(LWIPFILTERDIR)/nat/nat_track_proto_icmp4.c   \
	$(LWIPFILTERDIR)/nat/nat_track_proto_generic.c 

#=============================================================================
# Objects
#=============================================================================

# LWIPFILES: All the above.
LWIPFILES=$(COREFILES) $(CORE6FILES) $(APIFILES) $(NETIFFILES) $(ARCHFILES) $(LWIPFILTERFILES) $(RADVFILES)
LWIPFILESW=$(wildcard $(LWIPFILES))
LWIPOBJS=$(notdir $(LWIPFILESW:.c=.o))

#=============================================================================
# Targets 
#=============================================================================

# Shared library
LWIPLIB=liblwip.so

# Static library
STATICLWIPLIB=liblwip.a

%.o:
	$(CC) $(CFLAGS) -c $(<:.o=.c)

all: $(LWIPLIB) 
.PHONY: all

allstatic: $(STATICLWIPLIB)
.PHONY: allstatic

clean:
	rm -f *.o $(LWIPLIB) *.s .depend* *.core core $(STATICLWIPLIB)

depend dep: .depend
include .depend

$(LWIPLIB): $(LWIPOBJS) sharedlib.o unixlib.o
	$(CC) -g -nostartfiles -shared -o $@ $^

# NB: unixlib.o should not be included, it's used only by ViewOS 
# project. It's here only for debug.
$(STATICLWIPLIB): $(LWIPOBJS) unixlib.o
	$(AR) $(ARFLAGS) $(STATICLWIPLIB) $?

.depend: unixlib.c sharedlib.c $(LWIPFILES)
	$(CCDEP) $(CFLAGS) -MM $^ > .depend || rm -f .depend


