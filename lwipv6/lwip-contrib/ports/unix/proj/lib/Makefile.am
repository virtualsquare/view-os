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

CONTRIBDIR = ../../../..

# Architecture directories
LWIPARCH = $(CONTRIBDIR)/ports/unix

#Set this to where you have the lwip core module checked out from CVS
#default assumes it's a dir named lwip at the same level as the contrib module
LWIPDIR = $(CONTRIBDIR)/../lwip-v6/src

# Add on
LWIPFILTERDIR = $(LWIPDIR)/userfilter
LWIPRADVDIR = $(LWIPDIR)/radv

#=============================================================================
# Headers 
#=============================================================================

#
# Architecture dependent
#
AM_CPPFLAGS = -I$(LWIPARCH)/include

#
# Core
#
AM_CPPFLAGS += -I$(LWIPDIR)/include -I$(LWIPDIR)/include/ipv6 -Iapps -I.

#
# Add ons
#
AM_CPPFLAGS += -I$(LWIPDIR)/include/userfilter
AM_CPPFLAGS += -I$(LWIPDIR)/include/radv

LWIPHEADERS = $(LWIPDIR)/include/lwip/arch.h \
              $(LWIPDIR)/include/lwip/opt.h  \
              $(LWIPDIR)/include/lwip/def.h  \
              $(LWIPDIR)/include/lwip/mem.h  \
              $(LWIPDIR)/include/lwip/sys.h  \
              $(LWIPDIR)/include/lwip/stats.h \
              $(LWIPDIR)/include/lwip/debug.h \
              $(LWIPDIR)/include/lwip/memp.h \
              $(LWIPDIR)/include/lwip/pbuf.h \
              $(LWIPDIR)/include/lwip/udp.h \
              $(LWIPDIR)/include/lwip/raw.h \
              $(LWIPDIR)/include/lwip/tcp.h \
              $(LWIPDIR)/include/lwip/netif.h \
              $(LWIPDIR)/include/lwip/packet.h \
              $(LWIPDIR)/include/lwip/err.h \
              $(LWIPDIR)/include/lwip/api.h \
              $(LWIPDIR)/include/lwip/api_msg.h \
              $(LWIPDIR)/include/lwip/tcpip.h \
              $(LWIPDIR)/include/lwip/sockets.h \
              $(LWIPDIR)/include/lwip/netlink.h \
              $(LWIPDIR)/include/lwip/netlinkdefs.h \
              $(LWIPDIR)/include/lwip/if.h \
              $(LWIPDIR)/include/lwip/native_syscalls.h \
              $(LWIPDIR)/include/lwip/snmp.h \
              $(LWIPDIR)/include/lwip/arphdr.h \
              $(LWIPDIR)/include/lwip/stack.h \
              $(LWIPDIR)/include/lwip/lwslirp.h \
              $(LWIPDIR)/include/ipv6/lwip/ip.h \
              $(LWIPDIR)/include/ipv6/lwip/ip_addr.h \
              $(LWIPDIR)/include/ipv6/lwip/ip_autoconf.h \
              $(LWIPDIR)/include/ipv6/lwip/ip_route.h \
              $(LWIPDIR)/include/ipv6/lwip/ip_frag.h \
              $(LWIPDIR)/include/ipv6/lwip/inet.h \
              $(LWIPDIR)/include/ipv6/lwip/icmp.h \
              $(LWIPDIR)/include/netif/etharp.h \
              $(LWIPDIR)/include/netif/loopif.h \
              $(LWIPDIR)/include/userfilter/lwip/userfilter.h \
              $(LWIPARCH)/include/vde.h \
              $(LWIPARCH)/include/netif/vdeif.h \
              $(LWIPARCH)/include/netif/tunif.h \
              $(LWIPARCH)/include/netif/tapif.h \
              $(LWIPARCH)/include/netif/slirpif.h \
              $(LWIPARCH)/include/arch/cc.h \
              $(LWIPARCH)/include/arch/sys_arch.h \
              $(LWIPARCH)/include/arch/perf.h \
              lwipopts.h



#=============================================================================
# Stack Core Sources
#=============================================================================

# COREFILES, CORE4FILES: The minimum set of files needed for lwIP.

#
# Different implementations of memory manager
#
#COREFILES=$(LWIPDIR)/core/mem.c $(LWIPDIR)/core/memp.c
#COREFILES=$(LWIPDIR)/core/mem_malloc.c $(LWIPDIR)/core/memp_dynmalloc.c 
COREFILES = $(LWIPDIR)/core/mem_malloc.c $(LWIPDIR)/core/memp_malloc.c

#
# Different implementation of 'pbuf' manager
#
#COREFILES:=$(COREFILES) $(LWIPDIR)/core/pbuf.c
COREFILES += $(LWIPDIR)/core/pbufnopool.c

#
# Stack Core files 
#
COREFILES += \
	$(LWIPDIR)/core/netif.c   \
	$(LWIPDIR)/core/stats.c   \
	$(LWIPDIR)/core/sys.c     \
	$(LWIPDIR)/core/tcp.c     \
	$(LWIPDIR)/core/tcp_in.c  \
	$(LWIPDIR)/core/tcp_out.c \
	$(LWIPDIR)/core/udp.c     \
	$(LWIPDIR)/core/raw.c     \
	$(LWIPDIR)/core/packet.c  \
	$(LWIPDIR)/core/dhcp.c    \
	$(LWIPDIR)/core/lwslirp.c  

CORE6FILES = $(LWIPDIR)/core/inet6.c \
             $(LWIPDIR)/core/ipv6/icmp6.c \
             $(LWIPDIR)/core/ipv6/ip6.c \
             $(LWIPDIR)/core/ipv6/ip6_addr.c \
             $(LWIPDIR)/core/ipv6/ip6_route.c \
             $(LWIPDIR)/core/ipv6/ip6_frag.c \
             $(LWIPDIR)/core/ipv6/ip6_autoconf.c \
             $(LWIPDIR)/core/ipv6/ip6_radv.c

#
# APIFILES: The files which implement the sequential and socket APIs.
#
APIFILES = $(LWIPDIR)/api/api_lib.c \
	$(LWIPDIR)/api/api_msg.c  \
	$(LWIPDIR)/api/tcpip.c    \
	$(LWIPDIR)/api/err.c      \
	$(LWIPDIR)/api/netlink.c

#
# Different implementations of Socket API. 
# - renzosockets.c needs RD235LIB to be defined
#
#APIFILES:=$(APIFILES) $(LWIPDIR)/api/renzosockets.c
APIFILES += $(LWIPDIR)/api/sockets.c

#
# NETIFFILES: Files implementing various generic network interface functions.'
#
NETIFFILES = $(LWIPDIR)/netif/loopif.c \
	$(LWIPDIR)/netif/etharp.c

#=============================================================================
# Architecture specific files
#=============================================================================

# ARCHFILES: Architecture specific files.
#ARCHFILES=$(wildcard $(LWIPDIR)/arch/$(LWIPARCH)/*.c $(LWIPDIR)/arch/$(LWIPARCH)/netif/*.c)

#
# Different implementation of architecture backend
#
ARCHFILES=$(LWIPARCH)/sys_arch_pipe.c 
#ARCHFILES=$(LWIPARCH)/sys_arch.2sem.c 
#ARCHFILES = $(LWIPARCH)/sys_arch.c 

ARCHFILES += $(LWIPARCH)/netif/vdeif.c
ARCHFILES += $(LWIPARCH)/netif/slirpif.c
ARCHFILES += $(LWIPARCH)/netif/tapif.c
ARCHFILES += $(LWIPARCH)/netif/tunif.c


#=============================================================================
# Add on
#=============================================================================

# RADVFILES: Router Advertisement configuration loader (IPv6_RADVCONF)
RADVFILES = $(LWIPRADVDIR)/radvconf.c

# File of Userfilter syb-sytem (LWIP_USERFILTER)
LWIPFILTERFILES = $(LWIPFILTERDIR)/userfilter.c 

# Files of the NAT sub-system (LWIP_NAT)
LWIPFILTERFILES +=                                  \
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
LWIPFILES = $(COREFILES) $(CORE6FILES) $(APIFILES) $(NETIFFILES) $(ARCHFILES) $(LWIPFILTERFILES) $(RADVFILES)
#LWIPFILESW = $(wildcard $(LWIPFILES))
#LWIPOBJS = $(notdir $(LWIPFILESW:.c=.o))

#=============================================================================
# Targets 
#=============================================================================


lib_LTLIBRARIES = liblwipv6.la

# NB: unixlib.o should not be included, it's used only by ViewOS 
# project. It's here only for debug.

liblwipv6_la_SOURCES = $(LWIPFILES) $(LWIPHEADERS) sharedlib.c unixlib.c
liblwipv6_la_LDFLAGS = -version-number 2:0:0 -Xcompiler -nostartfiles
# liblwip_la_LIBADD = sharedlib.lo unixlib.lo

include_HEADERS = $(LWIPARCH)/include/lwipv6.h

