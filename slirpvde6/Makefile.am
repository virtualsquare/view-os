AM_CPPFLAGS = -I$(top_srcdir)/include -DVDE -DCONFIG_SLIRP -DCONFIG_NEED_OFFSETOF -D_GNU_SOURCE
AM_CFLAGS = -g -O2

bin_PROGRAMS = slirpvde6

slirpvde6_SOURCES = \
									 bootp.c \
									 bootp.h \
									 configure.ac \
									 dnsforward.c \
									 dnsforward.h \
									 slirpvde6.c \
									 slirpvde6.h \
									 tftp.c \
									 tftp.h \
									 tftp.o \
									 xlocal.c \
									 xlocal.h 

slirpvde6_LDADD = -llwipv6

man1_MANS = slirpvde6.1
