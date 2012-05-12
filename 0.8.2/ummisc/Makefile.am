include $(top_srcdir)/modules-common.mk

mod_LTLIBRARIES = ummisc.la umproc.la

#dist_man1_MANS = ummisc.1viewos

ummisc_la_SOURCES = ummisc.c ummiscfun.c ummiscfun.h
ummisc_la_LDFLAGS = $(AM_LDFLAGS) -lpthread
ummisc_la_CPPFLAGS = $(AM_CPPFLAGS) 

umproc_la_SOURCES = umproc.c 
umproc_la_LDFLAGS = $(AM_LDFLAGS) -lpthread
umproc_la_CPPFLAGS = $(AM_CPPFLAGS) 
