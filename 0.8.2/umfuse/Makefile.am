include $(top_srcdir)/modules-common.mk

mod_LTLIBRARIES = umfuse.la

dist_man1_MANS = umfuse.1viewos

umfuse_la_SOURCES = umfuse.c umfusestd.c umfuseargs.c umfusestd.h fuse_opt.c umfuse_node.c
umfuse_la_LDFLAGS = $(AM_LDFLAGS) -lpthread
umfuse_la_CPPFLAGS = $(AM_CPPFLAGS) -DFUSE_USE_VERSION=26

#DEVELFLAGS = -D__UMFUSE_DEBUG__ -D__UMFUSE_DEBUG_LEVEL__=10
#DEVELFLAGS=-D__UMFUSE_EXPERIMENTAL__

