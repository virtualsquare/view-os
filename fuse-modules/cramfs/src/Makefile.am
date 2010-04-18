moddir = $(libdir)/umview/modules

bin_PROGRAMS = fusecram

mod_LTLIBRARIES = umfusecram.la

fusecram_SOURCES = fusecram.c cramfs.c cramfs.h v2fuseutils.c
fusecram_LDFLAGS = -lfuse `pkg-config --libs glib-2.0` -lz 

fusecram_CFLAGS = -I.. $(all_includes) -Wall `pkg-config --cflags glib-2.0` -D_FILE_OFFSET_BITS=64

umfusecram_la_SOURCES = fusecram.c cramfs.c cramfs.h v2fuseutils.c
umfusecram_la_CFLAGS = -I.. $(all_includes) -Wall `pkg-config --cflags glib-2.0` -D_FILE_OFFSET_BITS=64

umfusecram_la_LDFLAGS = -module -avoid-version -export-dynamic `pkg-config --libs glib-2.0` -lz

#AM_CFLAGS = -Wall -g `pkg-config --cflags glib-2.0` -D_FILE_OFFSET_BITS=64
#AM_LDFLAGS = -g -lfuse `pkg-config --libs glib-2.0` -lz 
