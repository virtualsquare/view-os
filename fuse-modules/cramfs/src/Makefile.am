bin_PROGRAMS = fusecram
fusecram_SOURCES = fusecram.c cramfs.c cramfs.h

# set the include path found by configure
INCLUDES= -I.. $(all_includes)

# the library search path.
fusecram_LDFLAGS = $(all_libraries)

AM_CFLAGS = -Wall -g `pkg-config --cflags glib-2.0` -D_FILE_OFFSET_BITS=64
AM_LDFLAGS = -g -lfuse `pkg-config --libs glib-2.0` -lz
