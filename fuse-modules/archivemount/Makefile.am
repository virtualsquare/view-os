moddir = $(libdir)/umview/modules

bin_PROGRAMS = archivemount

archivemount_SOURCES = archivemount.c

archivemount_LDADD = $(ARCHIVE_LIBS) $(FUSE_LIBS)

archivemount_CFLAGS = $(FUSE_CFLAGS)

if DEBUG
archivemount_CFLAGS += -g
else
archivemount_CFLAGS += -O2
endif

mod_LTLIBRARIES = umfusearchive.la

umfusearchive_la_SOURCES = archivemount.c

umfusearchive_la_CFLAGS = $(FUSE_CFLAGS) -D_UMFUSE

umfusearchive_la_LDFLAGS = -module -avoid-version -export-dynamic $(ARCHIVE_LIBS) 

man_MANS = archivemount.1
#dist_man_MANS = archivemount.1
EXTRA_DIST = CHANGELOG
