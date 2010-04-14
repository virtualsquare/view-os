ACLOCAL_AMFLAGS = -I m4

moddir = $(libdir)/umview/modules

DEVELFLAGS =

bin_PROGRAMS =	 ntfs-3g

mod_LTLIBRARIES = umfusentfs3g.la

dist_man8_MANS = ntfs-3g.8

ntfs_3g_SOURCES =	\
	ntfs-3g.c

umfusentfs3g_la_SOURCES = \
	ntfs-3g.c

umfusentfs3g_la_CFLAGS = \
	-Wall					\
	-DHAVE_CONFIG_H				\
	-D_FILE_OFFSET_BITS=64			\
	-D_UMFUSE			\
	$(DEVELFLAGS) \
	-I$(includedir)/umview \
	-I/usr/local/include \
	-I/usr/include/ntfs-3g

umfusentfs3g_la_LDFLAGS = \
	-module \
	-avoid-version \
	-export-dynamic \
	-lntfs-3g

ntfs_3g_CFLAGS =				\
	-Wall					\
	-DHAVE_CONFIG_H				\
	-D_FILE_OFFSET_BITS=64			\
	-I/usr/local/include \
	-I/usr/include/ntfs-3g

ntfs_3g_LDADD =				\
	-L/usr/local/lib \
	-lfuse \
	-lntfs-3g

install-data-hook:
	cd "$(DESTDIR)/$(moddir)" && rm -f $(mod_LTLIBRARIES)

install-exec-local:
	$(INSTALL) -d "$(DESTDIR)/usr/sbin"
	$(LN_S) -f "$(DESTDIR)/$(bindir)/fuse-ntfs" "$(DESTDIR)/sbin/mount.fuse-ntfs"
