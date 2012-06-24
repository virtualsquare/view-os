moddir = $(libdir)/umview/modules

DEVELFLAGS =

# DARWIN always uses the latest libext2fs library included in
# fuse-ext2 source code distribution
# LINUX can use the same library statically linked (--enable-static-ext2fs)
# or the shared library of your GNU-Linux distribution.
# in this latter case use --disable-fileio if the library already includes
# the new features for fuse-ext2 (that should be included in e2fsprogs 1.42)
#if LINUX

if LINUX
LINUXE2LIBS = -lext2fs
if DISABLEFILEIO
LINUXE2CFLAGS =
else
LINUXE2CFLAGS = -DPRIVATE_FILEIO
endif
endif

bin_PROGRAMS =		\
	fuse-ext2	\
	fuse-ext2.probe

if LINUX
mod_LTLIBRARIES = umfuseext2.la
endif

fuse_ext2_probe_SOURCES =	\
	fuse-ext2.h \
	fuse-ext2.probe.c \
	do_probe.c

#if DARWIN
#fuse_ext2_probe_CFLAGS =			\
#	-Wall					\
#	-DHAVE_CONFIG_H				\
#	-D_FILE_OFFSET_BITS=64			\
#	-DTHREAD_LOCKS \
#	-I$(top_srcdir)/e2fsprogs-1.41.12.newgit \
#	-I/usr/local/include
#
#fuse_ext2_probe_LDADD =				\
#	../e2fsprogs-1.41.12.newgit/ext2fs/libext2fs.a	\
#	../e2fsprogs-1.41.12.newgit/et/libcom_err.a	\
#	-L/usr/local/lib \
#	-lfuse
#endif
if LINUX
fuse_ext2_probe_CFLAGS = 	\
	-Wall					\
	-DHAVE_CONFIG_H				\
	-D_FILE_OFFSET_BITS=64			\
	-DTHREAD_LOCKS \
	$(LINUXE2CFLAGS)	\
	-I/usr/local/include 

fuse_ext2_probe_LDADD = \
	-L/usr/local/lib \
	-lfuse \
	$(LINUXE2LIBS)
endif

if DISABLEFILEIO
fuse_ext2_SOURCES =	\
	fuse-ext2.h \
	fuse-ext2.c \
	vnode_hash.c \
	do_probe.c \
	do_check.c \
	do_fillstatbuf.c \
	do_readinode.c \
	do_killfilebyinode.c \
	op_init.c \
	op_destroy.c \
	op_access.c \
	op_fgetattr.c \
	op_getattr.c \
	op_open.c \
	op_read.c \
	op_readdir.c \
	op_readlink.c \
	op_release.c \
	op_statfs.c \
	op_chown.c \
	op_chmod.c \
	op_create.c \
	op_flush.c \
	op_fsync.c \
	op_mkdir.c \
	op_rmdir.c \
	op_unlink.c \
	op_utimens.c \
	op_write.c \
	op_mknod.c \
	op_symlink.c \
	op_truncate.c \
	op_link.c \
	op_rename.c
else
fuse_ext2_SOURCES = \
	fuse-ext2.h \
	fuse-ext2.c \
	vnode_hash.c \
	do_probe.c \
	do_check.c \
	do_fillstatbuf.c \
	do_readinode.c \
	do_killfilebyinode.c \
	op_init.c \
	op_destroy.c \
	op_access.c \
	op_fgetattr.c \
	op_getattr.c \
	op_open.c \
	op_read.c \
	op_readdir.c \
	op_readlink.c \
	op_release.c \
	op_statfs.c \
	op_chown.c \
	op_chmod.c \
	op_create.c \
	op_flush.c \
	op_fsync.c \
	op_mkdir.c \
	op_rmdir.c \
	op_unlink.c \
	op_utimens.c \
	op_write.c \
	op_mknod.c \
	op_symlink.c \
	op_truncate.c \
	op_link.c \
	op_rename.c \
	ext2-fileio.c
endif

if LINUX
if DISABLEFILEIO
umfuseext2_la_SOURCES = \
	fuse-ext2.h \
	fuse-ext2.c \
	vnode_hash.c \
	do_probe.c \
	do_check.c \
	do_fillstatbuf.c \
	do_readinode.c \
	do_killfilebyinode.c \
	op_init.c \
	op_destroy.c \
	op_access.c \
	op_fgetattr.c \
	op_getattr.c \
	op_open.c \
	op_read.c \
	op_readdir.c \
	op_readlink.c \
	op_release.c \
	op_statfs.c \
	op_chown.c \
	op_chmod.c \
	op_create.c \
	op_flush.c \
	op_fsync.c \
	op_mkdir.c \
	op_rmdir.c \
	op_unlink.c \
	op_utimens.c \
	op_write.c \
	op_mknod.c \
	op_symlink.c \
	op_truncate.c \
	op_link.c \
	op_rename.c
else
umfuseext2_la_SOURCES = \
	fuse-ext2.h \
	fuse-ext2.c \
	vnode_hash.c \
	do_probe.c \
	do_check.c \
	do_fillstatbuf.c \
	do_readinode.c \
	do_killfilebyinode.c \
	op_init.c \
	op_destroy.c \
	op_access.c \
	op_fgetattr.c \
	op_getattr.c \
	op_open.c \
	op_read.c \
	op_readdir.c \
	op_readlink.c \
	op_release.c \
	op_statfs.c \
	op_chown.c \
	op_chmod.c \
	op_create.c \
	op_flush.c \
	op_fsync.c \
	op_mkdir.c \
	op_rmdir.c \
	op_unlink.c \
	op_utimens.c \
	op_write.c \
	op_mknod.c \
	op_symlink.c \
	op_truncate.c \
	op_link.c \
	op_rename.c \
	ext2-fileio.c
endif

umfuseext2_la_CFLAGS = \
	-Wall					\
	-DHAVE_CONFIG_H				\
	-D_FILE_OFFSET_BITS=64			\
	-D_GNU_SOURCE \
	$(DEVELFLAGS) \
	-I$(includedir)/umview \
	$(LINUXE2CFLAGS)	\
	-I/usr/local/include

umfuseext2_la_LDFLAGS = \
	$(LINUXE2LIBS) \
	-module \
	-avoid-version \
	-export-dynamic
endif

fuse_ext2_CFLAGS =				\
	-Wall					\
	-DHAVE_CONFIG_H				\
	-D_FILE_OFFSET_BITS=64			\
	-DTHREAD_LOCKS \
	$(LINUXE2CFLAGS) \
	-I/usr/local/include

#if DARWIN
#bin_PROGRAMS += \
#	fuse-ext2.wait
#
#fuse_ext2_wait_SOURCES = \
#	fuse-ext2.wait.c
#
#fuse_ext2_wait_CFLAGS = \
#	-Wall \
#	-D__FreeBSD__=10
#
#fuse_ext2_wait_LDFLAGS = \
#	-framework CoreFoundation
#
#fuse_ext2_probe_CFLAGS +=			\
#	-D__FreeBSD__=10
#
#fuse_ext2_CFLAGS +=				\
#	-D__FreeBSD__=10
#
#fuse_ext2_LDADD =				\
#	../e2fsprogs-1.41.12.newgit/ext2fs/libext2fs.a	\
#	../e2fsprogs-1.41.12.newgit/et/libcom_err.a	\
#	-L/usr/local/lib \
#	-lfuse
#endif
if LINUX
fuse_ext2_LDADD =				\
	$(LINUXE2LIBS) \
	-L/usr/local/lib \
	-lfuse 
endif
#	-lext2fs

install-data-hook:
	cd "$(DESTDIR)/$(moddir)" && rm -f $(mod_LTLIBRARIES)

#if DARWIN
#install-exec-local:
#	$(INSTALL) -d "$(DESTDIR)/sbin"
#	$(LN_S) -f "../System/Library/Filesystems/fuse-ext2.fs/mount_fuse-ext2" "$(DESTDIR)/sbin/mount_fuse-ext2"
#endif
if LINUX
install-exec-local:
	$(INSTALL) -d "$(DESTDIR)/usr/sbin"
	$(LN_S) -f "$(DESTDIR)/$(bindir)/fuse-ext2" "$(DESTDIR)/sbin/mount.fuse-ext2"
endif
