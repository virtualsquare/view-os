#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.60)
AC_INIT([ntfs-3g], [2010.3.6], [test])
AM_INIT_AUTOMAKE([foreign dist-bzip2 1.10])
AC_CONFIG_SRCDIR([ntfs-3g.c])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_MACRO_DIR([m4])

AC_GNU_SOURCE
AC_HEADER_STDC
AC_CHECK_HEADERS([ctype.h fcntl.h libgen.h libintl.h limits.h locale.h \
		mntent.h stddef.h stdint.h stdlib.h stdio.h stdarg.h string.h \
		strings.h errno.h time.h unistd.h utime.h wchar.h getopt.h features.h \
		endian.h byteswap.h sys/byteorder.h sys/endian.h sys/param.h \
		sys/ioctl.h sys/mkdev.h sys/mount.h sys/stat.h sys/types.h sys/vfs.h \
		sys/statvfs.h sys/sysmacros.h linux/major.h linux/fd.h linux/hdreg.h \
		machine/endian.h windows.h syslog.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_LIBTOOL
AC_C_INLINE
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_STRUCT_ST_BLOCKS
AC_HEADER_STDBOOL
AC_CHECK_MEMBERS([struct stat.st_rdev])
AC_CHECK_MEMBERS([struct stat.st_atim])
AC_CHECK_MEMBERS([struct stat.st_atimespec])

case $target_os in
	*linux*) arch=linux;;
	*darwin*)  arch=darwin;;
	*)     arch=unknown;;
esac

# Checks for libraries.
AC_CHECK_LIB([fuse], [fuse_main], [FUSE_LIBS="-lfuse"],
		[AC_MSG_ERROR([Can't find libfuse, please install it])])

AC_CHECK_LIB([ntfs-3g], [ntfs_mount], [FUSE_LIBS="-lntfs-3g"],
		[AC_MSG_ERROR([Can't find libntfs-3g, please install it])])

AC_CHECK_LIB([umlib], [um_add_service], [UMLIB_LIBS="-lumlib"],
		[AC_MSG_ERROR([Can't find libumlib, please install it])])

AC_MSG_CHECKING([if FUSE on this system is too new for us])
	AC_EGREP_CPP([yes], [
#include "fuse.h"
#if FUSE_VERSION > 26
			yes
#endif
			], AC_DEFINE([FUSE_USE_VERSION], [26], [Version of FUSE interface]) AC_MSG_RESULT([yes]),
			AC_DEFINE([FUSE_USE_VERSION], [FUSE_VERSION], [Version of FUSE interface]) AC_MSG_RESULT([no]))

# Checks for typedefs, structures, and compiler characteristics.
	AC_C_CONST
	AC_TYPE_UID_T
	AC_TYPE_MODE_T
	AC_TYPE_OFF_T
	AC_TYPE_SIZE_T
AC_CHECK_MEMBERS([struct stat.st_blksize])
	AC_STRUCT_ST_BLOCKS
AC_CHECK_MEMBERS([struct stat.st_rdev])

# Enable large file support.
AC_SYS_LARGEFILE

# Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_HEADER_STDC
AC_CHECK_HEADERS([ctype.h fcntl.h libgen.h libintl.h limits.h locale.h \
			mntent.h stddef.h stdint.h stdlib.h stdio.h stdarg.h string.h \
			strings.h errno.h time.h unistd.h utime.h wchar.h getopt.h features.h \
			endian.h byteswap.h sys/byteorder.h sys/endian.h sys/param.h \
			sys/ioctl.h sys/mount.h sys/stat.h sys/types.h sys/vfs.h \
			sys/statvfs.h sys/sysmacros.h linux/major.h linux/fd.h linux/hdreg.h \
			machine/endian.h windows.h syslog.h pwd.h])

# Checks for library functions.
AC_CHECK_FUNCS([memset strdup strrchr \
		atexit basename dup2 fdatasync getopt_long hasmntopt mbsinit \
		memmove realpath regcomp setlocale setxattr strcasecmp strchr \
		strsep strdup strerror strnlen strtol strtoul sysconf utime])

AM_CONDITIONAL(LINUX, test "$arch" = linux)
AM_CONDITIONAL(DARWIN, test "$arch" = darwin)

AC_CONFIG_FILES([Makefile])
	AC_OUTPUT
