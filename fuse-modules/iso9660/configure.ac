#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(fuseiso9660,0.0.1)
AM_INIT_AUTOMAKE(fuseiso9660,0.0.1)
AC_CONFIG_SRCDIR([fuseiso9660.c])

# Checks for programs.
AC_PROG_CC

AC_ARG_PROGRAM
AC_PROG_INSTALL


# Checks for libraries.
AC_CHECK_LIB(fuse,fuse_main, [FUSE_LIBS="-lfuse"],
    [AC_MSG_ERROR([
	Can't find libfuse.a - add the search path to LDFLAGS
	and rerun configure, eg:
	export LDFLAGS=-L/usr/local/lib ])],)
	
AC_CHECK_LIB(iso9660,iso9660_xa_init, [ISO9660_LIBS="-liso9660"],
    [AC_MSG_ERROR([
	Can't find libiso9660 - add the search path to LDFLAGS
	and rerun configure, eg:
	export LDFLAGS=-L/usr/local/lib ])],)
	
AC_CHECK_LIB(z,zlibVersion, [Z_LIBS="-lz"],
    [AC_MSG_ERROR([
	Can't find libz - add the search path to LDFLAGS
	and rerun configure, eg:
	export LDFLAGS=-L/usr/local/lib ])],)


# Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_CHECK_HEADERS([fcntl.h stdlib.h string.h sys/statfs.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_UID_T
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_CHECK_MEMBERS([struct stat.st_blksize])
AC_STRUCT_ST_BLOCKS
AC_CHECK_MEMBERS([struct stat.st_rdev])
AC_STRUCT_TM
AC_HEADER_STDBOOL

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_MKTIME
AC_FUNC_UTIME_NULL
AC_CHECK_FUNCS([lchown memset mkdir rmdir utime])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
