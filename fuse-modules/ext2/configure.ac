#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.60)
AC_INIT([fuse+umfuse-ext2], [0.1], [osd@cs.unibo.it])
AM_INIT_AUTOMAKE([foreign dist-bzip2 1.10])
AC_CONFIG_SRCDIR([fuseext2.c])
AC_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_LIBTOOL

# Checks for libraries.
AC_CHECK_LIB([fuse], [fuse_main], [FUSE_LIBS="-lfuse"],
    [AC_MSG_ERROR([Can't find libfuse, please install it])])
AC_CHECK_LIB([ext2fs], [ext2fs_unlink], [EXT2FS_LIBS="-lext2fs"],
    [AC_MSG_ERROR([Can't find libext2fs, please install it])])

AC_CHECK_LIB([umlib], [um_add_service], [UMLIB_LIBS="-lumlib"],
    [AC_MSG_ERROR([Can't find libumlib, please install it])])

# Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_CHECK_HEADERS([fcntl.h string.h sys/statfs.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_UID_T
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_CHECK_MEMBERS([struct stat.st_blksize])
AC_STRUCT_ST_BLOCKS
AC_CHECK_MEMBERS([struct stat.st_rdev])

# Checks for library functions.
AC_CHECK_FUNCS([memset strdup strrchr])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
