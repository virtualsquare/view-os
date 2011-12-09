#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.60)
AC_INIT([purelibc], [0.4.1], [info@v2.cs.unibo.it])
AM_INIT_AUTOMAKE([foreign dist-bzip2])
AC_CONFIG_SRCDIR([purelibc.h])
AC_CONFIG_HEADER([config.h])

AC_GNU_SOURCE
AC_USE_SYSTEM_EXTENSIONS

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_LIBTOOL

# Checks for libraries.
AC_CHECK_LIB([dl], [dlopen])

# Checks for header files.
AC_FUNC_ALLOCA
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([fcntl.h limits.h mntent.h stdlib.h string.h sys/ioctl.h sys/socket.h sys/statvfs.h sys/time.h sys/timeb.h sys/vfs.h termios.h unistd.h utime.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_UID_T
AC_TYPE_INT32_T
AC_TYPE_MODE_T
AC_FUNC_OBSTACK
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_CHECK_MEMBERS([struct stat.st_blksize])
AC_STRUCT_ST_BLOCKS
AC_CHECK_MEMBERS([struct stat.st_rdev])
AC_CHECK_DECLS([sys_siglist])
AC_HEADER_TIME
AC_STRUCT_TM
AC_STRUCT_TIMEZONE
AC_C_VOLATILE

# Checks for library functions.
AC_FUNC_CHOWN
AC_FUNC_CLOSEDIR_VOID
AC_FUNC_FORK
AC_FUNC_FSEEKO
AC_FUNC_GETGROUPS
AC_FUNC_GETPGRP
AC_PROG_GCC_TRADITIONAL
AC_FUNC_LSTAT
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_MKTIME
AC_FUNC_REALLOC
AC_FUNC_SELECT_ARGTYPES
AC_FUNC_SETPGRP
AC_FUNC_SETVBUF_REVERSED
AC_TYPE_SIGNAL
AC_FUNC_STAT
AC_FUNC_STRCOLL
AC_FUNC_STRERROR_R
AC_FUNC_STRFTIME
AC_FUNC_STRNLEN
AC_FUNC_STRTOD
AC_FUNC_UTIME_NULL
AC_FUNC_VPRINTF
AC_FUNC_WAIT3
AC_CHECK_FUNCS([memchr memset strchr strdup strtol],,[AC_MSG_ERROR(required function not found)])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
