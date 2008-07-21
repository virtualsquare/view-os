#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.60)
AC_INIT([lwipv6], [1.2a], [info@v2.cs.unibo.it])
AM_INIT_AUTOMAKE([foreign dist-bzip2])
AC_CONFIG_SRCDIR([lwip-contrib/ports/unix/include/lwipv6.h])
AC_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_PROG_LIBTOOL

# Checks for libraries.
AC_CHECK_LIB([pcap], [pcap_open_offline],,AC_MSG_ERROR([libpcap missing]))
AC_CHECK_LIB([util], [forkpty],,AC_MSG_ERROR([libutil missing]))
AC_CHECK_LIB([vdeplug], [vde_close],,AC_MSG_ERROR([libvdeplug missing]))

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h netinet/in.h stdint.h stdlib.h string.h sys/ioctl.h sys/socket.h sys/time.h termios.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_CONST
AC_C_INLINE
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_HEADER_TIME
AC_TYPE_UINT32_T
AC_C_VOLATILE

# Checks for library functions.
AC_FUNC_ERROR_AT_LINE
AC_PROG_GCC_TRADITIONAL
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_REALLOC
AC_FUNC_SELECT_ARGTYPES
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([bzero gethostbyname gettimeofday inet_ntoa isascii memset select socket strchr strerror strtol])

AC_CONFIG_FILES([Makefile
                 lwip-contrib/ports/unix/proj/lib/Makefile])
#AC_CONFIG_FILES([Makefile
#                 lwip-contrib/ports/unix/proj/lib/Makefile
#                 lwip-contrib/ports/unix/proj/minimal/Makefile
#                 lwip-contrib/ports/unix/proj/unixsim/Makefile])
AC_OUTPUT
