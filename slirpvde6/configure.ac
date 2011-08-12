#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT([slirpvd6],[0.1.1],[info@v2.cs.unibo.it])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign dist-bzip2 subdir-objects])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AC_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S
AM_PROG_CC_C_O

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h stddef.h stdint.h stdlib.h string.h strings.h sys/ioctl.h sys/param.h sys/socket.h sys/time.h syslog.h termio.h termios.h unistd.h sys/filio.h sys/bitypes.h sys/wait.h sys/select.h sys/signal.h sys/stropts.h termios.h sys/type32.h])

AC_CHECK_HEADERS([syslimits.h sys/syslimits.h])

AC_CHECK_HEADERS([openssl/blowfish.h],
                 [],
                 [add_cryptcab_support=no ; warn_cryptcab=yes])

AC_CHECK_HEADERS([lwipv6.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_C_BIGENDIAN
AC_C_PROTOTYPES
AC_TYPE_MODE_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_HEADER_TIME

# Checks for library functions.
AC_FUNC_CHOWN
AC_FUNC_FORK
AC_PROG_GCC_TRADITIONAL
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_REALLOC
AC_FUNC_SELECT_ARGTYPES
AC_CHECK_FUNCS([atexit dup2 gethostbyname gethostname gettimeofday inet_ntoa memmove memset putenv select setenv socket strchr strdup strerror strstr uname inet_aton sprintf readv random srandom index bcmp drand48 memmove gethostid revoke fchmod getopt_long_only funopen])
AC_CHECK_FUNC([poll],
	[
		AC_MSG_CHECKING([for poll sanity])
		if expr "$build_os" : "darwin*" > /dev/null; then
			AC_MSG_RESULT([present but broken, emulating with select])
			AC_LIBOBJ([poll])
			AC_DEFINE([poll], [vde_poll], [Define to vde_poll if the replacement function should be used.])
		else
			AC_DEFINE([HAVE_POLL], 1, [Define to 1 if your system has a working poll() function.])
			AC_MSG_RESULT([yes])
		fi
	],
	[])

# All other nice checks I have to make for recostructing missing parts of
# slirp's config.h file
AC_CHECK_SIZEOF(char)
AC_CHECK_SIZEOF(short)
AC_CHECK_SIZEOF(int)
AC_CHECK_SIZEOF(char *)

AC_CONFIG_FILES(
		[Makefile]
		)
AC_OUTPUT
