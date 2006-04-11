
AC_PREREQ(2.59)
AC_INIT(fuseext2,0.0.1)
AC_CONFIG_SRCDIR([fuseext2.c])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
AC_CHECK_LIB(fuse,fuse_main, [FUSE_LIBS="-lfuse"],
    [AC_MSG_ERROR([
	Can't find libfuse.a - add the search path to LDFLAGS
	and rerun configure, eg:
	export LDFLAGS=-L/usr/local/lib ])],)
	
AC_CHECK_LIB(ext2fs,ext2fs_unlink, [EXT2FS_LIBS="-lext2fs"],
    [AC_MSG_ERROR([
	Can't find libext2fs - add the search path to LDFLAGS
	and rerun configure, eg:
	export LDFLAGS=-L/usr/local/lib ])],)


# Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_CHECK_HEADERS([fcntl.h string.h sys/statfs.h unistd.h])

AC_ARG_PROGRAM
AC_PROG_INSTALL 

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
