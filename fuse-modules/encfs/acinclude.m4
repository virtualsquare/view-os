
dnl If support is available, then HAVE_ATOMIC_GCC 
dnl will be set
dnl
AC_DEFUN([AM_ATOMIC],
[
    AC_ARG_ENABLE(atomic-gcc,
	AC_HELP_STRING([--enable-atomic-gcc],
	    [use gcc atomic instructions [default=test]]),
	enable_atomic_gcc=$enableval, enable_atomic_gcc="test" )

    if test $enable_atomic_gcc = "test"; then
	AC_CHECK_HEADER([bits/atomicity.h], 
	[
	    AC_MSG_CHECKING([for __atomic_add() support])
	    AC_TRY_LINK([#include <bits/atomicity.h>],
	    [
		_Atomic_word i(0); 
		__atomic_add(&i, 1); 
		__exchange_and_add(&i, 1); 
	    ], 
	    [ 
		AC_MSG_RESULT(yes) 
		enable_atomic_gcc="yes"
	    ], 
	    [ 
		AC_MSG_RESULT(no) 

		dnl check if it is in a private __gnu_cxx namespace..
		AC_MSG_CHECKING([for __gnu_cxx::__atomic_add() support])
		AC_TRY_LINK([#include <bits/atomicity.h>],
		[
		    using namespace __gnu_cxx;
		    _Atomic_word i(0); 
		    __atomic_add(&i, 1); 
		    __exchange_and_add(&i, 1); 
		], 
		[ 
		    AC_MSG_RESULT(yes) 
		    enable_atomic_gcc="private"
		],
		[ AC_MSG_RESULT(no) ])
	    ])
	])
    fi

    ATOMIC_GCC="0";
    ATOMIC_GCC_PRIVATE="0";
    if test $enable_atomic_gcc = "test"; then
	enable_atomic_gcc="no"
	AC_MSG_ERROR([atomic functions not found])
    elif test $enable_atomic_gcc = "yes"; then
	AC_DEFINE(HAVE_ATOMIC_GCC,, 
	    [Defined if <bits/atomicity.h> is usable]) 
	ATOMIC_GCC="1"
    elif test $enable_atomic_gcc = "private"; then
	AC_DEFINE(HAVE_ATOMIC_GCC_PRIVATE,, 
	    [Defined if <bits/atomicity.h> is usable in __gnu_cxx namespace]) 
	ATOMIC_GCC_PRIVATE="1"
    fi
    AC_SUBST(ATOMIC_GCC)
    AC_SUBST(ATOMIC_GCC_PRIVATE)
])


