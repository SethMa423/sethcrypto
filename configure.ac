#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT(crypto-Tools, 2.1, sethma423@outlook.com)
AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_CXX

AC_CONFIG_HEADERS([config.h])

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h stdint.h stdlib.h string.h unistd.h])

# Checks for libraries
AC_ARG_WITH(tommath, AS_HELP_STRING([--with-python], [add python support]), , with_dh="no")
if test $with_dh != "no"
then
  AX_PYTHON_DEVEL()
  if test $pythonexists = "yes"
  then
    AC_DEFINE([WITH_PYTHON], [1], [Use Python])
    echo "PYTHON_CPPFLAGS=${PYTHON_CPPFLAGS}"
    echo "PYTHON_LDFLAGS=${PYTHON_LDFLAGS}"
    echo "PYTHON_EXTRA_LIBS=${PYTHON_EXTRA_LIBS}"
    echo "PYTHON_EXTRA_LDFLAGS=${PYTHON_EXTRA_LDFLAGS}"
  fi
fi
AM_CONDITIONAL([WITH_PYTHON], [test $pythonexists = "yes"])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_CHECK_FUNCS([memset])

AC_CONFIG_FILES([Makefile
                 src/Makefile
                ])
AC_OUTPUT
