dnl Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(php, 1.0)


AC_CANONICAL_SYSTEM
AM_INIT_AUTOMAKE()

AC_ARG_ENABLE(debug, [--enable-debug	Enable debugging infomation],
			USE_DEBUG="yes", USE_DEBUG="no")

if test "$USE_DEBUG" = "yes"  ; then
	DEBUG=1
	CFLAGS=`echo "$CFLAGS" | sed -e 's/-O[0-9s]*//g'`
	CFLAGS="$CFLAGS -g -O0 -Wall"
else 
	DEBUG=0
fi

AC_PROG_CC

AM_PROG_CC_C_O

AC_CONFIG_FILES(Makefile zendmm/Makefile)
AC_OUTPUT

