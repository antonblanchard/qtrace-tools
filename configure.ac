AC_INIT([ptracer], [1.0])
AM_INIT_AUTOMAKE([foreign subdir-objects])
AM_SILENT_RULES([yes])
AM_MAINTAINER_MODE([enable])

AC_CONFIG_HEADERS([config.h])
AC_CANONICAL_HOST

case "$host" in
	powerpc*-*-*)  ARCH="ppc" ;;
	*)             ARCH="unk" ;;
esac
AM_CONDITIONAL([TARGET_PPC], [test x"$ARCH" = "xppc"])

AC_PROG_CC
AC_PROG_RANLIB

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
