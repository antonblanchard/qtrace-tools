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

AC_SEARCH_LIBS([bfd_init], [bfd-multiarch bfd])
AC_SEARCH_LIBS([disassembler], [opcodes-multiarch opcodes])
AC_CHECK_HEADERS([bfd.h dis-asm.h])
AC_COMPILE_IFELSE(
        [AC_LANG_PROGRAM([[#include <dis-asm.h>]],
                         [[(void) disassembler((enum bfd_architecture) 0,
						(bfd_boolean) 0,
						(unsigned long) 0,
						(bfd *)0);]])],
        [ac_cv_right_disassembler=yes],
        [ac_cv_right_disassembler=no])
if test x"${ac_cv_search_bfd_init}" = "xno" -o \
	x"${ac_cv_search_disassembler}" = "xno" ; then
	AC_MSG_WARN([Missing bfd library, install binutils-dev package])
elif test x"${ac_cv_header_bfd_h}" = "xno" -o \
	x"${ac_cv_header_dis_asm_h}" = "xno" ; then
	AC_MSG_WARN([Missing bfd headers, install binutils-dev package])
elif test x"${ac_cv_right_disassembler}" = "xno" ; then
	AC_MSG_WARN([Require binutils >= 2.29])
else
	AC_DEFINE([USE_BFD], [1], [Use bfd library])
fi

AC_C_BIGENDIAN(dnl
	AC_DEFINE([HAVE_BIG_ENDIAN], [1], [Big endian]),dnl
	AC_DEFINE([HAVE_LITTLE_ENDIAN], [1], [Little endian])dnl
)

AS_IF([test x"${ARCH}" = "xppc"], [AC_SUBST([PTRACER], [ptracer/ptracer])], [])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
