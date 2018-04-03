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

AC_CHECK_LIB([bfd], [bfd_init])
AC_CHECK_LIB([opcodes], [disassembler])
AC_CHECK_HEADERS([bfd.h dis-asm.h])
if test x"${ac_cv_lib_bfd_bfd_init}" = "xyes" -a \
	x"${ac_cv_lib_opcodes_disassembler}" = "xyes" -a \
	x"${ac_cv_header_bfd_h}" = "xyes" -a \
	x"${ac_cv_header_dis_asm_h}" = "xyes" ; then
	AC_DEFINE([USE_BFD], [1], [Use bfd library])
	AC_SUBST([LIBBFD], ["-lbfd -lopcodes"])
else
	AC_MSG_WARN([Building without bfd library])
fi

AC_C_BIGENDIAN(dnl
	AC_DEFINE([HAVE_BIG_ENDIAN], [1], [Big endian]),dnl
	AC_DEFINE([HAVE_LITTLE_ENDIAN], [1], [Little endian])dnl
)

AS_IF([test x"${ARCH}" = "xppc"], [AC_SUBST([PTRACER], [ptracer/ptracer])], [])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
