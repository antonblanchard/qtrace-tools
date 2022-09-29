AUTOMAKE_OPTIONS = foreign

AM_CFLAGS = -Wall -Werror \
	    -I$(top_srcdir)/qtlib

lib_LIBRARIES = libqtrace.a libppcstats.a libbb.a

libqtrace_a_SOURCES = qtlib/qtreader.c qtlib/qtwriter.c

libppcstats_a_SOURCES = qtlib/ppcstats.c \
			qtlib/ppc-opc.c \
			qtrace-bbv/ccan/hash/hash.c \
			qtrace-bbv/ccan/htable/htable.c
libppcstats_a_CFLAGS = $(AM_CFLAGS) -I$(top_srcdir)/qtrace-bbv

libbb_a_SOURCES = qtlib/bb.c \
	qtrace-bbv/ccan/hash/hash.c \
	qtrace-bbv/ccan/htable/htable.c
libbb_a_CFLAGS = $(AM_CFLAGS) -I$(top_srcdir)/qtrace-bbv

qtlib_TESTS = qtlib/tests/test1 qtlib/tests/test2 \
	      qtlib/tests/test3 qtlib/tests/test4 \
	      qtlib/tests/basictest qtlib/tests/guestpagetest \
	      qtlib/tests/radixtest qtlib/tests/radixonradixtest \
	      qtlib/tests/realonradixtest

check_PROGRAMS = $(qtlib_TESTS) $(htm_c_tests)

TESTS = $(qtlib_run_tests) $(htm_tests)

qtlib_tests_test1_SOURCES = qtlib/tests/test1.c
qtlib_tests_test1_LDADD = libqtrace.a

qtlib_tests_test2_SOURCES = qtlib/tests/test2.c
qtlib_tests_test2_LDADD = libqtrace.a

qtlib_tests_test3_SOURCES = qtlib/tests/test3.c
qtlib_tests_test3_LDADD = libqtrace.a

qtlib_tests_test4_SOURCES = qtlib/tests/test4.c
qtlib_tests_test4_LDADD = libqtrace.a

qtlib_tests_basictest_SOURCES = qtlib/tests/basictest.c
qtlib_tests_basictest_LDADD = libqtrace.a

qtlib_tests_guestpagetest_SOURCES = qtlib/tests/guestpagetest.c
qtlib_tests_guestpagetest_LDADD = libqtrace.a

qtlib_tests_radixtest_SOURCES = qtlib/tests/radixtest.c
qtlib_tests_radixtest_LDADD = libqtrace.a

qtlib_tests_radixonradixtest_SOURCES = qtlib/tests/radixonradixtest.c
qtlib_tests_radixonradixtest_LDADD = libqtrace.a

qtlib_tests_realonradixtest_SOURCES = qtlib/tests/realonradixtest.c
qtlib_tests_realonradixtest_LDADD = libqtrace.a

qtlib_run_tests = qtlib/tests/basictest qtlib/tests/guestpagetest \
			qtlib/tests/radixtest qtlib/tests/radixonradixtest \
			qtlib/tests/realonradixtest

bin_PROGRAMS = branch/link_stack qtdis/qtdis qtrace-bbv/qtrace-bbv \
	       qtbuild/qtbuild htm/htmdecoder $(PTRACER)
EXTRA_PROGRAMS = ptracer/ptracer

branch_link_stack_SOURCES = branch/link_stack.c
branch_link_stack_LDADD = libqtrace.a

qtdis_qtdis_SOURCES = qtdis/qtdis.c
qtdis_qtdis_LDADD = libqtrace.a libppcstats.a libbb.a

qtrace_bbv_qtrace_bbv_SOURCES = \
	qtrace-bbv/ccan/hash/hash.c \
	qtrace-bbv/ccan/htable/htable.c \
	qtrace-bbv/matrix.c \
	qtrace-bbv/pam.c \
	qtrace-bbv/qtrace-bbv.c
qtrace_bbv_qtrace_bbv_CFLAGS = $(AM_CFLAGS) -I$(top_srcdir)/qtrace-bbv
qtrace_bbv_qtrace_bbv_LDADD = libqtrace.a

qtbuild_qtbuild_SOURCES = qtbuild/qtbuild.c
qtbuild_qtbuild_LDADD = libqtrace.a

ptracer_ptracer_SOURCES = \
	ptracer/ascii.c ptracer/main.c ptracer/perf_events.c ptracer/pids.c \
	ptracer/ppc_storage.c ptracer/ptrace.c \
	ptracer/single_step.c ptracer/pagemap.c
ptracer_ptracer_LDADD = libqtrace.a

HTM_SOURCES = htm/htm.c htm/tlb.c htm/pwc.c htm/erat.c htm/xlate.c \
	qtrace-bbv/ccan/hash/hash.c qtrace-bbv/ccan/htable/htable.c

htm_htmdecoder_SOURCES = htm/htmdecoder.c $(HTM_SOURCES)

htm_htmdecoder_CFLAGS = $(AM_CFLAGS) -I$(top_srcdir)/qtrace-bbv
htm_htmdecoder_LDADD = libqtrace.a libppcstats.a libbb.a

htm_tests_basictest_SOURCES = htm/tests/basictest.c $(HTM_SOURCES)
htm_tests_basictest_LDADD = libqtrace.a libppcstats.a libbb.a
htm_tests_basictest_CFLAGS = $(htm_htmdecoder_CFLAGS)

htm_tests_radixtest_SOURCES = htm/tests/radixtest.c $(HTM_SOURCES) \
	 qtrace-bbv/ccan/asprintf/asprintf.c qtrace-bbv/ccan/tap/tap.c
htm_tests_radixtest_LDADD = libqtrace.a libppcstats.a libbb.a
htm_tests_radixtest_CFLAGS = $(htm_htmdecoder_CFLAGS)

htm_c_tests = htm/tests/basictest \
	htm/tests/radixtest

htm_tests = htm/tests/run_tests $(htm_c_tests)
