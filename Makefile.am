AUTOMAKE_OPTIONS = foreign

AM_CFLAGS = -Wall -Werror -O2 \
	    -I$(top_srcdir)/qtlib

lib_LIBRARIES = libqtrace.a

libqtrace_a_SOURCES = qtlib/qtreader.c qtlib/qtwriter.c

qtlib_TESTS = qtlib/tests/test1 qtlib/tests/test2 \
	      qtlib/tests/test3 qtlib/tests/test4

check_PROGRAMS = $(qtlib_TESTS)

qtlib_tests_test1_SOURCES = qtlib/tests/test1.c
qtlib_tests_test1_LDADD = libqtrace.a

qtlib_tests_test2_SOURCES = qtlib/tests/test2.c
qtlib_tests_test2_LDADD = libqtrace.a

qtlib_tests_test3_SOURCES = qtlib/tests/test3.c
qtlib_tests_test3_LDADD = libqtrace.a

qtlib_tests_test4_SOURCES = qtlib/tests/test4.c
qtlib_tests_test4_LDADD = libqtrace.a

bin_PROGRAMS = branch/link_stack qtrace2dis/qtrace2dis qtrace-bbv/qtrace-bbv \
	       $(PTRACER)
EXTRA_PROGRAMS = ptracer/ptracer

branch_link_stack_SOURCES = branch/link_stack.c
branch_link_stack_LDADD = libqtrace.a

qtrace2dis_qtrace2dis_SOURCES = qtrace2dis/qtrace2dis.c
qtrace2dis_qtrace2dis_LDADD = libqtrace.a @LIBBFD@

qtrace_bbv_qtrace_bbv_SOURCES = \
	qtrace-bbv/ccan/hash/hash.c \
	qtrace-bbv/ccan/htable/htable.c \
	qtrace-bbv/matrix.c \
	qtrace-bbv/pam.c \
	qtrace-bbv/qtrace-bbv.c
qtrace_bbv_qtrace_bbv_CFLAGS = $(AM_CFLAGS) -I$(top_srcdir)/qtrace-bbv
qtrace_bbv_qtrace_bbv_LDADD = libqtrace.a

ptracer_ptracer_SOURCES = \
	ptracer/ascii.c ptracer/main.c ptracer/perf_events.c ptracer/pids.c \
	ptracer/ppc_storage.c ptracer/ptrace.c ptracer/qtrace.c \
	ptracer/single_step.c
ptracer_ptracer_LDADD = libqtrace.a @LIBBFD@
