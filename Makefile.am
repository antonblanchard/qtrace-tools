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

bin_PROGRAMS = branch/link_stack

branch_link_stack_SOURCES = branch/link_stack.c
branch_link_stack_LDADD = libqtrace.a
