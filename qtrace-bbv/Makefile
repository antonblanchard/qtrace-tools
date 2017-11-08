CFLAGS = -g -O2 -Wall -I. -I../qtlib

ARCH = $(shell uname -m)

all: qtrace-bbv

qtrace-bbv: qtrace-bbv.c ccan/hash/hash.c ccan/htable/htable.c matrix.c pam.c ../qtlib/qtreader.o

clean:
	rm -f *.o qtrace-bbv
