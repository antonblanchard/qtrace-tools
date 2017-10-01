CFLAGS = -g -O2 -Wall -I.

ARCH = $(shell uname -m)

all: qtrace-bbv

qtrace-bbv: qtrace-bbv.c ccan/hash/hash.c ccan/htable/htable.c

clean:
	rm -f *.o qtrace-bbv
