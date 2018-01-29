CFLAGS = -g -O2 -Wall -I. -I../qtlib

ARCH = $(shell uname -m)

all: link_stack

link_stack: link_stack.o ../qtlib/qtreader.o

clean:
	rm -f *.o $(all)
