CC = powerpc64le-linux-gnu-gcc
CFLAGS = -O2

targets := $(patsubst %.c,%,$(wildcard *.c))

.PHONY: all
all: $(targets)

clean:
	rm -f $(targets)
