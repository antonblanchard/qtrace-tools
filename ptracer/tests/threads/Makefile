CC = powerpc64le-linux-gnu-gcc
CFLAGS = -O2
LDFLAGS=-pthread

targets := $(patsubst %.c,%,$(wildcard *.c))

.PHONY: all
all: $(targets)

#$(targets): $<
	#$(CC) $(CFLAGS) -o $@ $@.S

clean:
	rm -f $(targets)


