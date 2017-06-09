targets := $(patsubst %.S,%,$(wildcard *.S))

CC = powerpc64le-linux-gnu-gcc
CFLAGS = -O2 -ffreestanding -nostdlib -fno-builtin -static -fno-pie

.PHONY: all
all: $(targets)

$(targets): $<
	$(CC) $(CFLAGS) -o $@ $@.S

clean:
	rm -f $(targets)
