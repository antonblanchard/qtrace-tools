CFLAGS = -g -O2 -Wall

ARCH = $(shell uname -m)

# Is BFD available?
CFLAGS+=-DUSE_BFD
ifeq ($(ARCH),ppc64le)
	LDLIBS=-lbfd -lopcodes
else
	LDLIBS=-lopcodes-multiarch -lbfd-multiarch
endif

all: qtrace2dis

clean:
	rm -f *.o qtrace2dis
