CC=powerpc64le-linux-gnu-gcc
CFLAGS=-g -Wall -O2

# Is BFD available?
CFLAGS+=-DUSE_BFD
LDLIBS=-lbfd -lopcodes

all: ptracer

ptracer: main.o perf_events.o pids.o ppc_storage.o ptrace.o qtrace.o single_step.o ascii.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

clean:
	rm -f *.o ptracer
