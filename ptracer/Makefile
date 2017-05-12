CFLAGS=-g -Wall -O2
LDLIBS=-lbfd -lopcodes

all: ptracer

ptracer: ptracer.o qtrace.o ppc_storage.o

clean:
	rm -f *.o ptracer
