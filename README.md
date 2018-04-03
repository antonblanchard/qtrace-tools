qtrace-tools
============

Various tools that operate on the qtrace instruction trace format. If
running on a ppc64 system, install the binutils development libraries.
On Ubuntu:

```
sudo apt-get install binutils-dev
```

To work with ppc64 traces on another architecture, on Ubuntu you can
install the multiarch version of the libraries:

```
sudo apt-get install binutils-multiarch-dev
```

To build:

```
./bootstrap.sh
./configure
make
```

ptracer
-------

Operates similar to strace. It attaches to a running process (via -p) or
executes a new process, and uses single stepping to create a objdump style
ascii disassembly or a qtrace binary instruction trace. It doesn't support
multiple threads or processes yet.
