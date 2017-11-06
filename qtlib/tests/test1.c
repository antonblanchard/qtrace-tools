#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "qtreader.h"

int main(int argc, char *argv[])
{
	int fd;
	struct stat buf;
	void *p;
	unsigned long size;
	struct qtreader_state state;
	struct qtrace_record record;

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		perror("open");
		exit(1);
	}

	if (fstat(fd, &buf)) {
		perror("fstat");
		exit(1);
	}
	size = buf.st_size;

	p = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
	if (p == MAP_FAILED) {
		perror("mmap");
		exit(1);
	}

	if (qtreader_initialize(&state, p, size, 0) == false) {
		fprintf(stderr, "qtreader_initialize failed\n");
		exit(1);
	}

	while (qtreader_next_record(&state, &record) == true)
		printf("0x%08x\n", record.insn);

	return 0;
}
