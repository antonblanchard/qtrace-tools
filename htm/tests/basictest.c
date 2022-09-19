#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <assert.h>

#include <qtlib/qtwriter.h>

#include <ppcstats.h>
#include "../htm.h"
#include "../tlb.h"
#include "bb.h"

static void check_record(struct htm_record *rec, void *private_data)
{
	struct qtrace_record qrec = rec->insn;

	assert(qrec.insn == 0x7f843800);
}

int main(int argc, char * const argv[])
{
	int fd;

	fd = open("htm/tests/dumps/01.htm", O_RDONLY);
	if (fd == -1) {
		fprintf(stderr, "Failed to open %s - %s\n",
			argv[1], strerror(errno));
		exit(1);
	}

	htm_decode(fd, check_record, (void*)1, NULL);

	return 0;
}
