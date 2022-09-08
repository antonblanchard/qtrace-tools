#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <assert.h>

#include "qtrace.h"
#include "qtwriter.h"
#include "qtreader.h"

#define TESTFILENAME "runtest1.qt"

#define MAGIC_TEST_VALUE 0xcafe

int run_qtwriter(void)
{
	struct qtwriter_state state;
	struct qtrace_record record;

	memset(&state, 0, sizeof(state));

	qtwriter_open(&state, TESTFILENAME, MAGIC_TEST_VALUE);

	memset(&record, 0, sizeof(record));
	qtwriter_close(&state);

	return 0;
}


int run_qtreader(void)
{
	int fd;
	struct qtreader_state state;

	fd = open(TESTFILENAME, O_RDONLY);
	if (fd < 0) {
		perror("open");
		exit(1);
	}

	if (qtreader_initialize_fd(&state, fd, 0) == false) {
		fprintf(stderr, "qtreader_initialize_fd failed\n");
		exit(1);
	}

	assert(state.magic == MAGIC_TEST_VALUE);
	assert(state.next_insn_addr == 0x4);

	return 0;
}

/* Test writing and reading a minimal qtrace */
int main(void)
{
	run_qtwriter();
	run_qtreader();
	return 0;
}
