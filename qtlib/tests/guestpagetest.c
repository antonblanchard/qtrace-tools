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

#define TESTFILENAME "runtest2.qt"

int run_qtwriter(void) {
	struct qtwriter_state state;
	struct qtrace_record record;

	memset(&state, 0, sizeof(state));

	qtwriter_open(&state, TESTFILENAME, 0);

	memset(&record, 0, sizeof(record));

	record.guest_insn_page_shift_valid = true;
	record.guest_insn_page_shift = 12;
	record.insn = 0xcafef00d;
	qtwriter_write_record(&state, &record);

	record.guest_insn_page_shift = 13;
	qtwriter_write_record(&state, &record);

	record.guest_data_page_shift = 9;
	record.guest_data_page_shift_valid = true;
	qtwriter_write_record(&state, &record);



	qtwriter_close(&state);

	return 0;
}


int run_qtreader(void) {
	int fd;
	struct qtreader_state state;
	struct qtrace_record record;

	fd = open(TESTFILENAME, O_RDONLY);
	if (fd < 0) {
		perror("open");
		exit(1);
	}

	if (qtreader_initialize_fd(&state, fd, 0) == false) {
		fprintf(stderr, "qtreader_initialize_fd failed\n");
		exit(1);
	}

	qtreader_next_record(&state, &record);
	assert(record.insn == 0xcafef00d);
	assert(record.guest_insn_page_shift_valid);
	assert(record.guest_insn_page_shift == 12);

	qtreader_next_record(&state, &record);
	assert(record.guest_insn_page_shift_valid);
	assert(record.guest_insn_page_shift == 13);

	qtreader_next_record(&state, &record);
	assert(record.guest_data_page_shift_valid);
	assert(record.guest_data_page_shift == 9);

	return 0;
}

/* Test guest instruction and data page size */
int main(void)
{
	run_qtwriter();
	run_qtreader();
	return 0;
}
