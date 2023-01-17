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

#define TESTFILENAME "runtest5.qt"

int run_qtwriter(void)
{
	struct qtwriter_state state;
	struct qtrace_record record;

	memset(&state, 0, sizeof(state));

	qtwriter_open(&state, TESTFILENAME, 0);

	memset(&record, 0, sizeof(record));

	record.insn_ra_valid = true;
	record.insn_ra = 0x100;
	record.insn = 0x6000000;

	record.radix_insn.nr_ptes = NR_RADIX_PTES;
	record.radix_insn.nr_pte_walks = 1;
	record.radix_insn.type = GUEST_REAL;
	record.radix_insn.host_ptes[0][0] = 0xdeadf00d;
	record.radix_insn.host_ptes[0][1] = 0xdeadf01d;
	record.radix_insn.host_ptes[0][2] = 0xdeadf02d;
	record.radix_insn.host_ptes[0][3] = 0xdeadf03d;

	qtwriter_write_record(&state, &record);

	record.data_addr_valid = true;
	record.data_ra = 0xc0000000;
	record.data_ra_valid = true;
	record.radix_data.nr_ptes = NR_RADIX_PTES;
	record.radix_data.nr_pte_walks = 1;
	record.radix_data.type = GUEST_REAL;
	record.radix_data.host_ptes[0][0] = 0xcafef00d;
	record.radix_data.host_ptes[0][1] = 0xcafef01d;
	record.radix_data.host_ptes[0][2] = 0xcafef02d;
	record.radix_data.host_ptes[0][3] = 0xcafef03d;
	qtwriter_write_record(&state, &record);

	qtwriter_close(&state);

	return 0;
}


int run_qtreader(void)
{
	int fd;
	struct qtrace_record record;
	struct qtreader_state state;

	fd = open(TESTFILENAME, O_RDONLY);
	if (fd < 0) {
		perror("open");
		exit(1);
	}

	if (qtreader_initialize_fd(&state, fd, 2) == false) {
		fprintf(stderr, "qtreader_initialize_fd failed\n");
		exit(1);
	}

	/* Test Instruction PTES */
	qtreader_next_record(&state, &record);
	assert(record.insn == 0x6000000);
	assert(record.radix_insn.type == GUEST_REAL);
	assert(record.radix_insn.nr_ptes == NR_RADIX_PTES);
	assert(record.radix_insn.host_ptes[0][0] == 0xdeadf00d);
	assert(record.radix_insn.host_ptes[0][1] == 0xdeadf01d);
	assert(record.radix_insn.host_ptes[0][2] == 0xdeadf02d);
	assert(record.radix_insn.host_ptes[0][3] == 0xdeadf03d);

	/* Test Data PTES */
	qtreader_next_record(&state, &record);
	assert(record.radix_data.nr_ptes == NR_RADIX_PTES);
	assert(record.radix_data.type == GUEST_REAL);
	assert(record.radix_data.host_ptes[0][0] == 0xcafef00d);
	assert(record.radix_data.host_ptes[0][1] == 0xcafef01d);
	assert(record.radix_data.host_ptes[0][2] == 0xcafef02d);
	assert(record.radix_data.host_ptes[0][3] == 0xcafef03d);

	return 0;
}

/* Testing Guest Real on Radix PTEs */
int main(void)
{
	run_qtwriter();
	run_qtreader();
	return 0;
}
