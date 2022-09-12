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

#define TESTFILENAME "runtest4.qt"

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
	record.radix_insn.nr_pte_walks = 5;
	for (int i = 0; i < record.radix_insn.nr_pte_walks; i++) {
		record.radix_insn.host_ptes[i][0] = 0xdeadf00 + i;
		record.radix_insn.host_ptes[i][1] = 0xdeadf00 + i;
		record.radix_insn.host_ptes[i][2] = 0xdeadf00 + i;
		record.radix_insn.host_ptes[i][3] = 0xdeadf00 + i;
	}

	for (int i = 0; i < record.radix_insn.nr_pte_walks - 1; i++)
		record.radix_insn.host_real_addrs[i] = 0xbeef00 + i;

	for (int i = 0; i < record.radix_insn.nr_pte_walks; i++)
		record.radix_insn.guest_real_addrs[i] = 0xfeed00 + i;


	qtwriter_write_record(&state, &record);

	record.data_addr_valid = true;
	record.data_ra = 0xc0000000;
	record.data_ra_valid = true;
	record.radix_data.nr_ptes = NR_RADIX_PTES;
	record.radix_data.nr_pte_walks = 5;
	for (int i = 0; i < record.radix_data.nr_pte_walks; i++) {
		record.radix_data.host_ptes[i][0] = 0xcafef00 + i;
		record.radix_data.host_ptes[i][1] = 0xcafef00 + i;
	}

	for (int i = 0; i < record.radix_data.nr_pte_walks - 1; i++)
		record.radix_data.host_real_addrs[i] = 0xfade00 + i;

	for (int i = 0; i < record.radix_data.nr_pte_walks; i++)
		record.radix_data.guest_real_addrs[i] = 0xbead00 + i;

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

	qtreader_next_record(&state, &record);
	assert(record.radix_insn.nr_pte_walks == 5);
	for (int i = 0; i < record.radix_insn.nr_pte_walks; i++) {
		assert(record.radix_insn.host_ptes[i][0] == 0xdeadf00 + i);
		assert(record.radix_insn.host_ptes[i][1] == 0xdeadf00 + i);
		assert(record.radix_insn.host_ptes[i][2] == 0xdeadf00 + i);
		assert(record.radix_insn.host_ptes[i][3] == 0xdeadf00 + i);
	}

	for (int i = 0; i < record.radix_insn.nr_pte_walks - 1; i++)
		assert(record.radix_insn.host_real_addrs[i] == 0xbeef00 + i);

	for (int i = 0; i < record.radix_insn.nr_pte_walks ; i++)
		assert(record.radix_insn.guest_real_addrs[i] == 0xfeed00 + i);

	qtreader_next_record(&state, &record);
	assert(record.radix_data.nr_pte_walks == 5);
	for (int i = 0; i < record.radix_data.nr_pte_walks; i++) {
		assert(record.radix_data.host_ptes[i][0] == 0xcafef00 + i);
		assert(record.radix_data.host_ptes[i][1] == 0xcafef00 + i);
		assert(record.radix_data.host_ptes[i][2] == 0);
		assert(record.radix_data.host_ptes[i][3] == 0);
	}

	for (int i = 0; i < record.radix_data.nr_pte_walks - 1; i++)
		assert(record.radix_data.host_real_addrs[i] == 0xfade00 + i);

	for (int i = 0; i < record.radix_data.nr_pte_walks; i++)
		assert(record.radix_data.guest_real_addrs[i] == 0xbead00 + i);

	return 0;
}

/* Testing Radix on Radix PTEs */
int main(void)
{
	run_qtwriter();
	run_qtreader();
	return 0;
}
