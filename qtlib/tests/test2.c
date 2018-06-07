#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "qtreader.h"

int main(int argc, char *argv[])
{
	int fd;
	struct qtreader_state state;
	struct qtrace_record record;

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		perror("open");
		exit(1);
	}

	if (qtreader_initialize_fd(&state, fd, 0) == false) {
		fprintf(stderr, "qtreader_initialize_fd failed\n");
		exit(1);
	}

	while (qtreader_next_record(&state, &record) == true)
                printf("%x %lx %lx %d %lx %lx %d %d %d %d\n", record.insn, record.insn_addr,
                        record.insn_ra, record.insn_page_shift, record.data_addr,
                        record.data_ra, record.data_page_shift, record.branch,
                        record.conditional_branch, record.branch_taken);


	return 0;
}
