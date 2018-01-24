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
                        record.insn_rpn, record.insn_page_size, record.data_addr,
                        record.data_rpn, record.data_page_size, record.is_conditional_branch,
                        record.is_unconditional_branch, record.branch_taken);


	return 0;
}
