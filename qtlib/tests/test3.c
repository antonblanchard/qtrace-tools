#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "qtreader.h"
#include "qtwriter.h"

int main(int argc, char *argv[])
{
	int fd;
	struct qtreader_state qtreader_state;
	struct qtwriter_state qtwriter_state;
	struct qtrace_record record;

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		perror("open");
		exit(1);
	}

	if (qtreader_initialize_fd(&qtreader_state, fd, 0) == false) {
		fprintf(stderr, "qtreader_initialize_fd failed\n");
		exit(1);
	}

	if (qtwriter_open(&qtwriter_state, argv[2], 0) == false) {
		fprintf(stderr, "qtwriter_open failed\n");
		exit(1);
	}

	while (qtreader_next_record(&qtreader_state, &record) == true) {
		if (qtwriter_write_record(&qtwriter_state, &record) == false) {
			fprintf(stderr, "qtwriter_write_record failed\n");
			exit(1);
		}
	}

	qtwriter_close(&qtwriter_state);

	return 0;
}
