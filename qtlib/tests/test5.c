#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>

#include "qtreader.h"

int main(int argc, char *argv[])
{
	int fd_a, fd_b;
	struct qtreader_state state_a, state_b;
	struct qtrace_record record_a, record_b;
    bool r_a, r_b;

	fd_a = open(argv[1], O_RDONLY);
	if (fd_a < 0) {
		perror("open A");
		exit(1);
	}

	fd_b = open(argv[2], O_RDONLY);
	if (fd_b < 0) {
		perror("open B");
		exit(1);
	}

	if (qtreader_initialize_fd(&state_a, fd_a, 0) == false) {
		fprintf(stderr, "qtreader_initialize_fd failed\n");
		exit(1);
	}

	if (qtreader_initialize_fd_compressed(&state_b, fd_b, 0) == false) {
		fprintf(stderr, "qtreader_initialize_fd_compressed failed\n");
		exit(1);
	}

    do {
        r_a = qtreader_next_record(&state_a, &record_a);
        r_b = qtreader_next_record_compressed(&state_b, &record_b);

        if (r_a != r_b) {
            fprintf(stderr, "A(%d) and B(%d) different lengths\n", r_a, r_b);
            /*
            if (r_a) {
                while (qtreader_next_record(&state_a, &record_a)) {
                    printf("0x%08x\n", record_a.insn);
                }
            }
            if (r_b) {
                while (qtreader_next_record_compressed(&state_b, &record_b)) {
                    printf("0x%08x\n", record_b.insn);
                }
            }
            */
            exit(1);
        }

        if (r_a && r_b) {
            if (memcmp(&record_a, &record_b,
                        sizeof(struct qtrace_record)) != 0) {
                fprintf(stderr, "record mismatch\n");
                exit(1);
            }
        }

    } while (r_a && r_b);

    printf("qtrace match\n");
    qtreader_destroy(&state_a);
    qtreader_destroy(&state_b);

	return 0;
}
