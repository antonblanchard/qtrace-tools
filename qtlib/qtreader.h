#ifndef __QTLIB_H__
#define __QTLIB_H__

#include <stdbool.h>
#include <stdint.h>

#include "qtrace_record.h"

struct qtreader_state {
	uint32_t version;
	uint32_t magic;

	/* Internal stuff */
	uint64_t next_insn_addr;
	uint32_t next_insn_rpn;
	bool next_insn_rpn_valid;
	uint32_t next_insn_page_size;
	bool next_insn_page_size_valid;
	void *mem;
	void *ptr;
	size_t size;
	unsigned int verbose;
	int fd;
};

bool qtreader_initialize(struct qtreader_state *state, void *mem, size_t size, unsigned int verbose);
bool qtreader_initialize_fd(struct qtreader_state *state, int fd, unsigned int verbose);
bool qtreader_next_record(struct qtreader_state *state, struct qtrace_record *record);
void qtreader_destroy(struct qtreader_state *state);

#endif
