#ifndef __QTLIB_H__
#define __QTLIB_H__

#include <stdbool.h>
#include <stdint.h>

struct qtrace_state {
	uint32_t version;
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

struct qtrace_record {
	uint32_t insn;
	uint64_t insn_addr;
	uint64_t insn_rpn;
	uint32_t insn_page_size;
	uint64_t data_addr;
	uint64_t data_rpn;
	uint32_t data_page_size;
	bool is_conditional_branch;
	bool is_unconditional_branch;
};

bool qtrace_initialize(struct qtrace_state *state, void *mem, size_t size, unsigned int verbose);
bool qtrace_initialize_fd(struct qtrace_state *state, int fd, unsigned int verbose);
bool qtrace_next_record(struct qtrace_state *state, struct qtrace_record *record);
void qtrace_destroy(struct qtrace_state *state);

#endif
