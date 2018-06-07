#ifndef __QTLIB_H__
#define __QTLIB_H__

#include <stdbool.h>
#include <stdint.h>

#include "qtrace_record.h"

#define QTREADER_FLAGS_BRANCH	(1 << 0)
#define QTREADER_FLAGS_TLBIE	(1 << 1)

struct qtreader_state {
	uint32_t version;
	uint32_t magic;
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
	uint64_t flags;

	bool insn_rpn_valid;
	uint32_t insn_rpn;
	bool insn_page_size_valid;
	uint32_t insn_page_size;
	bool data_rpn_valid;
	uint32_t data_rpn;
	bool data_page_size_valid;
	uint32_t data_page_size;

	bool lpid_present;
	uint32_t lpid;
	bool pid_present;
	uint32_t pid;
};

bool qtreader_initialize(struct qtreader_state *state, void *mem, size_t size, unsigned int verbose);
bool qtreader_initialize_fd(struct qtreader_state *state, int fd, unsigned int verbose);

static inline uint32_t qtreader_version(struct qtreader_state *state)
{
	return state->version;
}

static inline uint32_t qtreader_magic(struct qtreader_state *state)
{
	return state->magic;
}

static inline void qtreader_set_branch_info(struct qtreader_state *state)
{
	state->flags |= QTREADER_FLAGS_BRANCH;
}

static inline void qtreader_clear_branch_info(struct qtreader_state *state)
{
	state->flags &= ~QTREADER_FLAGS_BRANCH;
}

static inline void qtreader_set_tlbie_info(struct qtreader_state *state)
{
	state->flags |= QTREADER_FLAGS_TLBIE;
}

static inline void qtreader_clear_tlbie_info(struct qtreader_state *state)
{
	state->flags &= ~QTREADER_FLAGS_TLBIE;
}

bool qtreader_next_record(struct qtreader_state *state, struct qtrace_record *record);
void qtreader_destroy(struct qtreader_state *state);

#endif
