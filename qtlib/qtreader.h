#ifndef __QTLIB_H__
#define __QTLIB_H__

#ifdef __cplusplus
extern "C" {
#endif

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
	uint32_t next_insn_page_shift;
	bool next_insn_page_shift_valid;
	void *mem;
	void *ptr;
	size_t size;
	unsigned int verbose;
	int fd;
	uint64_t flags;
	bool prefixed;
	uint32_t suffix;

	bool insn_rpn_valid;
	uint32_t insn_rpn;
	bool insn_page_shift_valid;
	uint32_t insn_page_shift;
	bool data_rpn_valid;
	uint32_t data_rpn;
	bool data_page_shift_valid;
	uint32_t data_page_shift;

	bool guest_insn_page_shift_valid;
	uint32_t guest_insn_page_shift;
	uint32_t next_guest_insn_page_shift;
	bool next_guest_insn_page_shift_valid;

	bool lpid_present;
	uint32_t lpid;
	bool pid_present;
	uint32_t pid;

	unsigned int radix_nr_data_ptes;
	uint64_t radix_insn_ptes[NR_RADIX_PTES];
	uint64_t next_radix_insn_ptes[NR_RADIX_PTES];
	unsigned int radix_nr_insn_ptes;
	unsigned int next_radix_nr_insn_ptes;
	uint64_t radix_data_ptes[NR_RADIX_PTES];
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

#ifdef __cplusplus
}
#endif

#endif
