/*
 * Qtrace reader library
 *
 * Copyright (C) 2017 Anton Blanchard <anton@au.ibm.com>, IBM
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "qtrace_record.h"
#include "qtrace.h"
#include "qtreader.h"
#include "endian-helpers.h"
#include "branch.h"

#define GET8(__state) \
({ \
	uint8_t t; \
	struct qtreader_state *s = (__state); \
	if (s->ptr + sizeof(t) > (s->mem + s->size)) \
		goto err; \
	t = *(uint8_t *)s->ptr; \
	s->ptr += sizeof(t); \
	t; \
})

#define GET16(__state) \
({ \
	uint16_t t; \
	struct qtreader_state *s = (__state); \
	if (s->ptr + sizeof(t) > (s->mem + s->size)) \
		goto err; \
	t = be16_to_cpup(s->ptr); \
	s->ptr += sizeof(t); \
	t; \
})

#define GET32(__state) \
({ \
	uint32_t t; \
	struct qtreader_state *s = (__state); \
	if (s->ptr + sizeof(t) > (s->mem + s->size)) \
		goto err; \
	t = be32_to_cpup(s->ptr); \
	s->ptr += sizeof(t); \
	t; \
})

#define GET64(__state) \
({ \
	uint64_t t; \
	struct qtreader_state *s = (__state); \
	if (s->ptr + sizeof(t) > (s->mem + s->size)) \
		goto err; \
	t = be64_to_cpup(s->ptr); \
	s->ptr += sizeof(t); \
	t; \
})

#define SKIP(__state, __n) \
do { \
	size_t n = (__n); \
	struct qtreader_state *s = (__state); \
	if (s->ptr + n > (s->mem + s->size)) \
		goto err; \
	s->ptr += n; \
} while (0)


static unsigned int get_radix_insn_ptes(uint16_t flags3)
{
	unsigned int host_mode;
	unsigned int guest_mode;

	guest_mode = (flags3 >> QTRACE_GUEST_XLATE_MODE_INSTRUCTION_SHIFT) &
			QTRACE_XLATE_MODE_MASK;

	host_mode = (flags3 >> QTRACE_HOST_XLATE_MODE_INSTRUCTION_SHIFT) &
			QTRACE_XLATE_MODE_MASK;

	if (guest_mode == QTRACE_XLATE_MODE_RADIX) {
		fprintf(stderr, "Unsupported radix configuration host %d guest %d\n",
			host_mode, guest_mode);
		exit(1);
	}

	if (host_mode == QTRACE_XLATE_MODE_RADIX)
		return NR_RADIX_PTES;

	return 0;
}

static unsigned int get_radix_data_ptes(uint16_t flags3)
{
	unsigned int host_mode;
	unsigned int guest_mode;

	guest_mode = (flags3 >> QTRACE_GUEST_XLATE_MODE_DATA_SHIFT) &
			QTRACE_XLATE_MODE_MASK;

	host_mode = (flags3 >> QTRACE_HOST_XLATE_MODE_DATA_SHIFT) &
			QTRACE_XLATE_MODE_MASK;

	if (guest_mode == QTRACE_XLATE_MODE_RADIX) {
		fprintf(stderr, "Unsupported radix configuration host %d guest %d\n",
			host_mode, guest_mode);
		exit(1);
	}

	if (host_mode == QTRACE_XLATE_MODE_RADIX)
		return NR_RADIX_PTES;

	return 0;
}

static bool parse_radix(struct qtreader_state *state, unsigned int nr, uint64_t *ptes)
{
	unsigned long i;

	for (i = 0; i < nr; i++) {
		uint64_t p = GET64(state);

		if (ptes)
			ptes[i] = p;
	}

	return true;

err:
	return false;
}

/*
 * A header has a zero instruction, a set of record flags, and a set of file
 * header flags. Only a few of the record flags values are populated.
 */
static bool qtreader_parse_header(struct qtreader_state *state)
{
	uint32_t insn;
	uint16_t flags = 0, flags2 = 0, flags3 = 0, hdr_flags = 0;

	insn = GET32(state);

	if (insn) {
		fprintf(stderr, "Invalid file, insn is not zero\n");
		goto err;
	}

	flags = GET16(state);

	if (flags != QTRACE_EXTENDED_FLAGS_PRESENT) {
		fprintf(stderr, "Invalid file, extended flags missing\n");
		goto err;
	}

	flags2 = GET16(state);

	if (!(flags2 & QTRACE_FILE_HEADER_PRESENT)) {
		fprintf(stderr, "Invalid file, file header missing\n");
		goto err;
	}

	if (flags2 & ~(QTRACE_FILE_HEADER_PRESENT|QTRACE_EXTENDED_FLAGS2_PRESENT)) {
		fprintf(stderr, "Invalid file, incorrect extended flags\n");
		goto err;
	}

	if (flags2 & QTRACE_EXTENDED_FLAGS2_PRESENT)
		flags3 = GET16(state);

	hdr_flags = GET16(state);

	if (state->verbose >= 2) {
		printf("flags 0x%04x flags2 0x%04x flags3 0x%04x hdr_flags 0x%04x\n",
			flags, flags2, flags3, hdr_flags);
	}

	if (flags3 & UNHANDLED_FLAGS3) {
		fprintf(stderr, "Unhandled flags3 0x%04x\n", flags3 & UNHANDLED_FLAGS3);
		goto err;
	}

	if (hdr_flags & UNHANDLED_HDR_FLAGS) {
		fprintf(stderr, "Unhandled file header flags 0x%04x\n", hdr_flags & UNHANDLED_HDR_FLAGS);
		goto err;
	}

	if (hdr_flags & QTRACE_HDR_MAGIC_NUMBER_PRESENT)
		state->magic = GET32(state);

	if (hdr_flags & QTRACE_HDR_VERSION_NUMBER_PRESENT)
		state->version = GET32(state);

	if (hdr_flags & QTRACE_HDR_IAR_PRESENT)
		state->next_insn_addr = GET64(state);

	if (hdr_flags & QTRACE_HDR_IAR_VSID_PRESENT)
		SKIP(state, 7);

	if ((hdr_flags & QTRACE_HDR_IAR_RPN_PRESENT) && IS_RADIX(flags2)) {
		unsigned int nr = get_radix_insn_ptes(flags3);

		if (parse_radix(state, nr, NULL) == false)
			goto err;
	}

	if (hdr_flags & QTRACE_HDR_IAR_RPN_PRESENT) {
		state->insn_rpn_valid = true;
		state->next_insn_rpn_valid = true;
		state->next_insn_rpn = GET32(state);
	}

	if (hdr_flags & QTRACE_HDR_IAR_PAGE_SIZE_PRESENT) {
		state->insn_page_size_valid = true;
		state->next_insn_page_size_valid = true;
		state->next_insn_page_size = GET8(state);
	}

	if (hdr_flags & QTRACE_HDR_IAR_GPAGE_SIZE_PRESENT)
		SKIP(state, 1);

	if (flags3 & QTRACE_PTCR_PRESENT)
		GET64(state);

	if (flags3 & QTRACE_LPID_PRESENT) {
		state->lpid_present = true;
		state->lpid = GET64(state);
	}

	if (flags3 & QTRACE_PID_PRESENT) {
		state->pid_present = true;
		state->pid = GET32(state);
	}

	if (hdr_flags & QTRACE_HDR_COMMENT_PRESENT) {
		uint16_t len = GET16(state);

		if (state->ptr + len > (state->mem + state->size))
			goto err;

		state->ptr += len;
	}

	return true;

err:
	return false;
}

bool qtreader_initialize(struct qtreader_state *state, void *mem, size_t size, unsigned int verbose)
{
	memset(state, 0, sizeof(*state));

	state->mem = state->ptr = mem;
	state->size = size;
	state->verbose = verbose;
	state->fd = -1;
	state->next_insn_addr = -1UL;

	if (qtreader_parse_header(state) == false)
		return false;

	if (state->next_insn_addr == -1UL)
		fprintf(stderr, "Warning: header has no instruction address\n");

	return true;
}

#define OPCODE(insn)		((insn) >> 26)
#define SUB_OPCODE(insn)	(((insn) >> 1) & 0x3ff)

#define LINK(insn)		((insn) & 0x1)
#define AA(insn)		(((insn) >> 1) & 0x1)
#define BH(insn)		(((insn) >> 11) & 0x3)
#define BO(insn)		(((insn) >> 21) & 0x1f)
#define BI(insn)		(((insn) >> 16) & 0x1f)
#define BD(insn)		(((insn) >> 2) & 0x3fff)

static void annotate_branch(struct qtrace_record *record)
{
	uint32_t insn = record->insn;
	uint32_t opcode = OPCODE(insn);

	/*
	 * Look for bcl 20,31,$+4 - this sequence is special and used for
	 * addressing.
	 */
	if ((opcode == 16) && (AA(insn) == 0) && (LINK(insn) == 1)) {
		if ((BO(insn) == 20) && (BI(insn) == 31) && (BD(insn) == 1)) {
			assert(record->conditional_branch == false);
			record->branch_direct = true;
			record->branch_type = ADDRESSING;
			return;
		}
	}

	record->branch_direct = true;
	record->branch_type = BRANCH;

	if (LINK(insn))
		record->branch_type = CALL;

	/* Unconditional branches */
	if (opcode == 18) {
		assert(record->conditional_branch == false);
		return;
	}

	/* Conditional branches */
	if (opcode == 16) {
		if (record->conditional_branch != true)
			printf("%lx\n", record->insn_addr);
		assert(record->conditional_branch == true);
		return;
	}

	/* sc, scv */
	if (opcode == 17 || opcode == 18) {
		record->branch_type = SYSTEM_CALL_EXCEPTION;
		/* Bug in mambo? */
		//assert(record->conditional_branch == false);
		return;
	}

	/* branch to LR, CTR and TAR */
	if (opcode == 19) {
		switch (SUB_OPCODE(insn)) {
		/* bclr, bclrl */
		case 16:
			if (BH(insn) == 0)
				record->branch_type = RETURN;

			assert(branch_conditional_is_conditional(insn) ==
			       record->conditional_branch);

			return;

		/* bcctr, bctar */
		case 528:
		case 560:
			record->branch_direct = false;

			assert(branch_conditional_is_conditional(insn) ==
			       record->conditional_branch);

			return;

		case 50:	/* rfi */
		case 18:	/* rfid */
		case 274:	/* hrfid */
		case 82:	/* rfscv */
			record->branch_type = EXCEPTION_RETURN;
			/* bug in mambo? */
			//assert(record->conditional_branch == false);
			return;
		}
	}

	/* Most likely a decrementer, page fault etc */
	record->branch_type = ASYNC_EXCEPTION;
}

bool qtreader_next_record(struct qtreader_state *state, struct qtrace_record *record)
{
	uint16_t flags, flags2 = 0, flags3 = 0;

	memset(record, 0, sizeof(*record));

	/*
	 * We sometimes see header records in the middle of a trace, which are
	 * identified by a null instruction. Skip over them.
	 */
	while (be32_to_cpup(state->ptr) == 0) {
		if (qtreader_parse_header(state) == false)
			goto err;
	}

	record->insn_addr = state->next_insn_addr;

	if (state->next_insn_rpn_valid) {
		if (!state->insn_rpn_valid) {
			fprintf(stderr, "Warning: insn rpn becomes valid\n");
			state->insn_rpn_valid = true;
		}
		state->insn_rpn = state->next_insn_rpn;
	}
	if (state->insn_rpn_valid) {
		record->insn_rpn_valid = true;
		record->insn_rpn = state->insn_rpn;
	}

	if (state->next_insn_page_size_valid) {
		if (!state->insn_page_size_valid) {
			fprintf(stderr, "Warning: insn page size becomes valid\n");
			state->insn_page_size_valid = true;
		}
		state->insn_page_size = state->next_insn_page_size;
	}
	if (state->insn_page_size_valid) {
		record->insn_page_size_valid = true;
		record->insn_page_size = state->insn_page_size;
	}

	record->insn = GET32(state);

	flags = GET16(state);

	if (flags & QTRACE_EXTENDED_FLAGS_PRESENT) {
		flags2 = GET16(state);

		if (flags2 & QTRACE_EXTENDED_FLAGS2_PRESENT)
			flags3 = GET16(state);
	}

	if (flags & UNHANDLED_FLAGS) {
		fprintf(stderr, "Unhandled flags 0x%04x\n", flags & UNHANDLED_FLAGS);
		goto err;
	}

	if (flags2 & UNHANDLED_FLAGS2) {
		fprintf(stderr, "Unhandled flags2 0x%04x\n", flags2 & UNHANDLED_FLAGS2);
		goto err;
	}

	if (flags3 & UNHANDLED_FLAGS3) {
		fprintf(stderr, "Unhandled flags3 0x%04x\n", flags3 & UNHANDLED_FLAGS3);
		goto err;
	}

	if (state->verbose >= 2) {
		printf("flags 0x%04x flags2 0x%04x flags3 0x%04x\n",
			flags, flags2, flags3);
	}

	/* This bit is used on its own, no extra storage is allocated */
	if (flags & QTRACE_IAR_CHANGE_PRESENT) {
	}

	if (flags & QTRACE_NODE_PRESENT)
		GET8(state);

	if (flags & QTRACE_TERMINATION_PRESENT) {
		uint8_t termination_code;

		record->branch = true;

		GET8(state);
		termination_code = GET8(state);

		if ((termination_code == QTRACE_EXCEEDED_MAX_INST_DEPTH) ||
		    (termination_code == QTRACE_EXCEEDED_MAX_BRANCH_DEPTH))
			record->conditional_branch = true;
		else if (termination_code == QTRACE_UNCONDITIONAL_BRANCH)
			record->conditional_branch = false;
		else {
			printf("Inconsistent branch\n");
			goto err;
		}

		if (state->flags & QTREADER_FLAGS_BRANCH)
			annotate_branch(record);
	}

	if (flags & QTRACE_PROCESSOR_PRESENT)
		GET8(state);

	if (flags & QTRACE_DATA_ADDRESS_PRESENT) {
		record->data_addr_valid = true;
		record->data_addr = GET64(state);
	}

	if (flags & QTRACE_DATA_VSID_PRESENT)
		SKIP(state, 7);

	if ((flags & QTRACE_DATA_RPN_PRESENT) && IS_RADIX(flags2)) {
		unsigned int radix_nr_data_ptes = get_radix_data_ptes(flags3);

		if (parse_radix(state, radix_nr_data_ptes, NULL) == false)
			goto err;
	}

	if (flags & QTRACE_DATA_RPN_PRESENT) {
		if (!state->data_rpn_valid)
			state->data_rpn_valid = true;
		state->data_rpn = GET32(state);
	}
	if (state->data_rpn_valid) {
		record->data_rpn_valid = true;
		record->data_rpn = state->data_rpn;
	} else {
		record->data_rpn_valid = false;
	}

	if (flags & QTRACE_IAR_PRESENT) {
		state->next_insn_addr = GET64(state);
	} else {
		state->next_insn_addr += sizeof(uint32_t);
	}

	record->next_insn_addr = state->next_insn_addr;

	if (flags & QTRACE_TERMINATION_PRESENT) {
		if (state->next_insn_addr != record->insn_addr + sizeof(uint32_t))
			record->branch_taken = true;
		else
			record->branch_taken = false;
	} else if (is_conditional_branch(record->insn)) {
		/*
		 * Some qtraces are missing termination codes on not taken
		 * conditional branches. Fix it here.
		 */
		record->branch = true;
		record->conditional_branch = true;
	}

	if (flags & QTRACE_IAR_VSID_PRESENT)
		SKIP(state, 7);

	if ((flags & QTRACE_IAR_RPN_PRESENT) && IS_RADIX(flags2)) {
		unsigned int radix_nr_insn_ptes = get_radix_insn_ptes(flags3);

		if (parse_radix(state, radix_nr_insn_ptes, NULL) == false)
			goto err;
	}

	if (flags & QTRACE_IAR_RPN_PRESENT) {
		state->next_insn_rpn_valid = true;
		state->next_insn_rpn = GET32(state);
	} else {
		state->next_insn_rpn_valid = false;
	}


	/* FIXME */
	if (flags & QTRACE_REGISTER_TRACE_PRESENT) {
		uint8_t gprs_in, fprs_in, vmxs_in, vsxs_in = 0, sprs_in;
		uint8_t gprs_out, fprs_out, vmxs_out, vsxs_out = 0, sprs_out;
		uint32_t sz;

		gprs_in = GET8(state);
		fprs_in = GET8(state);
		vmxs_in = GET8(state);
		if (state->version >= 0x7000000)
			vsxs_in = GET8(state);
		sprs_in = GET8(state);

		gprs_out = GET8(state);
		fprs_out = GET8(state);
		vmxs_out = GET8(state);
		if (state->version >= 0x7000000)
			vsxs_out = GET8(state);
		sprs_out = GET8(state);

		sz = gprs_in * (sizeof(uint8_t) + sizeof(uint64_t));
		sz += fprs_in * (sizeof(uint8_t) + sizeof(uint64_t));
		sz += vmxs_in * (sizeof(uint16_t) + sizeof(uint64_t) * 2);
		sz += vsxs_in * (sizeof(uint16_t) + sizeof(uint64_t) * 2);
		sz += sprs_in * (sizeof(uint16_t) + sizeof(uint64_t));

		sz += gprs_out * (sizeof(uint8_t) + sizeof(uint64_t));
		sz += fprs_out * (sizeof(uint8_t) + sizeof(uint64_t));
		sz += vmxs_out * (sizeof(uint16_t) + sizeof(uint64_t) * 2);
		sz += vsxs_out * (sizeof(uint16_t) + sizeof(uint64_t) * 2);
		sz += sprs_out * (sizeof(uint16_t) + sizeof(uint64_t));

		if (state->ptr + sz > (state->mem + state->size))
			goto err;

		state->ptr += sz;
	}

	if (flags2 & QTRACE_SEQUENTIAL_INSTRUCTION_RPN_PRESENT) {
		uint32_t insn_rpn = GET32(state);
		if (!state->next_insn_rpn_valid) {
			state->next_insn_rpn_valid = true;
			state->next_insn_rpn = insn_rpn;
		}
	}

	/* FIXME */
	if (flags2 & QTRACE_TRACE_ERROR_CODE_PRESENT)
		GET8(state);

	if (flags2 & QTRACE_SEQUENTIAL_INSTRUCTION_PAGE_SIZE_PRESENT) {
		uint8_t insn_page_size = GET8(state);
		state->next_insn_page_size_valid = true;
		state->next_insn_page_size = insn_page_size;
	}

	if (flags2 & QTRACE_IAR_PAGE_SIZE_PRESENT) {
		state->next_insn_page_size_valid = true;
		state->next_insn_page_size = GET8(state);
	} else {
		state->next_insn_page_size_valid = false;
	}

	if (flags2 & QTRACE_DATA_PAGE_SIZE_PRESENT) {
		record->data_page_size_valid = true;
		record->data_page_size = GET8(state);
	} else {
		record->data_page_size_valid = false;
	}

	if (flags2 & QTRACE_INSTRUCTION_GPAGE_SIZE_PRESENT)
		SKIP(state, 1);

	if (flags2 & QTRACE_DATA_GPAGE_SIZE_PRESENT)
		SKIP(state, 1);

	return true;

err:
	return false;
}

bool qtreader_initialize_fd(struct qtreader_state *state, int fd, unsigned int verbose)
{
	struct stat buf;
	size_t size;
	void *p;
	bool ret;

	if (fstat(fd, &buf)) {
		perror("fstat");
		return false;
	}
	size = buf.st_size;

	p = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
	if (p == MAP_FAILED) {
		perror("mmap");
		return false;
	}

	ret = qtreader_initialize(state, p, size, verbose);

	/* qtrace_initialize zeroes ->fd, so we have to do this here */
	state->fd = fd;

	return ret;
}

void qtreader_destroy(struct qtreader_state *state)
{
	if (state->fd != -1) {
		munmap(state->mem, state->size);
		close(state->fd);
	}
}
