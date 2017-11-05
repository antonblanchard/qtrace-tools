/*
 * Qtrace parsing library
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
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "qtlib.h"

/* File header flags */
#define QTRACE_HDR_MAGIC_NUMBER_PRESENT			0x8000
#define QTRACE_HDR_VERSION_NUMBER_PRESENT		0x4000
#define QTRACE_HDR_IAR_PRESENT				0x2000
#define QTRACE_HDR_IAR_RPN_PRESENT			0x0800
#define QTRACE_HDR_IAR_PAGE_SIZE_PRESENT		0x0040
#define QTRACE_HDR_COMMENT_PRESENT			0x0002

#define UNHANDLED_HDR_FLAGS	(~(QTRACE_HDR_MAGIC_NUMBER_PRESENT|QTRACE_HDR_VERSION_NUMBER_PRESENT|QTRACE_HDR_IAR_PRESENT|QTRACE_HDR_IAR_RPN_PRESENT|QTRACE_HDR_IAR_PAGE_SIZE_PRESENT|QTRACE_HDR_COMMENT_PRESENT))

/* Primary flags */
#define QTRACE_IAR_CHANGE_PRESENT			0x8000
#define QTRACE_NODE_PRESENT				0x4000
#define QTRACE_TERMINATION_PRESENT			0x2000
#define QTRACE_PROCESSOR_PRESENT			0x1000
#define QTRACE_DATA_ADDRESS_PRESENT			0x0800
#define QTRACE_DATA_RPN_PRESENT				0x0200
#define QTRACE_IAR_PRESENT				0x0040
#define QTRACE_IAR_RPN_PRESENT				0x0010
#define QTRACE_REGISTER_TRACE_PRESENT			0x0008
#define QTRACE_EXTENDED_FLAGS_PRESENT			0x0001

#define UNHANDLED_FLAGS	(~(QTRACE_IAR_CHANGE_PRESENT|QTRACE_NODE_PRESENT|QTRACE_TERMINATION_PRESENT|QTRACE_PROCESSOR_PRESENT|QTRACE_DATA_ADDRESS_PRESENT|QTRACE_DATA_RPN_PRESENT|QTRACE_IAR_PRESENT|QTRACE_IAR_RPN_PRESENT|QTRACE_REGISTER_TRACE_PRESENT|QTRACE_EXTENDED_FLAGS_PRESENT))

/* First extended flags */
#define QTRACE_SEQUENTIAL_INSTRUCTION_RPN_PRESENT	0x4000
#define QTRACE_TRACE_ERROR_CODE_PRESENT			0x1000
#define QTRACE_IAR_PAGE_SIZE_PRESENT			0x0200
#define QTRACE_DATA_PAGE_SIZE_PRESENT			0x0100
#define QTRACE_SEQUENTIAL_INSTRUCTION_PAGE_SIZE_PRESENT	0x0020
#define QTRACE_FILE_HEADER_PRESENT			0x0002
#define QTRACE_EXTENDED_FLAGS2_PRESENT			0x0001

#define UNHANDLED_FLAGS2	(~(QTRACE_SEQUENTIAL_INSTRUCTION_RPN_PRESENT|QTRACE_TRACE_ERROR_CODE_PRESENT|QTRACE_IAR_PAGE_SIZE_PRESENT|QTRACE_DATA_PAGE_SIZE_PRESENT|QTRACE_SEQUENTIAL_INSTRUCTION_PAGE_SIZE_PRESENT|QTRACE_FILE_HEADER_PRESENT|QTRACE_EXTENDED_FLAGS2_PRESENT))

#define IS_RADIX(FLAGS2)	((FLAGS2) & QTRACE_EXTENDED_FLAGS2_PRESENT)

/* Second extended flags */
#define QTRACE_HOST_XLATE_MODE_DATA			0xC000
#define QTRACE_HOST_XLATE_MODE_DATA_SHIFT		14
#define QTRACE_GUEST_XLATE_MODE_DATA			0x3000
#define QTRACE_GUEST_XLATE_MODE_DATA_SHIFT		12
#define QTRACE_HOST_XLATE_MODE_INSTRUCTION		0x0C00
#define QTRACE_HOST_XLATE_MODE_INSTRUCTION_SHIFT	10
#define QTRACE_GUEST_XLATE_MODE_INSTRUCTION		0x0300
#define QTRACE_GUEST_XLATE_MODE_INSTRUCTION_SHIFT	8
#define QTRACE_PTCR_PRESENT				0x0080
#define QTRACE_LPID_PRESENT				0x0040
#define QTRACE_PID_PRESENT				0x0020

#define QTRACE_XLATE_MODE_MASK				0x3
#define QTRACE_XLATE_MODE_RADIX				0
#define QTRACE_XLATE_MODE_HPT				1
#define QTRACE_XLATE_MODE_REAL				2
#define QTRACE_XLATE_MODE_NOT_DEFINED			3

#define UNHANDLED_FLAGS3 0

/* Termination codes */
#define QTRACE_EXCEEDED_MAX_INST_DEPTH			0x40
#define QTRACE_UNCONDITIONAL_BRANCH			0x08

/* 4 level radix */
#define NR_RADIX_PTES	4

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define be16_to_cpup(A)	__builtin_bswap16(*(uint16_t *)(A))
#define be32_to_cpup(A)	__builtin_bswap32(*(uint32_t *)(A))
#define be64_to_cpup(A)	__builtin_bswap64(*(uint64_t *)(A))
#else
#define be16_to_cpup(A)	(*(uint16_t *)A)
#define be32_to_cpup(A)	(*(uint32_t *)A)
#define be64_to_cpup(A)	(*(uint64_t *)A)
#endif

#define GET8(__state) \
({ \
	uint8_t t; \
	struct qtrace_state *s = (__state); \
	if (s->ptr + sizeof(t) > (s->mem + s->size)) \
		goto err; \
	t = *(uint8_t *)s->ptr; \
	s->ptr += sizeof(t); \
	t; \
})

#define GET16(__state) \
({ \
	uint16_t t; \
	struct qtrace_state *s = (__state); \
	if (s->ptr + sizeof(t) > (s->mem + s->size)) \
		goto err; \
	t = be16_to_cpup(s->ptr); \
	s->ptr += sizeof(t); \
	t; \
})

#define GET32(__state) \
({ \
	uint32_t t; \
	struct qtrace_state *s = (__state); \
	if (s->ptr + sizeof(t) > (s->mem + s->size)) \
		goto err; \
	t = be32_to_cpup(s->ptr); \
	s->ptr += sizeof(t); \
	t; \
})

#define GET64(__state) \
({ \
	uint64_t t; \
	struct qtrace_state *s = (__state); \
	if (s->ptr + sizeof(t) > (s->mem + s->size)) \
		goto err; \
	t = be64_to_cpup(s->ptr); \
	s->ptr += sizeof(t); \
	t; \
})

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

static bool parse_radix(struct qtrace_state *state, unsigned int nr, uint64_t *ptes)
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
static bool qtrace_parse_header(struct qtrace_state *state)
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
		GET32(state);

	if (hdr_flags & QTRACE_HDR_VERSION_NUMBER_PRESENT)
		state->version = GET32(state);

	if (hdr_flags & QTRACE_HDR_IAR_PRESENT)
		state->next_insn_addr = GET64(state);

	if ((hdr_flags & QTRACE_HDR_IAR_RPN_PRESENT) && IS_RADIX(flags2)) {
		unsigned int nr = get_radix_insn_ptes(flags3);

		if (parse_radix(state, nr, NULL) == false)
			goto err;
	}

	if (hdr_flags & QTRACE_HDR_IAR_RPN_PRESENT) {
		state->next_insn_rpn_valid = true;
		state->next_insn_rpn = GET32(state);
	}

	if (hdr_flags & QTRACE_HDR_IAR_PAGE_SIZE_PRESENT) {
		state->next_insn_page_size_valid = true;
		state->next_insn_page_size = GET8(state);
	}

	if (flags3 & QTRACE_PTCR_PRESENT)
		GET64(state);

	if (flags3 & QTRACE_LPID_PRESENT)
		GET64(state);

	if (flags3 & QTRACE_PID_PRESENT)
		GET32(state);

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

bool qtrace_initialize(struct qtrace_state *state, void *mem, size_t size, unsigned int verbose)
{
	memset(state, 0, sizeof(*state));

	state->mem = state->ptr = mem;
	state->size = size;
	state->verbose = verbose;
	state->fd = -1;

	if (qtrace_parse_header(state) == false)
		return false;

	return true;
}

bool qtrace_next_record(struct qtrace_state *state, struct qtrace_record *record)
{
	uint16_t flags, flags2 = 0, flags3 = 0;

	memset(record, 0, sizeof(*record));

	/*
	 * We sometimes see header records in the middle of a trace, which are
	 * identified by a null instruction. Skip over them.
	 */
	while (be32_to_cpup(state->ptr) == 0) {
		if (qtrace_parse_header(state) == false)
			goto err;
	}

	record->insn_addr = state->next_insn_addr;

	if (state->next_insn_rpn_valid)
		record->insn_rpn = state->next_insn_rpn;

	if (state->next_insn_page_size_valid)
		record->insn_page_size = state->next_insn_page_size;

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

		GET8(state);
		termination_code = GET8(state);

		if (termination_code == QTRACE_EXCEEDED_MAX_INST_DEPTH)
			record->is_conditional_branch = true;
		else
			record->is_conditional_branch = false;

		if (termination_code == QTRACE_UNCONDITIONAL_BRANCH)
			record->is_unconditional_branch = true;
		else
			record->is_unconditional_branch = false;
	}

	if (flags & QTRACE_PROCESSOR_PRESENT)
		GET8(state);

	if (flags & QTRACE_DATA_ADDRESS_PRESENT)
		record->data_addr = GET64(state);

	if ((flags & QTRACE_DATA_RPN_PRESENT) && IS_RADIX(flags2)) {
		unsigned int radix_nr_data_ptes = get_radix_data_ptes(flags3);

		if (parse_radix(state, radix_nr_data_ptes, NULL) == false)
			goto err;
	}

	if (flags & QTRACE_DATA_RPN_PRESENT)
		record->data_rpn = GET32(state);

	if (flags & QTRACE_IAR_PRESENT) {
		state->next_insn_addr = GET64(state);
	} else {
		state->next_insn_addr += sizeof(uint32_t);
	}

	if ((flags & QTRACE_IAR_RPN_PRESENT) && IS_RADIX(flags2)) {
		unsigned int radix_nr_insn_ptes = get_radix_insn_ptes(flags3);

		if (parse_radix(state, radix_nr_insn_ptes, NULL) == false)
			goto err;
	}

	if (flags & QTRACE_IAR_RPN_PRESENT)
		state->next_insn_rpn = GET32(state);

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

	if (flags2 & QTRACE_SEQUENTIAL_INSTRUCTION_RPN_PRESENT)
		GET32(state);

	if (flags2 & QTRACE_TRACE_ERROR_CODE_PRESENT)
		GET8(state);

	if (flags2 & QTRACE_SEQUENTIAL_INSTRUCTION_PAGE_SIZE_PRESENT)
		GET8(state);

	if (flags2 & QTRACE_IAR_PAGE_SIZE_PRESENT)
		state->next_insn_page_size = GET8(state);

	if (flags2 & QTRACE_DATA_PAGE_SIZE_PRESENT)
		record->data_page_size = GET8(state);

	return true;

err:
	return false;
}

bool qtrace_initialize_fd(struct qtrace_state *state, int fd, unsigned int verbose)
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

	ret = qtrace_initialize(state, p, size, verbose);

	/* qtrace_initialize zeroes ->fd, so we have to do this here */
	state->fd = fd;

	return ret;
}

void qtrace_destroy(struct qtrace_state *state)
{
	if (state->fd != -1) {
		free(state->mem);
		close(state->fd);
	}
}
