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
#include <archive.h>
#include <archive_entry.h>

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
		state->insn_page_shift_valid = true;
		state->next_insn_page_shift_valid = true;
		state->next_insn_page_shift = GET8(state);
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

#define RIC(insn)		(((insn) >> 18) & 0x3)
#define PRS(insn)		(((insn) >> 17) & 0x1)
#define R(insn)			(((insn) >> 16) & 0x1)
#define IS(rb)			(((rb) >> 10) & 0x3)
#define AP(rb)			(((rb) >> 5) & 0x7)
#define EPN(rb)			(((rb) >> 12) & 0x7ffffffffffffULL)
#define SET(rb)			(((rb) >> 12) & 0xfffU)

static bool annotate_tlbie(struct qtreader_state *state, struct qtrace_record *record)
{
	struct qtrace_reg_state *regs = &record->regs;
	uint32_t insn = record->insn;
	uint32_t opcode = OPCODE(insn);
	uint32_t sub_opcode = SUB_OPCODE(insn);
	uint64_t rb, rs;
	uint8_t ap;
	uint64_t epn;

	if (opcode != 31)
		return true;
	if (sub_opcode != 274 && sub_opcode != 306)
		return true;

	record->tlbie = true;
	record->tlbie_local = (sub_opcode == 274);

	if (regs->nr_gprs_out != 2)
		return false; /* no gprs */

	rb = regs->gprs_out[0].value;
	rs = regs->gprs_out[1].value;
	record->tlbie_ric = RIC(insn);
	record->tlbie_prs = PRS(insn);
	record->tlbie_r = R(insn);
	record->tlbie_is = IS(rb);

	if (record->tlbie_r != 1) {
		fprintf(stderr, "Error: hash tlbie not supported\n");
		return false; /* hash not supported */
	}

	if (record->tlbie_is == 0) {
		ap = AP(rb);
		epn = EPN(rb);
		switch (ap) {
		case 0x0:
			record->tlbie_page_shift = 12;
			break;
		case 0x5:
			record->tlbie_page_shift = 16;
			break;
		case 0x1:
			record->tlbie_page_shift = 21;
			break;
		case 0x2:
			record->tlbie_page_shift = 30;
			break;
		default:
			fprintf(stderr, "Error: bad tlbie AP\n");
			return false;
		}
		record->tlbie_addr = epn << 12;
	}

	record->tlbie_pid = rs >> 32;
	if (record->tlbie_local) {
		record->tlbie_lpid = state->lpid;
		if (record->tlbie_is != 0)
			record->tlbie_set = SET(rb);
	} else {
		record->tlbie_lpid = rs & 0xffffffffUL;
	}

	return true;
}

static bool do_parse_regs(struct qtreader_state *state, struct qtrace_reg_state *regs)
{
	int i;

	regs->nr_gprs_in = GET8(state);
	regs->nr_fprs_in = GET8(state);
	regs->nr_vmxs_in = GET8(state);
	if (state->version >= 0x7000000)
		regs->nr_vsxs_in = GET8(state);
	else
		regs->nr_vsxs_in = 0;
	regs->nr_sprs_in = GET8(state);

	regs->nr_gprs_out = GET8(state);
	regs->nr_fprs_out = GET8(state);
	regs->nr_vmxs_out = GET8(state);
	if (state->version >= 0x7000000)
		regs->nr_vsxs_out = GET8(state);
	else
		regs->nr_vsxs_out = 0;
	regs->nr_sprs_out = GET8(state);

	for (i = 0; i < regs->nr_gprs_in; i++) {
		regs->gprs_in[i].index = GET8(state);
		regs->gprs_in[i].value = GET64(state);
	}
	for (i = 0; i < regs->nr_fprs_in; i++) {
		regs->fprs_in[i].index = GET8(state);
		regs->fprs_in[i].value = GET64(state);
	}
	state->ptr += regs->nr_vmxs_in * (sizeof(uint16_t) + sizeof(uint64_t) * 2);
	state->ptr += regs->nr_vsxs_in * (sizeof(uint16_t) + sizeof(uint64_t) * 2);
	for (i = 0; i < regs->nr_sprs_in; i++) {
		regs->sprs_in[i].index = GET16(state);
		regs->sprs_in[i].value = GET64(state);
	}

	for (i = 0; i < regs->nr_gprs_out; i++) {
		regs->gprs_out[i].index = GET8(state);
		regs->gprs_out[i].value = GET64(state);
	}
	for (i = 0; i < regs->nr_fprs_out; i++) {
		regs->fprs_out[i].index = GET8(state);
		regs->fprs_out[i].value = GET64(state);
	}
	state->ptr += regs->nr_vmxs_out * (sizeof(uint16_t) + sizeof(uint64_t) * 2);
	state->ptr += regs->nr_vsxs_out * (sizeof(uint16_t) + sizeof(uint64_t) * 2);
	for (i = 0; i < regs->nr_sprs_out; i++) {
		regs->sprs_out[i].index = GET16(state);
		regs->sprs_out[i].value = GET64(state);
	}

	if (state->ptr > (state->mem + state->size))
		goto err;

	return true;

err:
	return false;
}

bool qtreader_next_record(struct qtreader_state *state, struct qtrace_record *record)
{
	uint16_t flags, flags2 = 0, flags3 = 0;

	memset(record, 0, sizeof(*record));

	/*
	 * We sometimes see header records in the middle of a trace, which are
	 * identified by a null instruction. Skip over them.
	 * Suffixes of prefixed instructions come as seperate records and can
	 * be null.
	 */
	while (be32_to_cpup(state->ptr) == 0 && !state->prefixed) {
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

	if (state->next_insn_page_shift_valid) {
		if (!state->insn_page_shift_valid) {
			fprintf(stderr, "Warning: insn page size becomes valid\n");
			state->insn_page_shift_valid = true;
		}
		state->insn_page_shift = state->next_insn_page_shift;
	}

	if (state->insn_page_shift_valid) {
		record->insn_page_shift_valid = true;
		record->insn_page_shift = state->insn_page_shift;
	}

	if (state->insn_rpn_valid) {
		uint8_t pshift = 16;
		uint64_t ra;

		if (state->insn_page_shift_valid)
			pshift = state->insn_page_shift;

		ra = ((uint64_t)state->insn_rpn << pshift);
		ra |= record->insn_addr & ((1UL << pshift) - 1);

		record->insn_ra_valid = true;
		record->insn_ra = ra;
	}

	record->insn = GET32(state);

	if (state->prefixed)
		state->suffix = record->insn;

	state->prefixed = ((record->insn >> 26) == 1);

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

	if (flags & QTRACE_NODE_PRESENT) {
		record->node_valid = true;
		record->node = GET8(state);
	}

	if (flags & QTRACE_TERMINATION_PRESENT) {
		record->branch = true;

		record->term_node = GET8(state);
		record->term_code = GET8(state);

		if ((record->term_code == QTRACE_EXCEEDED_MAX_INST_DEPTH) ||
		    (record->term_code == QTRACE_EXCEEDED_MAX_BRANCH_DEPTH)) {
			record->conditional_branch = true;
		} else if (record->term_code == QTRACE_UNCONDITIONAL_BRANCH) {
			record->conditional_branch = false;
		} else if (record->term_code == QTRACE_EXCEPTION) {
			record->conditional_branch = false;
		} else {
			printf("Inconsistent branch\n");
			goto err;
		}
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
		state->radix_nr_data_ptes = get_radix_data_ptes(flags3);

		if (parse_radix(state, state->radix_nr_data_ptes, state->radix_data_ptes) == false)
			goto err;
	}

	if (flags & QTRACE_DATA_RPN_PRESENT) {
		state->data_rpn_valid = true;
		state->data_rpn = GET32(state);
	} else {
		state->data_rpn_valid = false;
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
		/*
		 * Some qtwriter/chtm qtraces don't get unconditional branches
		 * right.
		 */
		if (is_unconditional_branch(record->insn))
			record->conditional_branch = false;
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
		state->radix_nr_insn_ptes = get_radix_insn_ptes(flags3);

		if (parse_radix(state, state->radix_nr_insn_ptes, state->radix_insn_ptes) == false)
			goto err;
	}

	if (flags & QTRACE_IAR_RPN_PRESENT) {
		state->next_insn_rpn_valid = true;
		state->next_insn_rpn = GET32(state);
	} else {
		state->next_insn_rpn_valid = false;
	}


	if (flags & QTRACE_REGISTER_TRACE_PRESENT) {
		if (!do_parse_regs(state, &record->regs))
			goto err;
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
		uint8_t insn_page_shift = GET8(state);
		state->next_insn_page_shift_valid = true;
		state->next_insn_page_shift = insn_page_shift;
	}

	if (flags2 & QTRACE_IAR_PAGE_SIZE_PRESENT) {
		state->next_insn_page_shift_valid = true;
		state->next_insn_page_shift = GET8(state);
	} else {
		state->next_insn_page_shift_valid = false;
	}

	if (flags2 & QTRACE_DATA_PAGE_SIZE_PRESENT) {
		record->data_page_shift_valid = true;
		record->data_page_shift = GET8(state);
	}

	if (state->data_rpn_valid) {
		uint8_t pshift = 16;
		uint64_t ea = 0;
		uint64_t ra;

		if (record->data_page_shift_valid)
			pshift = record->data_page_shift;

		if (record->data_addr_valid)
			ea = record->data_addr;

		ra = ((uint64_t)state->data_rpn << pshift);
		ra |= ea & ((1UL << pshift) - 1);

		record->data_ra_valid = true;
		record->data_ra = ra;
	}

	if (flags2 & QTRACE_INSTRUCTION_GPAGE_SIZE_PRESENT)
		SKIP(state, 1);

	if (flags2 & QTRACE_DATA_GPAGE_SIZE_PRESENT)
		SKIP(state, 1);

	if (record->branch && (state->flags & QTREADER_FLAGS_BRANCH))
		annotate_branch(record);

	if (state->flags & QTREADER_FLAGS_TLBIE) {
		if (!annotate_tlbie(state, record))
			goto err;
	}

	return true;

err:
	return false;
}

/*
 * Looking at parse_record the max size of a qt entry should be 33151 bytes,
 * but round up to a bigger number in case I missed some.
 */
#define MAX_RECORD_LENGTH 34000
/* 5MB seemed like a good size */
#define BUF_SIZE (5 * 1024 * 1024)

/*
 * Reads from the archive to fill the buffer.
 * This will fill as much of the buffer as possible
 * from the archive.
 */
static ssize_t read_from_archive(struct qtreader_state *state) {
    ssize_t size;

    /*
     * read from archive.
     * we fill from state->buf_wrt to the end of the buffer.
     * the archive lib will fill as much of that space as it can
     * given the size of the current block.
     * */
    size = archive_read_data(state->archive, state->buf_wrt, BUF_SIZE - (state->buf_wrt - state->mem));

    /* if no data is read, return an error */
    if (size < 0) {
        fprintf(stderr, "Couldn't read data from archive. %zi\n", size);
        return false;
    }
    /*printf("Read %zi from archive.\n", size);*/

    /* increment buf_wrt to account for the number of bytes filled */
    state->buf_wrt += size;

    return size;
}

/*
 * Fills state's buffer with data from the archive.
 * Returns true if there is valid data in the buffer after filling.
 * Otherwise false.
 * So it should return false only after the whole archive is read
 * and the buffer is emptied or an error has occurred.
 */
static bool fill_from_archive(struct qtreader_state *state) {
    uintptr_t buf_end;
    size_t buf_len;

    buf_end = (uintptr_t)state->mem + BUF_SIZE;
    buf_len = (uintptr_t)(state->buf_wrt - state->ptr);
    /* printf("%p %p %zu\n", state->buf_wrt, state->ptr, buf_len); */

    /*
     *         /-- state->mem
     *         |     /-- state->ptr
     *         |     |      /-- state->buf_wrt
     *         |     |      |        /-- buf_end
     *         v     v      v        v
     * Buffer: +---------------------+
     *
     * Valid data is from [state->ptr, state->buf_wrt)
     */


    if (state->archive_end && buf_len == 0) {
        /* buffer has no data and end of archive */
        return false;
    }
    /*
     * check to see if read is necessary.
     * we want to make sure the valid data in the buffer contains
     * at least one valid record.
     * we do that by ensuring the valid segment is at least the size of
     * the largest possible record.
     */
    else if (buf_len < MAX_RECORD_LENGTH) {
        /* printf("Shifting: %p %p %lu %lu\n", state->mem, state->ptr, (uintptr_t)(state->buf_wrt - state->ptr), buf_end - (uintptr_t)state->buf_wrt); */

        /* move the data to align the ptr and mem. */
        memmove(state->mem, state->ptr, buf_len);
        state->ptr = state->mem;
        state->buf_wrt = (void *)((uintptr_t)state->ptr + buf_len);

    } else {
        /* read isn't necessary, so just return -- buffer has valid data */
        return true;
    }


    /* fill buffer from archive */

    /*
     * read from archive and fill the buffer until
     *   + there isn't enough room for another record
     *   + and the archive is not done
     */
    while (!state->archive_end
            && buf_end - (uintptr_t)state->buf_wrt + 1 > MAX_RECORD_LENGTH) {
        ssize_t bytes_read;

        /* read from archive */
        bytes_read = read_from_archive(state);

        /* if bytes read, then read again until the while condition is met */

        /* if no bytes read, then need to read next header */
        if (bytes_read == 0) {
            struct archive_entry *ae;
            int r;

            r = archive_read_next_header(state->archive, &ae);
            switch(r) {
                case ARCHIVE_OK:
                    /* no need to do anything, can continue reading */
                    /*
                    printf("Archive state: ARCHIVE_OK\n");
                    ssize_t bytes_left = archive_entry_size(ae);
                    printf("Archive entry size: %zu\n", bytes_left);
                    */
                    break;

                case ARCHIVE_EOF:
                    /* end of file; mark and return true as nothing left */
                    /* printf("Archive state: ARCHIVE_EOF\n"); */
                    state->archive_end = true;
                    return true;

                default:
                    /* error or unsupported */
                    fprintf(stderr, "Archive header error: %d\n", r);
                    return false;
            }
        }
    }

    /* success */
    return true;
}

bool qtreader_next_record_compressed(struct qtreader_state *state, struct qtrace_record *record) {
    bool fill_result, record_result = false;

    /* fill buffer from archive */
    fill_result = fill_from_archive(state);

    /* if there is valid data in the buffer, read record */
    if (fill_result) {
        record_result = qtreader_next_record(state, record);
    }

    return record_result;
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

bool qtreader_initialize_fd_compressed(struct qtreader_state *state, int fd, unsigned int verbose) {
    int r;
	void *p;
    bool ret;
    struct archive *a;
    struct archive_entry *ae;

    /* allocate memory for compression output buffer */
	p = malloc(BUF_SIZE);
	if (p == NULL) {
		fprintf(stderr, "Failed to allocate memory \n");
		exit(1);
	}

    /* initialize archive support */
	a = archive_read_new();
	archive_read_support_filter_all(a);
	archive_read_support_format_all(a);
	archive_read_support_format_raw(a);

    /* open file */
	r = archive_read_open_fd(a, fd, 16384);
	if (r != ARCHIVE_OK) {
		fprintf(stderr, "File not ok \n");
		return 1;
	}

    /* initialize qtreader */
    /*
     * we can't call qtreader_initialize because that automatically
     * calls qtreader_parse_header and we need to set up the memory buffer
     * first and the init function clears the buf pointers
     */
	memset(state, 0, sizeof(*state));
	state->mem = state->ptr = p;
	state->size = BUF_SIZE;
	state->verbose = verbose;
	state->fd = fd;
	state->next_insn_addr = -1UL;

    /* set state's archive info */
    state->archive = a;
    state->buf_wrt = state->mem;

    /* begin by reading header of archive to prime the read func */
    r = archive_read_next_header(state->archive, &ae);
    if (r != ARCHIVE_OK) {
        fprintf(stderr, "Unable to read initial archive header: %i\n", r);
        return false;
    }

    /* read qtrace header -- so need to fill archive first */
	if (!fill_from_archive(state) || qtreader_parse_header(state) == false) {
		return false;
    }

    /* this is same as in the regular init func */
	if (state->next_insn_addr == -1UL) {
		fprintf(stderr, "Warning: header has no instruction address\n");
    }

	return true;


	return ret;
}
/* undefine these as we are done with archive buffer */
#undef BUF_SIZE
#undef MAX_RECORD_LENGTH

void qtreader_destroy(struct qtreader_state *state)
{
	if (state->fd != -1) {
		munmap(state->mem, state->size);
		close(state->fd);
	}
    if (state->archive != NULL) {
	    archive_read_free(state->archive);
    }
}
