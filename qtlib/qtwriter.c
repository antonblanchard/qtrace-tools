/*
 * Qtrace writer library
 *
 * Copyright (C) 2017 Anton Blanchard <anton@au.ibm.com>, IBM
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "qtrace_record.h"
#include "qtrace.h"
#include "qtwriter.h"
#include "endian-helpers.h"

static int fallocate_or_ftruncate(int fd, size_t size)
{
	if (fallocate(fd, 0, 0, size) == 0)
		return 0;

	if (errno != EOPNOTSUPP)
		return -1;

	if (ftruncate(fd, size) == -1)
		return -1;

	return 0;
}

#define QTWRITER_VERSION 0x7010000

/*
 * This needs to be bigger than the maximum qtrace record size. We also
 * want it to be large enough that we don't continually extend the file
 * with fallocate/mremap.
 */
#define BUFFER	(128*1024)

bool qtwriter_open(struct qtwriter_state *state, char *filename,
		   uint32_t magic)
{
	void *p;

	memset(state, 0, sizeof(*state));

	state->magic = magic;
	state->version = QTWRITER_VERSION;

	state->fd = open(filename, O_RDWR|O_CREAT|O_TRUNC, 0644);
	if (state->fd == -1) {
		perror("open");
		return false;
	}

	state->size = BUFFER;

	if (fallocate_or_ftruncate(state->fd, state->size) == -1) {
		perror("fallocate/ftruncate");
		return false;
	}

	p = mmap(NULL, state->size, PROT_READ|PROT_WRITE, MAP_SHARED,
		 state->fd, 0);

	if (p == MAP_FAILED) {
		perror("mmap");
		return false;
	}

	state->mem = p;
	state->ptr = state->mem;

	return true;
}

static inline void put8(struct qtwriter_state *state, uint8_t val)
{
	typeof(val) *p = state->ptr;
	*p = val;
	state->ptr += sizeof(*p);
}

static inline void put16(struct qtwriter_state *state, uint16_t val)
{
	typeof(val) *p = state->ptr;
	*p = cpu_to_be16(val);
	state->ptr += sizeof(*p);
}

static inline void put32(struct qtwriter_state *state, uint32_t val)
{
	typeof(val) *p = state->ptr;
	*p = cpu_to_be32(val);
	state->ptr += sizeof(*p);
}

static inline void put64(struct qtwriter_state *state, uint64_t val)
{
	typeof(val) *p = state->ptr;
	*p = cpu_to_be64(val);
	state->ptr += sizeof(*p);
}

/*
 * The header contains the address of the first instruction, so we can't
 * write it until we get the first trace entry.
 */
static bool qtwriter_write_header(struct qtwriter_state *state,
				  struct qtrace_record *record)
{
	uint64_t hdr_flags;

	/* Header is identified by a zero instruction */
	put32(state, 0);

	put16(state, QTRACE_EXTENDED_FLAGS_PRESENT);

	put16(state, QTRACE_FILE_HEADER_PRESENT);

	hdr_flags = QTRACE_HDR_IAR_PRESENT;

	if (record->insn_ra_valid)
		hdr_flags |= QTRACE_HDR_IAR_RPN_PRESENT;

	if (record->insn_page_size_valid)
		hdr_flags |= QTRACE_HDR_IAR_PAGE_SIZE_PRESENT;

	if (state->version)
		hdr_flags |= QTRACE_HDR_VERSION_NUMBER_PRESENT;

	if (state->magic)
		hdr_flags |= QTRACE_HDR_MAGIC_NUMBER_PRESENT;

	put16(state, hdr_flags);

	if (state->magic)
		put32(state, state->magic);

	if (state->version)
		put32(state, state->version);

	put64(state, record->insn_addr);

	if (record->insn_ra_valid) {
		uint8_t pshift = 16;

		if (record->insn_page_size_valid)
			pshift = record->insn_page_size;

		put32(state, record->insn_ra >> pshift);
	}

	if (record->insn_page_size_valid)
		put8(state, record->insn_page_size);

	return true;
}

bool qtwriter_write_record(struct qtwriter_state *state,
			   struct qtrace_record *record)
{
	uint16_t flags;
	uint16_t flags2;
	bool iar_change = false;
	bool is_branch = false;

	/* Do we need to allocate more space? */
	if ((state->ptr + BUFFER) > (state->mem + state->size)) {
		void *p;
		size_t offset;

		if (fallocate_or_ftruncate(state->fd, state->size + BUFFER) == -1) {
			perror("fallocate/ftruncate");
			return false;
		}

		p = mremap(state->mem, state->size, state->size + BUFFER,
			   MREMAP_MAYMOVE);
		if (p == MAP_FAILED) {
			perror("mmap");
			return false;
		}

		state->size += BUFFER;
		offset = state->ptr - state->mem;

		state->mem = p;

		/* adjust ->ptr, mremap may have returned a new address */
		state->ptr = state->mem + offset;
	} 

	if (state->header_written == false) {
		qtwriter_write_header(state, record);
		state->header_written = true;

		memcpy(&state->prev_record, record, sizeof(*record));

		return true;
	}

	flags = QTRACE_EXTENDED_FLAGS_PRESENT;
	flags2 = 0;

	if (state->prev_record.data_addr_valid)
		flags |= QTRACE_DATA_ADDRESS_PRESENT;

	if (state->prev_record.data_ra_valid)
		flags |= QTRACE_DATA_RPN_PRESENT;

	if (state->prev_record.data_page_size_valid)
		flags2 |= QTRACE_DATA_PAGE_SIZE_PRESENT;

	if (record->insn_ra_valid)
		flags |= QTRACE_IAR_RPN_PRESENT;

	if (record->insn_page_size_valid)
		flags2 |= QTRACE_IAR_PAGE_SIZE_PRESENT;

	/* Some sort of branch */
	if (state->prev_record.branch == true ||
	    record->insn_addr != (state->prev_record.insn_addr + 4)) {

		is_branch = true;

		flags |= QTRACE_NODE_PRESENT | QTRACE_TERMINATION_PRESENT;

		if ((record->insn_addr != (state->prev_record.insn_addr + 4)))
			iar_change = true;

		if (iar_change)
			flags |= (QTRACE_IAR_CHANGE_PRESENT | QTRACE_IAR_PRESENT);
	}

	put32(state, state->prev_record.insn);

	put16(state, flags);

	put16(state, flags2);

	if (is_branch) {
		uint8_t termination_code = 0;

		/* node */
		put8(state, 0);

		/* termination node */
		put8(state, 0);

		/* termination code */
		if (state->prev_record.branch) {
			if (state->prev_record.conditional_branch == true)
				//termination_code = QTRACE_EXCEEDED_MAX_INST_DEPTH;
				termination_code = QTRACE_EXCEEDED_MAX_BRANCH_DEPTH;
			else
				termination_code = QTRACE_UNCONDITIONAL_BRANCH;
		}

		put8(state, termination_code);
	}

	if (state->prev_record.data_addr_valid)
		put64(state, state->prev_record.data_addr);

	if (state->prev_record.data_ra_valid) {
		uint8_t pshift = 16;

		if (state->prev_record.data_page_size_valid)
			pshift = state->prev_record.data_page_size;

		put32(state, state->prev_record.data_ra >> pshift);
	}

	if (iar_change)
		put64(state, record->insn_addr);

	if (record->insn_ra_valid) {
		uint8_t pshift = 16;

		if (record->insn_page_size_valid)
			pshift = record->insn_page_size;

		put32(state, record->insn_ra >> pshift);
	}

	if (record->insn_page_size_valid)
		put8(state, record->insn_page_size);

	if (state->prev_record.data_page_size_valid)
		put8(state, state->prev_record.data_page_size);

	memcpy(&state->prev_record, record, sizeof(*record));

	return true;
}

#if 0
void qtwriter_write_record_simple(struct qtwriter_state *state, uint32_t insn,
				  unsigned long insn_addr)
{
	struct qtrace_record record;

	memset(&record, 0, sizeof(record));

	record.insn = insn;
	record.insn_addr = insn_addr;

	/* what about branches? */

	qtwriter_write_record(state, &record);
}

void qtwriter_write_storage_record_simple(struct qtwriter_state *state,
					  uint32_t insn, unsigned long insn_addr,
					  unsigned long storage_addr,
					  unsigned long storage_size)
{
	struct qtrace_record record;

	memset(&record, 0, sizeof(record));

	record.insn = insn;
	record.insn_addr = insn_addr;

	record.data_addr_valid = true;
	record.data_addr = storage_addr;

	/* what about branches? */

	qtwriter_write_record(state, &record);
}
#endif

void qtwriter_close(struct qtwriter_state *state)
{
	struct qtrace_record record;

	/* Flush the final instruction */
	memset(&record, 0, sizeof(record));
	record.insn_addr = state->prev_record.insn_addr + 4;
	qtwriter_write_record(state, &record);

	munmap(state->mem, state->size);

	/* truncate file to actual size */
	if (ftruncate(state->fd, state->ptr - state->mem)) {
		fprintf(stderr, "ftruncate\n");
	}

	close(state->fd);
}
