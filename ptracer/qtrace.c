/*
 * Copyright (C) 2017 Anton Blanchard <anton@au.ibm.com>, IBM
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "branch.h"

/* File header flags */
#define QTRACE_HDR_VERSION_NUMBER_PRESENT		0x4000
#define QTRACE_HDR_IAR_PRESENT				0x2000

/* Primary flags */
#define QTRACE_IAR_CHANGE_PRESENT			0x8000
#define QTRACE_NODE_PRESENT				0x4000
#define QTRACE_TERMINATION_PRESENT			0x2000
#define QTRACE_DATA_ADDRESS_PRESENT			0x0800
#define QTRACE_IAR_PRESENT				0x0040
#define QTRACE_EXTENDED_FLAGS_PRESENT			0x0001

/* First extended flags */
#define QTRACE_FILE_HEADER_PRESENT			0x0002

/* Termination codes */
#define QTRACE_EXCEEDED_MAX_INST_DEPTH			0x40
#define QTRACE_UNCONDITIONAL_BRANCH			0x08

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define be16_to_cpup(A)	__builtin_bswap16(*(uint16_t *)(A))
#define be32_to_cpup(A)	__builtin_bswap32(*(uint32_t *)(A))
#define be64_to_cpup(A)	__builtin_bswap64(*(uint64_t *)(A))
#define cpu_to_be16(A) __builtin_bswap16(A)
#define cpu_to_be32(A) __builtin_bswap32(A)
#define cpu_to_be64(A) __builtin_bswap64(A)
#else
#define be16_to_cpup(A)	(*(uint16_t *)A)
#define be32_to_cpup(A)	(*(uint32_t *)A)
#define be64_to_cpup(A)	(*(uint64_t *)A)
#define cpu_to_be16(A) (A)
#define cpu_to_be32(A) (A)
#define cpu_to_be64(A) (A)
#endif

static int fd;

void qtrace_open(char *filename)
{
	fd = open(filename, O_WRONLY|O_CREAT|O_TRUNC, 0644);
	if (fd == -1) {
		perror("open");
		exit(1);
	}
}

static bool handle_branch(uint32_t insn, unsigned long insn_addr);

void qtrace_close(void)
{
	/* If the previous instruction was a branch, write it out. */
	handle_branch(0, 0);
	close(fd);
}

/*
 * The header contains the address of the first instruction, so we can't
 * write it until we get the first trace entry.
 */
static bool header_written = false;
static void write_header(unsigned long addr)
{
	uint16_t flags;
	uint32_t t32;
	uint64_t t64;

	/* Header is identified by a zero instruction */
	t32 = 0;
	assert(write(fd, &t32, sizeof(t32)) == sizeof(t32));

	flags = cpu_to_be16(QTRACE_EXTENDED_FLAGS_PRESENT);
	assert(write(fd, &flags, sizeof(flags)) == sizeof(flags));

	flags = cpu_to_be16(QTRACE_FILE_HEADER_PRESENT);
	assert(write(fd, &flags, sizeof(flags)) == sizeof(flags));

	flags = cpu_to_be16(QTRACE_HDR_VERSION_NUMBER_PRESENT | QTRACE_HDR_IAR_PRESENT);
	assert(write(fd, &flags, sizeof(flags)) == sizeof(flags));

	t32 = cpu_to_be32(0); /* XXX FIXME */
	assert(write(fd, &t32, sizeof(t32)) == sizeof(t32));

	t64 = cpu_to_be64(addr);
	assert(write(fd, &t64, sizeof(t64)) == sizeof(t64));
}

static bool handle_branch(uint32_t insn, unsigned long insn_addr)
{
	static uint32_t prev_branch_insn = 0;
	static unsigned long prev_branch_addr = 0;

	if (prev_branch_insn) {
		uint8_t t8;
		uint16_t flags = QTRACE_NODE_PRESENT | QTRACE_TERMINATION_PRESENT;
		uint32_t t32;
		uint64_t t64;
		bool iar_change = false;

		/*
		 * A zero instruction is used to write out any previous branch
		 * before closing the qtrace file.
		 */
		if (insn && ((prev_branch_addr + 4) != insn_addr))
			iar_change = true;

		if (iar_change)
			flags |= (QTRACE_IAR_CHANGE_PRESENT | QTRACE_IAR_PRESENT);

		t32 = cpu_to_be32(prev_branch_insn);
		assert(write(fd, &t32, sizeof(t32)) == sizeof(t32));

		flags = cpu_to_be16(flags);
		assert(write(fd, &flags, sizeof(flags)) == sizeof(flags));

		/* node */
		t8 = 0;
		assert(write(fd, &t8, sizeof(t8)) == sizeof(t8));

		/* termination node */
		t8 = 0;
		assert(write(fd, &t8, sizeof(t8)) == sizeof(t8));

		/* termination code */
		t8 = 0;
		if (is_conditional_branch(prev_branch_insn))
			t8 = QTRACE_EXCEEDED_MAX_INST_DEPTH;

		if (is_unconditional_branch(prev_branch_insn))
			t8 = QTRACE_UNCONDITIONAL_BRANCH;

		assert(write(fd, &t8, sizeof(t8)) == sizeof(t8));

		if (iar_change) {
			t64 = cpu_to_be64(insn_addr);
			assert(write(fd, &t64, sizeof(t64)) == sizeof(t64));
		}
	}

	if (is_branch(insn)) {
		prev_branch_insn = insn;
		prev_branch_addr = insn_addr;
		return true;
	} else {
		prev_branch_insn = 0;
		return false;
	}
}

void qtrace_add_record(uint32_t insn, unsigned long insn_addr)
{
	uint16_t flags;
	uint32_t t32;

	if (!header_written) {
		header_written = true;
		write_header(insn_addr);
	}

	if (handle_branch(insn, insn_addr))
		return;

	t32 = cpu_to_be32(insn);
	assert(write(fd, &t32, sizeof(t32)) == sizeof(t32));

	flags = 0;
	assert(write(fd, &flags, sizeof(flags)) == sizeof(flags));
}

void qtrace_add_storage_record(uint32_t insn, unsigned long insn_addr, unsigned long storage_addr, unsigned long storage_size)
{
	uint16_t flags;
	uint32_t t32;
	uint64_t t64;

	if (!header_written) {
		header_written = true;
		write_header(insn_addr);
	}

	handle_branch(insn, insn_addr);

	t32 = cpu_to_be32(insn);
	assert(write(fd, &t32, sizeof(t32)) == sizeof(t32));

	flags = cpu_to_be16(QTRACE_DATA_ADDRESS_PRESENT);
	assert(write(fd, &flags, sizeof(flags)) == sizeof(flags));

	t64 = cpu_to_be64(storage_addr);
	assert(write(fd, &t64, sizeof(t64)) == sizeof(t64));
}
