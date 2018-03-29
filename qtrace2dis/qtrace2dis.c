/*
 * Create a disassembly from a qtrace.
 *
 * Copyright (C) 2017 Anton Blanchard <anton@au.ibm.com>, IBM
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "config.h"

#ifdef USE_BFD
#include <bfd.h>
#include <dis-asm.h>
#endif

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

static unsigned int verbose;
static uint32_t version;

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

static uint32_t parse_radix(void *p, unsigned int nr, uint64_t *ptes)
{
	unsigned long i;
	void *q = p;

	for (i = 0; i < nr; i++) {
		ptes[i] = be64_to_cpup(p);
		p += sizeof(uint64_t);
	}

	return p - q;
}

static void print_radix(unsigned int nr, uint64_t *ptes)
{
	unsigned long i;

	for (i = 0; i < nr; i++)
		fprintf(stdout, "0x%016lx ", ptes[i]);
}

/*
 * A header has a zero instruction, a set of record flags, and a set of file
 * header flags. Only a few of the record flags values are populated.
 */
static unsigned long parse_header(void *p, unsigned long *iar)
{
	void *q = p;
	uint32_t insn;
	uint16_t flags = 0, flags2 = 0, flags3 = 0, hdr_flags = 0;

	insn = be32_to_cpup(p);
	p += sizeof(uint32_t);

	if (insn) {
		fprintf(stderr, "Invalid file\n");
		exit(1);
	}

	flags = be16_to_cpup(p);
	p += sizeof(uint16_t);

	if (flags != QTRACE_EXTENDED_FLAGS_PRESENT) {
		fprintf(stderr, "Invalid file\n");
		exit(1);
	}

	flags2 = be16_to_cpup(p);
	p += sizeof(uint16_t);

	if (!(flags2 & QTRACE_FILE_HEADER_PRESENT)) {
		fprintf(stderr, "Invalid file\n");
		exit(1);
	}

	if (flags2 & ~(QTRACE_FILE_HEADER_PRESENT|QTRACE_EXTENDED_FLAGS2_PRESENT)) {
		fprintf(stderr, "Invalid file\n");
		exit(1);
	}

	if (flags2 & QTRACE_EXTENDED_FLAGS2_PRESENT) {
		flags3 = be16_to_cpup(p);
		p += sizeof(uint16_t);
	}

	hdr_flags = be16_to_cpup(p);
	p += sizeof(uint16_t);

	if (verbose >= 2) {
		printf("flags 0x%04x flags2 0x%04x flags3 0x%04x hdr_flags 0x%04x\n",
			flags, flags2, flags3, hdr_flags);
	}

	if (flags3 & UNHANDLED_FLAGS3) {
		printf("Unhandled flags3 0x%04x\n", flags3 & UNHANDLED_FLAGS3);
		exit(1);
	}

	if (hdr_flags & UNHANDLED_HDR_FLAGS) {
		printf("Unhandled file header flags 0x%04x\n", hdr_flags & UNHANDLED_HDR_FLAGS);
		exit(1);
	}

	if (hdr_flags & QTRACE_HDR_MAGIC_NUMBER_PRESENT)
		p += sizeof(uint32_t);

	if (hdr_flags & QTRACE_HDR_VERSION_NUMBER_PRESENT) {
		version = be32_to_cpup(p);
		p += sizeof(uint32_t);
	}

	if (hdr_flags & QTRACE_HDR_IAR_PRESENT) {
		*iar = be64_to_cpup(p);
		p += sizeof(uint64_t);
	}

	if ((hdr_flags & QTRACE_HDR_IAR_RPN_PRESENT) && IS_RADIX(flags2)) {
		unsigned int nr = get_radix_insn_ptes(flags3);
		uint64_t radix_insn_ptes[NR_RADIX_PTES];

		p += parse_radix(p, nr, radix_insn_ptes);
	}

	if (hdr_flags & QTRACE_HDR_IAR_RPN_PRESENT)
		p += sizeof(uint32_t);

	if (hdr_flags & QTRACE_HDR_IAR_PAGE_SIZE_PRESENT)
		p += sizeof(uint8_t);

	if (flags3 & QTRACE_PTCR_PRESENT)
		p += sizeof(uint64_t);

	if (flags3 & QTRACE_LPID_PRESENT)
		p += sizeof(uint64_t);

	if (flags3 & QTRACE_PID_PRESENT)
		p += sizeof(uint32_t);

	if (hdr_flags & QTRACE_HDR_COMMENT_PRESENT) {
		uint16_t len = be16_to_cpup(p);
		p += sizeof(uint16_t);
		p += len;
	}

	return p - q;
}

#ifdef USE_BFD
static asymbol **syms = NULL;
static long symcount;

static int symcmp(const void *p1, const void *p2)
{
	asymbol * const *s1 = p1;
	asymbol * const *s2 = p2;

	return bfd_asymbol_value(*s1) > bfd_asymbol_value(*s2);
}

#define KERNEL_START 0xc000000000000000ULL

static void build_symtab(bfd *abfd)
{
	unsigned int size;
	unsigned long nr_syms;

	if (!(bfd_get_file_flags(abfd) & HAS_SYMS))
		return;

	nr_syms = bfd_read_minisymbols(abfd, 0, (PTR) &syms, &size);

	if (nr_syms == 0)
		nr_syms = bfd_read_minisymbols(abfd, 1, (PTR) &syms, &size);

	symcount = nr_syms;

	/*
	 * Strip any symbols below our kernel entry address. Module CRCs create
	 * absolute symbols that will cause false matches.
	 */
	if (bfd_get_start_address(abfd) == KERNEL_START) {
		unsigned long i;
		void *src, *dest;

		src = dest = syms;
		symcount = 0;

		for (i = 0; i < nr_syms; i++) {
			if (bfd_asymbol_value(syms[i]) >= KERNEL_START) {
				memcpy(dest, src, size);
				dest += size;
				symcount++;
			}

			src += size;
		}
	}

	qsort(syms, symcount, sizeof(asymbol *), symcmp);
}

static asymbol *symfind(symvalue addr)
{
	unsigned long left = 0;
	unsigned long right = symcount;

	if ((symcount < 1) || (addr < bfd_asymbol_value(syms[0]) ||
			addr > bfd_asymbol_value(syms[symcount-1])))
		return NULL;

	while (left + 1 < right) {
		unsigned long middle;
		asymbol *sym;

		middle = (right + left) / 2;
		sym = syms[middle];

		if (bfd_asymbol_value(sym) > addr) {
			right = middle;
		} else if (bfd_asymbol_value(sym) < addr) {
			left = middle;
		} else {
			left = middle;
			break;
		}
	}

	return syms[left];
}

static void syminit(char *file, char *target)
{
	bfd *abfd;

	bfd_init();
	abfd = bfd_openr(file, target);
	if (abfd == NULL) {
		printf("Unable to open %s\n", file);
		return;
	}

	if (!bfd_check_format(abfd, bfd_object)) {
		printf("unsupported file type\n");
		exit(1);
	}

	build_symtab(abfd);
}

static void __print_address(bfd_vma vma)
{
	asymbol *sym = symfind(vma);

	if (sym) {
		unsigned long offset = vma - bfd_asymbol_value(sym);
		const char *name = bfd_asymbol_name(sym);

		fprintf(stdout, "%016lx <%s+0x%lx> ", vma, name, offset);
	} else {
		fprintf(stdout, "%016lx ", vma);
	}
}

static void print_address(bfd_vma vma, struct disassemble_info *info)
{
	__print_address(vma);
}

void disasm(unsigned long ea, unsigned int *buf, unsigned long bufsize)
{
	disassemble_info info;
	int i;

	INIT_DISASSEMBLE_INFO(info, stdout, fprintf);

	info.disassembler_options = "power9";
	info.buffer = (bfd_byte *)buf;
	info.buffer_vma = ea;
	info.buffer_length = bufsize;
	info.print_address_func = print_address;

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	info.endian = BFD_ENDIAN_LITTLE;
#else
	info.endian = BFD_ENDIAN_BIG;
#endif
	info.mach = bfd_mach_ppc64;

	info.arch = bfd_arch_powerpc;
	disassemble_init_for_target(&info);

	i = 0;
	while (i < bufsize) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
		i += print_insn_little_powerpc(ea, &info);
#else
		i += print_insn_big_powerpc(ea, &info);
#endif
	}
}
#endif

#ifdef DEBUG
static void dump(unsigned char *p, unsigned long len)
{
	unsigned long i;

	for (i = 0; i < len; i++) {
		printf("%02x ", p[i]);
	}

	printf("\n");
}
#else
static void dump(unsigned char *p, unsigned long len)
{
}
#endif

static unsigned long parse_record(void *p, unsigned long *ea)
{
	uint32_t insn;
	uint16_t flags, flags2 = 0, flags3 = 0;
	uint64_t iar = 0;
	uint64_t iar_rpn;
	uint8_t iar_page_size;
	uint64_t data_address = 0;
	uint32_t data_rpn;
	uint8_t data_page_size;
	uint8_t node = 0;
	uint8_t term_node = 0, term_code = 0;
	void *q;
	unsigned int radix_nr_data_ptes = 0;
	uint64_t radix_insn_ptes[NR_RADIX_PTES];
	unsigned int radix_nr_insn_ptes = 0;
	uint64_t radix_data_ptes[NR_RADIX_PTES];

	q = p;

	dump(p, 128);

	insn = be32_to_cpup(p);
	p += sizeof(uint32_t);

	flags = be16_to_cpup(p);
	p += sizeof(uint16_t);

	if (flags & QTRACE_EXTENDED_FLAGS_PRESENT) {
		flags2 = be16_to_cpup(p);
		p += sizeof(uint16_t);

		if (flags2 & QTRACE_EXTENDED_FLAGS2_PRESENT) {
			flags3 = be16_to_cpup(p);
			p += sizeof(uint16_t);
		}
	}

	if (flags & UNHANDLED_FLAGS) {
		printf("Unhandled flags 0x%04x\n", flags & UNHANDLED_FLAGS);
		exit(1);
	}

	if (flags2 & UNHANDLED_FLAGS2) {
		printf("Unhandled flags2 0x%04x\n", flags2 & UNHANDLED_FLAGS2);
		exit(1);
	}

	if (flags3 & UNHANDLED_FLAGS3) {
		printf("Unhandled flags3 0x%04x\n", flags3 & UNHANDLED_FLAGS3);
		exit(1);
	}

	if (verbose >= 2)
		printf("flags 0x%04x flags2 0x%04x flags3 0x%04x\n",
			flags, flags2, flags3);

	/* This bit is used on its own, no extra storage is allocated */
	if (flags & QTRACE_IAR_CHANGE_PRESENT) {
	}

	if (flags & QTRACE_NODE_PRESENT) {
		node = *(uint8_t *)p;
		p += sizeof(uint8_t);
	}

	if (flags & QTRACE_TERMINATION_PRESENT) {
		term_node = *(uint8_t *)p;
		p += sizeof(uint8_t);
		term_code = *(uint8_t *)p;
		p += sizeof(uint8_t);
	}

	if (flags & QTRACE_PROCESSOR_PRESENT)
		p += sizeof(uint8_t);

	if (flags & QTRACE_DATA_ADDRESS_PRESENT) {
		data_address = be64_to_cpup(p);
		p += sizeof(uint64_t);
	}

	if ((flags & QTRACE_DATA_RPN_PRESENT) && IS_RADIX(flags2)) {
		radix_nr_data_ptes = get_radix_data_ptes(flags3);
		p += parse_radix(p, radix_nr_data_ptes, radix_data_ptes);
	}

	if (flags & QTRACE_DATA_RPN_PRESENT) {
		data_rpn = be32_to_cpup(p);
		p += sizeof(uint32_t);
	}

	if (flags & QTRACE_IAR_PRESENT) {
		iar = be64_to_cpup(p);
		p += sizeof(uint64_t);
	}

	if ((flags & QTRACE_IAR_RPN_PRESENT) && IS_RADIX(flags2)) {
		radix_nr_insn_ptes = get_radix_insn_ptes(flags3);
		p += parse_radix(p, radix_nr_insn_ptes, radix_insn_ptes);
	}

	if (flags & QTRACE_IAR_RPN_PRESENT) {
		iar_rpn = be32_to_cpup(p);
		p += sizeof(uint32_t);
	}

	if (flags & QTRACE_REGISTER_TRACE_PRESENT) {
		uint8_t gprs_in, fprs_in, vmxs_in, vsxs_in = 0, sprs_in;
		uint8_t gprs_out, fprs_out, vmxs_out, vsxs_out = 0, sprs_out;

		gprs_in = *(uint8_t *)p++;
		fprs_in = *(uint8_t *)p++;
		vmxs_in = *(uint8_t *)p++;
		if (version >= 0x7000000)
			vsxs_in = *(uint8_t *)p++;
		sprs_in = *(uint8_t *)p++;

		gprs_out = *(uint8_t *)p++;
		fprs_out = *(uint8_t *)p++;
		vmxs_out = *(uint8_t *)p++;
		if (version >= 0x7000000)
			vsxs_out = *(uint8_t *)p++;
		sprs_out = *(uint8_t *)p++;

		p += gprs_in * (sizeof(uint8_t) + sizeof(uint64_t));
		p += fprs_in * (sizeof(uint8_t) + sizeof(uint64_t));
		p += vmxs_in * (sizeof(uint16_t) + sizeof(uint64_t) * 2);
		p += vsxs_in * (sizeof(uint16_t) + sizeof(uint64_t) * 2);
		p += sprs_in * (sizeof(uint16_t) + sizeof(uint64_t));

		p += gprs_out * (sizeof(uint8_t) + sizeof(uint64_t));
		p += fprs_out * (sizeof(uint8_t) + sizeof(uint64_t));
		p += vmxs_out * (sizeof(uint16_t) + sizeof(uint64_t) * 2);
		p += vsxs_out * (sizeof(uint16_t) + sizeof(uint64_t) * 2);
		p += sprs_out * (sizeof(uint16_t) + sizeof(uint64_t));
	}

	if (flags2 & QTRACE_SEQUENTIAL_INSTRUCTION_RPN_PRESENT) {
		p += sizeof(uint32_t);
	}

	if (flags2 & QTRACE_TRACE_ERROR_CODE_PRESENT) {
		p += sizeof(uint8_t);
	}

	if (flags2 & QTRACE_SEQUENTIAL_INSTRUCTION_PAGE_SIZE_PRESENT) {
		p += 1;
	}

	if (flags2 & QTRACE_IAR_PAGE_SIZE_PRESENT) {
		iar_page_size = *(uint8_t *)p;
		p += 1;
	}

	if (flags2 & QTRACE_DATA_PAGE_SIZE_PRESENT) {
		data_page_size = *(uint8_t *)p;
		p += 1;
	}

#ifdef USE_BFD
	__print_address(*ea);
	disasm(*ea, &insn, sizeof(insn));
#else
	fprintf(stdout, "0x%016lx\t0x%x\n", *ea, insn);
#endif

	if (verbose) {
		if (flags & (QTRACE_DATA_ADDRESS_PRESENT |
				QTRACE_DATA_RPN_PRESENT |
				QTRACE_DATA_PAGE_SIZE_PRESENT |
				QTRACE_IAR_RPN_PRESENT |
				QTRACE_IAR_PAGE_SIZE_PRESENT |
				QTRACE_NODE_PRESENT |
				QTRACE_TERMINATION_PRESENT))
			fprintf(stdout, "\t #");

		if (flags & QTRACE_DATA_ADDRESS_PRESENT)
			fprintf(stdout, " 0x%016lx", data_address);

		if (flags & QTRACE_DATA_RPN_PRESENT)
			fprintf(stdout, " DATA RPN 0x%08x", data_rpn);

		if ((flags & QTRACE_DATA_RPN_PRESENT) && IS_RADIX(flags2)) {
			fprintf(stdout, " DATA RADIX ");
			print_radix(radix_nr_data_ptes, radix_data_ptes);
		}

		if (flags2 & QTRACE_DATA_PAGE_SIZE_PRESENT)
			fprintf(stdout, " DATA PAGE SIZE %d", data_page_size);

		if (flags & QTRACE_IAR_RPN_PRESENT)
			fprintf(stdout, " INSN RPN 0x%08lx", iar_rpn);

		if ((flags & QTRACE_IAR_RPN_PRESENT) && IS_RADIX(flags2)) {
			fprintf(stdout, " INSN RADIX ");
			print_radix(radix_nr_insn_ptes, radix_insn_ptes);
		}

		if (flags2 & QTRACE_IAR_PAGE_SIZE_PRESENT)
			fprintf(stdout, " INSN PAGE SIZE %d", iar_page_size);

		if (flags & QTRACE_NODE_PRESENT)
			fprintf(stdout, " NODE 0x%02x", node);

		if (flags & QTRACE_TERMINATION_PRESENT)
			fprintf(stdout, " TERM NODE 0x%02x TERM CODE 0x%02x", term_node, term_code);
	}

	fprintf(stdout, "\n");

	if (flags & QTRACE_IAR_PRESENT)
		*ea = iar;
	else
		*ea += sizeof(uint32_t);

	return p - q;
}

static void usage(void)
{
	fprintf(stderr, "Usage: qtrace2dis [OPTION]... [FILE]\n\n");
	fprintf(stderr, "\t-e <file>\t\tresolve symbols using this file\n");
	fprintf(stderr, "\t-v\t\t\tprint verbose info\n");
}

int main(int argc, char *argv[])
{
	int fd;
	struct stat buf;
	void *p;
	unsigned long size, x;
	unsigned long ea = 0;

	while (1) {
		signed char c = getopt(argc, argv, "e:v");
		if (c < 0)
			break;

		switch (c) {
#ifdef USE_BFD
		case 'e':
			syminit(optarg, "elf64-powerpc");
			break;
#endif

		case 'v':
			verbose++;
			break;

		default:
			usage();
			exit(1);
		}
	}

	if ((argc - optind) != 1) {
		usage();
		exit(1);
	}

	fd = open(argv[optind], O_RDONLY);
	if (fd < 0) {
		perror("open");
		exit(1);
	}

	if (fstat(fd, &buf)) {
		perror("fstat");
		exit(1);
	}
	size = buf.st_size;

	p = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
	if (p == MAP_FAILED) {
		perror("mmap");
		exit(1);
	}

	x = parse_header(p, &ea);
	size -= x;
	p += x;

	while (size) {
		/*
		 * We sometimes see two file headers at the start of a mambo trace, or
		 * a header in the middle of a trace. Not sure if this is a bug, but
		 * skip over them regardless. We identify them by a null instruction.
		 */
		if (!be32_to_cpup(p)) {
			x = parse_header(p, &ea);
			size -= x;
			p += x;
		}

		x = parse_record(p, &ea);
		p += x;
		size -= x;
	}

	return 0;
}
