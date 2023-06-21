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
#include <stdbool.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <assert.h>
#include <archive.h>

#include "config.h"
#include "qtreader.h"

#ifdef HAVE_BFD_H
#include <bfd.h>
#include <dis-asm.h>
#endif

#include <qtrace.h>
#include <ppcstats.h>
#include <bb.h>

/*
 * Looking at parse_record the max size of a qt entry should be 33151 bytes,
 * but round up to a bigger number in case I missed some.
 */
#define MAX_RECORD_LENGTH 34000
/* 5MB seemed like a good size */
#define BUF_SIZE (5 * 1024 * 1024)

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define be16_to_cpup(A)	__builtin_bswap16(*(uint16_t *)(A))
#define be32_to_cpup(A)	__builtin_bswap32(*(uint32_t *)(A))
#define be64_to_cpup(A)	__builtin_bswap64(*(uint64_t *)(A))
#else
#define be16_to_cpup(A)	(*(uint16_t *)A)
#define be32_to_cpup(A)	(*(uint32_t *)A)
#define be64_to_cpup(A)	(*(uint64_t *)A)
#endif

#ifdef HAVE_BFD_H
static int qtbuild;
#endif

static unsigned int verbose;
static int dump_nr;
static bool show_stats_only;
static bool show_imix_only;
static bool basic_block_only;

static void print_radix(unsigned int nr, uint64_t *ptes)
{
	unsigned long i;

	for (i = 0; i < nr; i++)
		fprintf(stdout, "0x%016lx ", ptes[i]);
}

static bool show_raw_insn;

static void print_raw_insn(uint32_t *insn, unsigned int len)
{
	unsigned int i;

	if (show_raw_insn) {
		uint8_t *p = (uint8_t *)insn;

		fprintf(stdout, "\t");
		for (i = 0; i < len; i++)
			fprintf(stdout, "%02x ", p[i]);
	}
}

#ifdef HAVE_BFD_H
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

	nr_syms = bfd_read_minisymbols(abfd, 0, (void*) &syms, &size);

	if (nr_syms == 0)
		nr_syms = bfd_read_minisymbols(abfd, 1, (void*) &syms, &size);

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

#ifdef HAVE_BFD_H
	if (qtbuild) {
		fprintf(stdout, "_dummy_%016lx ", vma);
		return;
	}
#endif

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

static int fprintf_styled(void *, enum disassembler_style, const char* fmt, ...)
{
	va_list args;
	int r;

	va_start(args, fmt);
	r = vprintf(fmt, args);
	va_end(args);

	return r;
}

/*
 * The qtrace format writes the instruction in big endian format, but we
 * converted it to host endian as we read it.  Since we pass the instruction in
 * via memory, it is still in host endian format and as such we pass the
 * host endian to the disassembler.
 */
void disasm(unsigned long ea, uint32_t *buf, unsigned long bufsize)
{
	static bool disassembler_initialized = false;
	static disassembler_ftype disassembler_p;
	static disassemble_info info;
	int i;

	if (!disassembler_initialized) {
#ifdef BFD_NEW_DISASSEMBLER_ARGS
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
		bfd_boolean is_big = false;
#else
		bfd_boolean is_big = true;
#endif

		disassembler_p = disassembler(bfd_arch_powerpc, is_big, bfd_mach_ppc64, NULL);
#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
		disassembler_p = print_insn_little_powerpc;
#else
		disassembler_p = print_insn_big_powerpc;
#endif

		init_disassemble_info(&info, stdout, (fprintf_ftype)fprintf, fprintf_styled);
		info.disassembler_options = "power10";
		info.print_address_func = print_address;
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
		info.endian = BFD_ENDIAN_LITTLE;
#else
		info.endian = BFD_ENDIAN_BIG;
#endif
		info.mach = bfd_mach_ppc64;
		info.arch = bfd_arch_powerpc;
		disassemble_init_for_target(&info);

		disassembler_initialized = true;
	}

	info.buffer = (bfd_byte *)buf;
	info.buffer_vma = ea;
	info.buffer_length = bufsize;

	if (show_stats_only || basic_block_only || show_imix_only)
		goto out;
	if (!disassembler_p) {
		fprintf(stdout, "0x%x", *buf);
	} else {
		i = 0;
		while (i < bufsize)
			i += disassembler_p((unsigned long)ea, &info);
	}

out:
	if (show_stats_only || show_imix_only)
		ppcstats_log_inst(ea, *buf);
	if (basic_block_only)
		bb_ea_log(ea);
}
#endif

static void usage(void)
{
	fprintf(stderr, "Usage: qtdis [OPTION]... [FILE]\n\n");
	fprintf(stderr, "\t-r\t\tShow raw instruction\n");
	fprintf(stderr, "\t-v\t\t\tprint verbose info\n");
#ifdef HAVE_BFD_H
	fprintf(stderr, "\t-e <file>\t\tresolve symbols using this file\n");
	fprintf(stderr, "\t-b\t\t\toutput qtbuild assembly\n");
#endif
	fprintf(stderr, "\t-d <nr>\t\t\tdump with strategy nr\n");
	fprintf(stderr, "\t       \t\t\t1. ifetch, load, store addresses\n");
	fprintf(stderr, "\t-s \t\t\tdump stats\n");
	fprintf(stderr, "\t-i \t\t\tdump instruction mix\n");
	fprintf(stderr, "\t-c \t\t\tbasic block anaylsis\n");
}

void print_qt_record(struct qtreader_state *state, struct qtrace_record *rec,
		     unsigned long ea)
{
	unsigned int buf[2];
	unsigned int buflen = sizeof(unsigned int);

	buf[0] = rec->insn;
	if (state->prefixed) {
		buf[1] = state->suffix;
		buflen = sizeof(unsigned int) * 2;
	}
	switch (dump_nr) {
	case 0:
		break;
	case 1:
		fprintf(stdout, "IFTCH EA:0x%016lx", ea);
		if (state->next_insn_rpn_valid)
			fprintf(stdout, " RA:0x%016lx", (unsigned long)state->next_insn_rpn << 12);
		if (state->next_insn_page_shift_valid)
			fprintf(stdout, " PAGE_SIZE:0x%lx", 1UL << state->next_insn_page_shift);
		fprintf(stdout, "\n");

		if (rec->data_addr_valid) {
			fprintf(stdout, "LDST EA:0x%016lx", rec->data_addr);
			if (state->data_rpn_valid)
				fprintf(stdout, " RA:0x%016lx", (unsigned long)state->data_rpn << 12);
			if (rec->data_page_shift_valid)
				fprintf(stdout, " PAGE_SIZE:0x%lx", 1UL << rec->data_page_shift);
			fprintf(stdout, "\n");
		}
		break;
	default:
		fprintf(stdout, "Unknown dump strategy %d\n", dump_nr);
		exit(1);
	}
	if (dump_nr)
		return;

#ifdef HAVE_BFD_H
	if (qtbuild) {
		static int first = 1;
		static unsigned long last_ea;
		static int i_num = 0;

		if (first) {
			first = 0;
			fprintf(stdout, "#include \"qtb.h\"\n");
			fprintf(stdout, "start_trace\t0x%016lx\n", ea);
		} else {
			if (last_ea + sizeof(uint32_t) != ea)
				fprintf(stdout, "branch_to_abs\t0x%016lx\n", ea);
		}

		last_ea = ea;

		if (i_num % 10 == 0)
			fprintf(stdout, "# instruction number %d\n", i_num);
		i_num++;
		disasm(ea, buf, buflen);
		if (rec->data_addr_valid)
			fprintf(stdout, "\t; ldst 0x%016lx", rec->data_addr);
	} else {
		if (!show_stats_only && !basic_block_only && !show_imix_only) {
			__print_address(ea);
			print_raw_insn(buf, buflen);
			fprintf(stdout, "\t");
		}
		disasm(ea, buf, buflen);
	}
#else
	fprintf(stdout, "%016lx", ea);
	print_raw_insn(buf, buflen);
	if (!state->prefixed) {
		fprintf(stdout, "\t0x%x", rec->insn);
	} else {
		fprintf(stdout, "\t0x%x 0x%x", rec->insn, state->suffix);
	}
#endif
	if (verbose) {
		if (rec->data_addr_valid || state->data_rpn_valid ||
		    state->next_insn_rpn_valid || rec->node_valid ||
		    rec->branch || rec->data_page_shift_valid ||
		    state->next_insn_rpn_valid || state->next_insn_page_shift_valid)
			fprintf(stdout, "\t #");

		if (rec->data_addr_valid)
			fprintf(stdout, " 0x%016lx", rec->data_addr);

		if (state->data_rpn_valid)
			fprintf(stdout, " DATA RPN 0x%08x", state->data_rpn);

		if (state->radix_nr_data_ptes) {
			fprintf(stdout, " DATA RADIX ");
			print_radix(state->radix_nr_data_ptes, state->radix_data_ptes);
		}

		if (rec->data_page_shift_valid)
			fprintf(stdout, " DATA PAGE SIZE %d", rec->data_page_shift);

		if (state->next_insn_rpn_valid)
			fprintf(stdout, " INSN RPN 0x%08x", state->next_insn_rpn);

		// TODO: qtreader does not separate from QTRACE_IAR_RPN_PRESENT
		//if (flags2 & QTRACE_SEQUENTIAL_INSTRUCTION_RPN_PRESENT)
		//	fprintf(stdout, " INSN SEQ RPN 0x%08lx", iar_seq_rpn);

		if (state->next_insn_rpn_valid && state->radix_nr_insn_ptes) {
			fprintf(stdout, " INSN RADIX ");
			print_radix(state->radix_nr_insn_ptes, state->radix_insn_ptes);
		}

		if (state->next_insn_page_shift_valid)
			fprintf(stdout, " INSN PAGE SIZE %d", state->next_insn_page_shift);

		// TODO: qtreader does not separate from QTRACE_IAR_PAGE_SIZE_PRESENT
		//if (flags2 & QTRACE_SEQUENTIAL_INSTRUCTION_PAGE_SIZE_PRESENT)
		//	fprintf(stdout, " INSN SEQ PAGE SIZE %d", iar_seq_page_size);

		if (rec->node_valid)
			fprintf(stdout, " NODE 0x%02x", rec->node);

		if (rec->branch)
			fprintf(stdout, " TERM NODE 0x%02x TERM CODE 0x%02x", rec->term_node, rec->term_code);
	}

	if (!show_stats_only && !basic_block_only && !show_imix_only)
		fprintf(stdout, "\n");

	return;
}

static int read_qt(char *file)
{
	struct qtreader_state state, prev_state;
	struct qtrace_record rec, prev_rec;
	unsigned long ea = 0;
	int fd;

	fd = open(file, O_RDONLY);
	if (fd < 0) {
		perror("open");
		exit(1);
	}

	if (qtreader_initialize_fd(&state, fd, 0) == false) {
		fprintf(stderr, "qtreader_initialize_fd failed\n");
		exit(1);
	}

	ea = state.next_insn_addr;
	while (qtreader_next_record(&state, &rec) == true) {
		if (!state.prefixed) {
			print_qt_record(&state, &rec, ea);
			ea = state.next_insn_addr;
		} else {
			memcpy(&prev_state, &state, sizeof(state));
			memcpy(&prev_rec, &rec, sizeof(rec));
			qtreader_next_record(&state, &rec);
			print_qt_record(&prev_state, &prev_rec, ea);
			ea = state.next_insn_addr;
		}
	}

	return 0;
}

int main(int argc, char *argv[])
{
	show_stats_only = false;
	basic_block_only = false;
	show_imix_only = false;

	while (1) {
		signed char c = getopt(argc, argv, "e:d:rvbsci");
		if (c < 0)
			break;

		switch (c) {
#ifdef HAVE_BFD_H
		case 'e':
			syminit(optarg, "elf64-powerpc");
			break;
		case 'b':
			qtbuild = 1;
			break;
#endif
		case 'd':
			dump_nr = atoi(optarg);
			break;
		case 'r':
			show_raw_insn = true;
			break;

		case 's':
			show_stats_only = true;
			break;

		case 'i':
			show_imix_only = true;
			break;

		case 'c':
			basic_block_only = true;
			break;

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

	if ((show_stats_only || basic_block_only || show_imix_only) &&
	    (verbose || show_raw_insn)) {
		fprintf(stderr, "Dumping stats (-s/-i/-c) can only be used alone\n");
		exit(1);
	}

	if (show_stats_only || show_imix_only){
		uint64_t flags = 0;
		if (show_stats_only)
			flags |= PPCSTATS_STATS;
		if (show_imix_only)
			flags |= PPCSTATS_IMIX;
		ppcstats_init(flags);
	}

	if (basic_block_only)
		bb_init();

	read_qt(argv[optind]);

	if (show_stats_only || show_imix_only)
		ppcstats_print();

	if (basic_block_only)
		bb_dump();

	return 0;
}
