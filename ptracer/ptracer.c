/*
 * Copyright (C) 2017 Anton Blanchard <anton@au.ibm.com>, IBM
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include <bfd.h>
#include <dis-asm.h>

#include "qtrace.h"
#include "ppc_storage.h"

#if 1
#define DBG(A...)
#else
#define DBG(A...) printf(A)
#endif

#define LWARX_MASK 0xfc0007fe
#define LBARX_INSTRUCTION 0x7c000068
#define LHARX_INSTRUCTION 0x7c0000e8
#define LWARX_INSTRUCTION 0x7c000028
#define LDARX_INSTRUCTION 0x7c0000A8
#define LQARX_INSTRUCTION 0x7c000228

#define STWCX_MASK 0xfc0007ff
#define STBCX_INSTRUCTION 0x7c00056d
#define STHCX_INSTRUCTION 0x7c0005ad
#define STWCX_INSTRUCTION 0x7c00012d
#define STDCX_INSTRUCTION 0x7c0001ad
#define STQCX_INSTRUCTION 0x7c00016d

#define BRANCH_MASK 0xfc000000
#define BC_INSN 0x40000000

#define TRAP_INSN 0x7d821008UL

static uint32_t *read_pc(pid_t pid)
{
#ifdef __powerpc64__
	unsigned long pc;

	pc = ptrace(PTRACE_PEEKUSER, pid, sizeof(unsigned long) * PT_NIP);

	if (pc == -1) {
		perror("read_pc: ptrace");
		exit(1);
	}

	return (uint32_t *)pc;
#else
#error Implement read_pc
#endif
}

static uint32_t read_insn(pid_t pid, uint32_t *pc)
{
#ifdef __powerpc64__
	int insn;
	unsigned long data;

	data = ptrace(PTRACE_PEEKDATA, pid, pc, NULL);
	if (data == -1) {
		perror("read_insn: ptrace");
		exit(1);
	}

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	insn = data & 0xffffffffUL;
#else
	insn = data >> 32;
#endif

	DBG("read addr %p val %x\n", pc, insn);

	return insn;
#else
#error Implement read_insn
#endif
}

static void write_insn(pid_t pid, uint32_t *pc, uint32_t insn)
{
	DBG("write_insn pc %p insn %x\n", pc, insn);
#ifdef __powerpc64__
	unsigned long data;

	data = ptrace(PTRACE_PEEKDATA, pid, pc, NULL);
	if (data == -1) {
		perror("write_insn: ptrace");
		exit(1);
	}

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	data = (data & 0xffffffff00000000UL) | insn;
#else
	data = (data & 0xffffffffUL) | (unsigned long)insn << 32;
#endif

	if (ptrace(PTRACE_POKEDATA, pid, pc, data) == -1) {
		perror("write_insn: ptrace");
		exit(1);
	}
#else
#error Implement write_insn
#endif
}

static inline bool is_larx(uint32_t insn)
{
	uint32_t insn_base = insn & LWARX_MASK;

	if ((insn_base == LBARX_INSTRUCTION) ||
	    (insn_base == LHARX_INSTRUCTION) ||
	    (insn_base == LWARX_INSTRUCTION) ||
	    (insn_base == LDARX_INSTRUCTION) ||
	    (insn_base == LQARX_INSTRUCTION))
		return true;

	return false;
}

static inline bool is_stcx(uint32_t insn)
{
	uint32_t insn_base = insn & STWCX_MASK;

	if ((insn_base == STBCX_INSTRUCTION) ||
	    (insn_base == STHCX_INSTRUCTION) ||
	    (insn_base == STWCX_INSTRUCTION) ||
	    (insn_base == STDCX_INSTRUCTION) ||
	    (insn_base == STQCX_INSTRUCTION))
		return true;

	return false;
}

static inline bool is_branch(uint32_t insn)
{
	uint32_t insn_base = insn & BRANCH_MASK;

	if (insn_base == BC_INSN)
		return true;

	return false;
}

static inline uint32_t *branch_target(uint32_t insn, uint32_t *addr)
{
	unsigned long target;
	int immediate = ((insn & 0xfffc) ^ 0x8000) - 0x8000;
	int absolute = insn & 2;

	if (absolute)
		target = immediate;
	else
		target = ((unsigned long)addr) + immediate;

	return (uint32_t *)target;
}

/* This includes the breakpoint at the termination of the larx/stcx sequence */
#define MAX_BREAKPOINTS		8
#define MAX_LARX_STCX_GAP	32

struct breakpoint {
	uint32_t *addr;
	uint32_t insn;
};

static bool insert_one_breakpoint(pid_t pid, struct breakpoint *breakpoint)
{
	uint32_t val;

	val = read_insn(pid, breakpoint->addr);
	breakpoint->insn = val;
	write_insn(pid, breakpoint->addr, TRAP_INSN);

	return true;
}

static bool remove_one_breakpoint(pid_t pid, struct breakpoint *breakpoint)
{
	uint32_t val;

	val = read_insn(pid, breakpoint->addr);

	if (val != TRAP_INSN)
		return false;

	write_insn(pid, breakpoint->addr, breakpoint->insn);

	return true;
}

static bool insert_breakpoints(pid_t pid, struct breakpoint *breakpoints, unsigned long nr)
{
	struct breakpoint *b = breakpoints;
	unsigned long i, j;

	for (i = 0; i < nr; i++) {
		if ((b->addr != (uint32_t *)-1) &&
		    (insert_one_breakpoint(pid, b) == false)) {
			b = breakpoints;
			for (j = 0; j < i; j++)
				remove_one_breakpoint(pid, b++);
			return false;
		}
		b++;
	}

	return true;
}

static bool remove_breakpoints(pid_t pid, struct breakpoint *breakpoints, unsigned long nr)
{
	struct breakpoint *b = breakpoints;
	unsigned long i;
	bool ret = true;

	for (i = 0; i < nr; i++) {
		if ((b->addr != (uint32_t *)-1) &&
		    (remove_one_breakpoint(pid, b) == false))
			ret = false;
		b++;
	}

	return ret;
}

#define MAX_SYMS 256

static struct sym_table {
	long symcount;
	asymbol **syms;
	unsigned long base_address;
	unsigned long base_offset;
} sym_tables[MAX_SYMS];

unsigned long nr_sym_tables = 0;

static int symcmp(const void *p1, const void *p2)
{
	asymbol * const *s1 = p1;
	asymbol * const *s2 = p2;

	return bfd_asymbol_value(*s1) > bfd_asymbol_value(*s2);
}

void build_symtab(bfd *abfd, asymbol ***syms, long *symcount)
{
	unsigned int size;

	if (!(bfd_get_file_flags(abfd) & HAS_SYMS))
		return;

	*symcount = bfd_read_minisymbols(abfd, 0, (PTR) syms, &size);

	if (*symcount == 0)
		*symcount = bfd_read_minisymbols(abfd, 1, (PTR) syms, &size);

	qsort(*syms, *symcount, sizeof(asymbol *), symcmp);
}

static asymbol *symfind(symvalue addr, unsigned long *base_offset)
{
	unsigned long i;
	unsigned long left = 0;
	unsigned long right;
	int nearest = 0;
	bool found = false;
	long symcount;
	asymbol **syms;

	/* find the nearest matching symbol table */
	for (i = 0; i < nr_sym_tables; i++) {
		if (sym_tables[i].base_address > addr)
			continue;

		if (!found) {
			found = true;
			nearest = i;
		}

		if (sym_tables[i].base_address > sym_tables[nearest].base_address)
			nearest = i;
	}

	if (!found)
		return NULL;

	*base_offset = sym_tables[nearest].base_offset;
	addr -= sym_tables[nearest].base_offset;
	symcount = sym_tables[nearest].symcount;
	syms = sym_tables[nearest].syms;

	right = symcount;

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

void syminit(char *file, unsigned long base_address,
	     unsigned long base_offset, char *target)
{
	bfd *abfd;

	abfd = bfd_openr(file, target);
	if (abfd == NULL) {
		printf("Unable to open %s\n", file);
		return;
	}

	if (!bfd_check_format(abfd, bfd_object)) {
		printf("unsupported file type\n");
		exit(1);
	}

	build_symtab(abfd, &sym_tables[nr_sym_tables].syms, &sym_tables[nr_sym_tables].symcount);
	sym_tables[nr_sym_tables].base_address = base_address;
	sym_tables[nr_sym_tables].base_offset = base_offset;
	nr_sym_tables++;
}

FILE *fout;

static void __print_address(bfd_vma vma)
{
	unsigned long base_offset;
	asymbol *sym = symfind(vma, &base_offset);

	if (sym) {
		unsigned long offset = (vma - base_offset) - bfd_asymbol_value(sym);
		const char *name = bfd_asymbol_name(sym);

		fprintf(fout, "%lx <%s+0x%lx> ", vma, name, offset);
	} else {
		fprintf(fout, "%lx ", vma);
	}
}

static void print_address(bfd_vma vma, struct disassemble_info *info)
{
	__print_address(vma);
}

void disasm(uint32_t *ea, unsigned int *buf, unsigned long bufsize)
{
	disassemble_info info;
	int i;

	INIT_DISASSEMBLE_INFO(info, fout, fprintf);

	info.disassembler_options = "power8";
	info.buffer = (bfd_byte *)buf;
	info.buffer_vma = (unsigned long)ea;
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
		i += print_insn_little_powerpc((unsigned long)ea, &info);
#else
		i += print_insn_big_powerpc((unsigned long)ea, &info);
#endif
	}
}

static bool qtrace_format;
static unsigned long nr_insns_left = -1UL;
static unsigned long nr_insns_skip = 0;

void print_insn(uint32_t *pc, uint32_t insn, pid_t pid)
{
	if (nr_insns_skip) {
		nr_insns_skip--;
		return;
	}

	if (qtrace_format) {
		int ret;
		struct pt_regs regs;
		unsigned long addr = 0, size = 0;

		ret = ptrace(PTRACE_GETREGS, pid, NULL, &regs);
		if (ret) {
			perror("PTRACE_GETREGS");
			exit(1);
		}

		if (is_storage_insn(insn, &regs.gpr[0], &addr, &size))
			qtrace_add_storage_record(insn, (unsigned long)pc, addr, size);
		else
			qtrace_add_record(insn, (unsigned long)pc);
	} else {
		__print_address((unsigned long)pc);
		disasm(pc, &insn, sizeof(insn));
		fprintf(fout, "\n");
	}

	if (!nr_insns_left--) {
		ptrace(PTRACE_DETACH, pid, 0, 0);
		qtrace_close();
		exit(0);
	}
}

static bool step_over_atomic(pid_t pid, uint32_t *p)
{
	struct breakpoint breakpoints[MAX_BREAKPOINTS];
	unsigned long b = 0, i = 0, j = 0;
	uint32_t *start, *end;
	uint32_t *pc;
	uint32_t insn;

	insn = read_insn(pid, p);
	if (!is_larx(insn))
		return false;

	start = p;

	for (i = 0; i < MAX_LARX_STCX_GAP; i++) {
		insn = read_insn(pid, p);
		if (is_stcx(insn))
			break;

		if (is_branch(insn)) {
			/* Too many branches? */
			if (b == (MAX_BREAKPOINTS-1)) {
				fprintf(stderr, "step_over_atomic() failed at %p, too many breakpoints\n", p);
				return false;
			}

			breakpoints[b++].addr = branch_target(insn, p);
		}

		p++;
	}

	/* We didn't find the stcx */
	if (!is_stcx(insn)) {
		fprintf(stderr, "step_over_atomic() failed at %p, stcx not found\n", p);
		return false;
	}

	/* Add breakpoint after stcx */
	p++;
	breakpoints[b++].addr = p;

	end = p;

	/*
	 * check for breakpoints within the larx/stcx region, or
	 * duplicated breakpoints.
	 */
	for (i = 0; i < b; i++) {
		if ((breakpoints[i].addr >= start) &&
		    (breakpoints[i].addr < end)) {
			breakpoints[i].addr = (uint32_t *)-1;
			continue;
		}

		for (j = i+1; j < b; j++) {
			if (breakpoints[i].addr == breakpoints[j].addr) {
				breakpoints[i].addr = (uint32_t *)-1;
			}
		}
	}

	insert_breakpoints(pid, breakpoints, b);

	if (ptrace(PTRACE_CONT, pid, 0, 0) == -1) {
		perror("ptrace");
		exit(1);
	}

	int status;
	waitpid(pid, &status, __WALL);

	pc = read_pc(pid);

	/* XXX FIXME This assumes the larx/stcx passed */
	while (start < pc) {
		insn = read_insn(pid, start);
		print_insn(start, insn, pid);
		start++;
	}

	remove_breakpoints(pid, breakpoints, b);

	/*
	 * Trace the instruction we trapped on, now we've removed the
	 * breakpoint
	 */
	insn = read_insn(pid, start);
	print_insn(pc, insn, pid);

	if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) == -1) {
		perror("ptrace");
		exit(1);
	}

	return true;
}

#define BUFSIZE 2048

static void initialise_mem_map(pid_t pid)
{
	char map[PATH_MAX];
	FILE *fptr;
	bool first = true;

	bfd_init();

	snprintf(map, PATH_MAX, "/proc/%d/maps", pid);

	fptr = fopen(map, "r");
	if (!fptr) {
		perror("open /proc/pid/maps failed");
		exit(1);
	}

	while (1) {
		char buf[BUFSIZE];
		unsigned long start, end;
		char perm[BUFSIZE];
		char library[BUFSIZE];
		unsigned long offset;

		if (fgets(buf, sizeof(buf), fptr) == NULL)
			break;

		sscanf(buf, "%lx-%lx %s %*s %*s %*s %s", &start, &end,
			perm, library);

		if (*(perm + 2) != 'x')
			continue;

		printf("start %lx end %lx library %s\n", start, end, library);

		offset = start;
		if (first == true) {
			first = false;
			offset = 0;
		}

		syminit(library, start, offset, "elf64-powerpc");
	}

	fclose(fptr);
}

void usage(void)
{
	fprintf(stderr, "Usage: ptracer [OPTION] PROG [ARGS]\n");
	fprintf(stderr, "\t-o logfile	(required)\n");
	fprintf(stderr, "\t-c		trace after first fork/vfork/clone\n");
	fprintf(stderr, "\t-p pid	pid to attach to\n");
	fprintf(stderr, "\t-n nr_insns	Number of instructions to trace\n");
	fprintf(stderr, "\t-s nr_insns	Number of instructions to skip\n");
	fprintf(stderr, "\t-q		qtrace format (default disassembly format)\n");
}

int main(int argc, char *argv[])
{
	char *logfile = NULL;
	pid_t child_pid = 0;
	uint32_t *pc;
	uint32_t insn;
	static bool initialized = false;
	static bool trace_forked_child = false;

	while (1) {
		signed char c = getopt(argc, argv, "+cfo:p:n:s:qh");
		if (c < 0)
			break;

		switch (c) {
		case 'c':
			trace_forked_child = true;
			break;

#if 0
		case 'f':
			follow_fork = true;
			break;
#endif

		case 'o':
			logfile = optarg;
			break;

		case 'p':
			child_pid = atoi(optarg);
			break;

		case 'n':
			nr_insns_left = strtol(optarg, NULL, 10);
			break;

		case 's':
			nr_insns_skip = strtol(optarg, NULL, 10);
			break;

		case 'q':
			qtrace_format = true;
			break;

		default:
			usage();
			exit(1);
		}
	}

	if (!logfile || (child_pid && (argc - optind))) {
		usage();
		exit(1);
	}

	if (!child_pid && !(argc - optind)) {
		usage();
		exit(1);
	}

	if (qtrace_format) {
		qtrace_open(logfile);
	} else {
		fout = fopen(logfile, "w");
		if (fout == NULL) {
			perror("Could not open logfile\n");
			exit(1);
		}
	}

	if (!child_pid) {
		child_pid = fork();

		if (child_pid < 0) {
			perror("fork");
			exit(1);
		}

		if (!child_pid) {
			if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
				perror("ptrace");
				exit(1);
			}

			execvp(argv[optind], &argv[optind]);
			perror("execv");
			exit(1);
		}
	} else {
		if (ptrace(PTRACE_ATTACH, child_pid, 0, 0) == -1) {
			perror("ptrace");
			exit(1);
		}
	}

	if (trace_forked_child) {
		pid_t pid;
		int status;

		pid = waitpid(child_pid, &status, __WALL);
		if (pid != child_pid) {
			fprintf(stderr, "Waiting on unknown PID %d, expected %d\n", pid, child_pid);
			perror("waitpid");
			exit(1);
		}

		if (ptrace(PTRACE_SETOPTIONS, child_pid, 0,
			   PTRACE_O_TRACECLONE|PTRACE_O_TRACEFORK|
			   PTRACE_O_TRACEVFORK) == -1) {
			perror("ptrace");
			exit(1);
		}

		if (ptrace(PTRACE_CONT, child_pid, 0, 0) == -1) {
			perror("ptrace");
			exit(1);
		}
	}

	while (1) {
		pid_t pid;
		int status;

		if (trace_forked_child) {
			/* Ignore child_pid events */
			do {
				pid = waitpid(-1, &status, __WALL);
			} while (pid == child_pid);
		} else {
			pid = waitpid(child_pid, &status, __WALL);
			if (pid != child_pid) {
				fprintf(stderr, "Waiting on unknown PID %d, expected %d\n", pid, child_pid);
				perror("waitpid");
				exit(1);
			}
		}

		/* The child exited */
		if (WIFEXITED(status)) {
			qtrace_close();
			exit(0);
		}

		if (!WIFSTOPPED(status)) {
			fprintf(stderr, "Unknown issue, waitpid returned 0x%x\n", status);
			exit(1);
		}

		if (!initialized) {
			initialized = true;
			initialise_mem_map(pid);
		}

		pc = read_pc(pid);
		insn = read_insn(pid, pc);
		asm volatile("":::"memory");

		if (is_larx(insn)) {
			step_over_atomic(pid, pc);
		} else {
			unsigned int sig = 0;

			print_insn(pc, insn, pid);

			if (WSTOPSIG(status) && WSTOPSIG(status) != SIGTRAP)
				sig = WSTOPSIG(status);

			if (ptrace(PTRACE_SINGLESTEP, pid, 0, sig) == -1) {
				perror("ptrace");
				exit(1);
			}
		}
	}

	return 0;
}
