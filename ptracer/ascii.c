#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <limits.h>
#include "config.h"
#ifdef USE_BFD
#include <bfd.h>
#include <dis-asm.h>
#endif

FILE *ascii_fout;

#ifdef USE_BFD

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

static void syminit(char *file, unsigned long base_address,
		    unsigned long base_offset, char *target)
{
	bfd *abfd;

	abfd = bfd_openr(file, target);
	if (abfd == NULL) {
#ifdef DEBUG
		printf("Unable to open %s\n", file);
#endif
		return;
	}

	if (!bfd_check_format(abfd, bfd_object)) {
#ifdef DEBUG
		printf("unsupported file type\n");
#endif
		return;
	}

	build_symtab(abfd, &sym_tables[nr_sym_tables].syms, &sym_tables[nr_sym_tables].symcount);
	sym_tables[nr_sym_tables].base_address = base_address;
	sym_tables[nr_sym_tables].base_offset = base_offset;
	nr_sym_tables++;
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

#ifdef DEBUG
		printf("start %lx end %lx library %s\n", start, end, library);
#endif

		offset = start;
		if (first == true) {
			first = false;
			offset = 0;
		}

		syminit(library, start, offset, "elf64-powerpc");
	}

	fclose(fptr);
}

static void __print_address(bfd_vma vma)
{
	unsigned long base_offset;
	asymbol *sym = symfind(vma, &base_offset);

	if (sym) {
		unsigned long offset = (vma - base_offset) - bfd_asymbol_value(sym);
		const char *name = bfd_asymbol_name(sym);

		fprintf(ascii_fout, "%lx <%s+0x%lx> ", vma, name, offset);
	} else {
		fprintf(ascii_fout, "%lx ", vma);
	}
}

static void print_address(bfd_vma vma, struct disassemble_info *info)
{
	__print_address(vma);
}

static void disasm(uint32_t *ea, unsigned int *buf, unsigned long bufsize)
{
	disassemble_info info;
	int i;

	INIT_DISASSEMBLE_INFO(info, ascii_fout, fprintf);

	info.disassembler_options = "power9";
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
#endif

void ascii_open(char *filename)
{
	ascii_fout = fopen(filename, "w");
	if (ascii_fout == NULL) {
		perror("Could not open logfile\n");
		exit(1);
	}
}

void ascii_close(void)
{
	fclose(ascii_fout);
}

void ascii_add_record(pid_t pid, uint32_t insn, uint32_t *insn_addr)
{
#ifdef USE_BFD
	static bool initialized = false;

	if (!initialized) {
		initialized = true;
		initialise_mem_map(pid);
	}

	__print_address((bfd_vma)insn_addr);
	disasm(insn_addr, &insn, sizeof(insn));
	fprintf(ascii_fout, "\n");
#else
	fprintf(ascii_fout, "%p\t0x%x\n", insn_addr, insn);
#endif
}
