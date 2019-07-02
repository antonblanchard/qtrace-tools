/*
 * Create a qtrace from a set of asm statements.
 *
 * These can be generated from a qtrace with qtdis (qtbuild output),
 * edited, then turned back into a qtrace with qtbuild.
 *
 * Build the qtrace tool with:
 *
 * make
 *
 * To test an example:
 *
 * cp examples/spinlock.S ./
 * make CC=powerpc64le-linux-gnu-gcc spinlock.qt
 *
 * Turn a qtrace into a qtbuild .S file:
 *
 * ../qtdis/qtdis -b spinlock.qt spinlock2.S
 * vi spinlock2.S # edit and save
 * make CC=powerpc64le-linux-gnu-gcc spinlock2.qt
 *
 * Copyright (C) 2015-2018 Anton Blanchard <anton@au.ibm.com>, et al. IBM
 */
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <config.h>
#include <bfd.h>
#include <dis-asm.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <qtwriter.h>
#include "../qtlib/branch.h"
#include "../ptracer/ppc_storage.h"
#include "../ptracer/ppc_storage.c"

#undef DEBUG

static struct qtwriter_state qtwr;

#define BRANCH_TYPE_ABS 0
#define BRANCH_TYPE_REL 1
#define BRANCH_TYPE_INS 2

struct insn_map {
	uint64_t text_addr;
	uint32_t branch_type;
	uint64_t dynamic_addr;
} __attribute__((__packed__));

struct ldst_map {
	uint64_t text_addr;
	uint64_t storage_addr;
} __attribute__((__packed__));

static void build(bfd *abfd)
{
	asection *text_section;
	asection *insnmap_section;
	asection *ldstmap_section;
	bfd_size_type text_size, insnmap_size, ldstmap_size;
	bfd_size_type insnmap_idx;
	bfd_size_type ldstmap_idx;
	uint64_t taddr;
	uint64_t daddr;
	uint32_t *text_buf;
	struct insn_map *insnmap_buf;
	struct ldst_map *ldstmap_buf;

	if (!bfd_check_format(abfd, bfd_object)) {
		printf("unsupported file type\n");
		exit(1);
	}

	text_section = bfd_get_section_by_name (abfd, ".text");
	if (!text_section) {
		printf("no .text section\n");
		exit(1);
	}

	insnmap_section = bfd_get_section_by_name (abfd, ".data.insnmap");
	if (!insnmap_section) {
		printf("no .data.insnmap section\n");
		exit(1);
	}

	ldstmap_section = bfd_get_section_by_name (abfd, ".data.ldstmap");
	if (!ldstmap_section) {
		printf("no .data.ldstmap section\n");
		exit(1);
	}

	text_size = bfd_section_size(bfd, text_section);
	insnmap_size = bfd_section_size(bfd, insnmap_section);
	ldstmap_size = bfd_section_size(bfd, ldstmap_section);

	text_buf = malloc(text_size);
	insnmap_buf = malloc(insnmap_size + sizeof(struct insn_map));
	ldstmap_buf = malloc(ldstmap_size);

	/* make a terminating entry that never matches */
	insnmap_buf[insnmap_size / sizeof(struct insn_map)].text_addr = -1;

	if (!bfd_get_section_contents(abfd, text_section, text_buf, 0, text_size)) {
		printf("could not read .text section\n");
		exit(1);
	}

	if (!bfd_get_section_contents(abfd, insnmap_section, insnmap_buf, 0, insnmap_size)) {
		printf("could not read .data.insnmap section\n");
		exit(1);
	}

	if (!bfd_get_section_contents(abfd, ldstmap_section, ldstmap_buf, 0, ldstmap_size)) {
		printf("could not read .data.ldstmap section\n");
		exit(1);
	}

	taddr = 0;
	insnmap_idx = 0;
	if (insnmap_buf[insnmap_idx].text_addr != taddr) {
		printf("insnmap does not have initial dynamic address\n");
		exit(1);
	}
	if (insnmap_buf[insnmap_idx].branch_type != BRANCH_TYPE_ABS) {
		printf("insnmap does not have initial absolute address\n");
		exit(1);
	}
	daddr = insnmap_buf[insnmap_idx].dynamic_addr;
	insnmap_idx++;

	ldstmap_idx = 0;

	while (taddr < text_size) {
		struct qtrace_record qtr;
		uint32_t insn = text_buf[taddr / sizeof(uint32_t)];

		memset(&qtr, 0, sizeof(qtr));
		qtr.insn = insn;
		qtr.insn_addr = daddr;

#ifdef DEBUG
		printf("insn %lu iaddr=0x%lx", (taddr / 4), daddr);
#endif
		if (is_storage_insn(insn, NULL, NULL, NULL)) {
			struct ldst_map m = ldstmap_buf[ldstmap_idx];
			if (m.text_addr != taddr + sizeof(uint32_t)) {
				printf("ldstmap does not have record for storage instruction (insn %lu)\n", (taddr / sizeof(uint32_t)));
				exit(1);
			}
#ifdef DEBUG
			printf("  load/store daddr=0x%lx", m.storage_addr);
#endif
			ldstmap_idx++;

			qtr.data_addr = m.storage_addr;
			qtr.data_addr_valid = true;
		}

		qtr.branch = is_branch(insn);
		qtr.conditional_branch = is_conditional_branch(insn);

		if (insnmap_buf[insnmap_idx].text_addr == taddr + sizeof(uint32_t)) {
			uint32_t btype = insnmap_buf[insnmap_idx].branch_type;

			/* Instruction just added was a taken branch */
			if (btype == BRANCH_TYPE_ABS) {
				daddr = insnmap_buf[insnmap_idx].dynamic_addr;
#ifdef DEBUG
				printf("  branch abs to iaddr=0x%lx", daddr);
#endif
			} else if (btype == BRANCH_TYPE_REL) {
				daddr += (int64_t)insnmap_buf[insnmap_idx].dynamic_addr;
#ifdef DEBUG
				printf("  branch rel to iaddr=0x%lx", daddr);
#endif
			} else if (btype == BRANCH_TYPE_INS) {
				if (!has_branch_target(insn)) {
					printf("insnmap has instruction branch with no matching branch instruction\n");
					exit(1);
				}
				daddr = branch_target(insn, daddr);
#ifdef DEBUG
				printf("  branch insn to iaddr=0x%lx", daddr);
#endif
			} else {
				/*
				 * Interrupts could come here. Should add
				 * support.
				 */
				printf("insnmap has bad branch type %d\n", btype);
				exit(1);
			}

			insn = qtr.insn = set_branch_target(insn, qtr.insn_addr, daddr);
			if (!insn) {
				printf("  branch is invalid\n");
				exit(1);
			}

			insnmap_idx++;
		} else {
			daddr += sizeof(uint32_t);
		}
		taddr += sizeof(uint32_t);
#ifdef DEBUG
		printf("\n");
#endif

		if (qtwriter_write_record(&qtwr, &qtr) == false) {
			fprintf(stderr, "qtwriter_write_record failed\n");
			exit(1);
		}

	}
}

static void usage(void)
{
	fprintf(stderr, "Usage: qtbuild [INFILE] [QTFILE]\n\n");
}

bool qtwriter_open(struct qtwriter_state *state, char *filename,
		   uint32_t magic);
bool qtwriter_write_record(struct qtwriter_state *state,
			   struct qtrace_record *record);
void qtwriter_close(struct qtwriter_state *state);
int main(int argc, char *argv[])
{
	bfd *abfd;

	if (argc != 3) {
		usage();
		exit(1);
	}

	bfd_init();
	abfd = bfd_openr(argv[1], NULL);
	if (abfd == NULL) {
		printf("Unable to open input %s\n", argv[1]);
		exit(1);
	}

	if (!qtwriter_open(&qtwr, argv[2], 0)) {
		printf("could not open qtrace\n");
		exit(1);
	}

	build(abfd);

	qtwriter_close(&qtwr);

	return 0;
}
