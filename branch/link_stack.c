/*
 * Link stack performance
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "qtreader.h"

#define OPCODE(insn)		((insn) >> 26)
#define SUB_OPCODE(insn)	(((insn) >> 1) & 0x3ff)

#define LINK(insn)		((insn) & 0x1)
#define AA(insn)		(((insn) >> 1) & 0x1)
#define BH(insn)		(((insn) >> 11) & 0x3)
#define BO(insn)		(((insn) >> 21) & 0x1f)
#define BI(insn)		(((insn) >> 16) & 0x1f)
#define BD(insn)		(((insn) >> 2) & 0x3fff)

#define DEBUG

#ifdef DEBUG
#define DBG(A...) printf(A)
#else
#define DBG(A...) do { } while(0)
#endif

struct stats {
	uint64_t collisions;
	uint64_t predictions;
	uint64_t mispredictions;
};

struct link_stack_entry
{
	uint64_t nia;
};

/*
 * It would be nice to have statistics for underflow and overflow, user/kernel,
 * and context switch related misprediction.
 */
struct link_stack
{
	uint64_t depth;
	uint64_t offset;
	struct stats stats;
	struct link_stack_entry *entries;
};

struct link_stack *link_stack_init(uint64_t depth)
{
	struct link_stack *p;

	p = calloc(1, sizeof(struct link_stack));
	if (!p) {
		perror("calloc");
		exit(1);
	}

	p->entries = calloc(depth, sizeof(struct link_stack_entry));
	if (!p->entries) {
		perror("calloc");
		exit(1);
	}

	p->depth = depth;
	p->offset = depth-1;

	return p;
}

static void link_stack_push(struct link_stack *p, uint64_t addr)
{
	if (p->offset == (p->depth-1))
		p->offset = 0;
	else
		p->offset++;

	p->entries[p->offset].nia = addr + sizeof(uint32_t);
}

static bool link_stack_pop(struct link_stack *p, uint64_t addr)
{
	uint64_t predicted_addr = p->entries[p->offset].nia;

	if (p->offset == 0)
		p->offset = p->depth-1;
	else
		p->offset--;

	p->stats.predictions++;

	if (predicted_addr != addr)
		p->stats.mispredictions++;

	return predicted_addr == addr;
}

static void print_stats(struct link_stack *p)
{
	printf("total predictions %ld\n", p->stats.predictions);
	printf("prediction rate %.2f%%\n", 100.0 * (p->stats.predictions-p->stats.mispredictions)/p->stats.predictions);
}

#ifdef TEST

int main(void)
{
	struct link_stack *p;

	p = link_stack_init(2);

	link_stack_push(p, 0x10000000);
	link_stack_push(p, 0x10000010);
	link_stack_push(p, 0x10000020);

	assert(link_stack_pop(p, 0x10000024) == 1);
	assert(link_stack_pop(p, 0x10000014) == 1);
	assert(link_stack_pop(p, 0x10000004) == 0);
}

#else

static void check_bh_bits(uint32_t insn, unsigned long insn_addr)
{
	uint32_t bh_bits = BH(insn);

	if (SUB_OPCODE(insn) != 16 && BH(insn) == 0x1)
		printf("Reserved BH field in insn 0x%08x at 0x%lx\n", insn,
			insn_addr);

	if (bh_bits == 0x2)
		printf("Reserved BH field in insn 0x%08x at 0x%lx\n", insn,
			insn_addr);

	if (bh_bits == 0x3)
		printf("Unpredictable BH field in insn 0x%08x at 0x%lx\n", insn,
			insn_addr);
}

int main(int argc, char *argv[])
{
	int fd;
	struct qtreader_state state;
	struct qtrace_record record;
	struct link_stack *p;

	if (argc != 3) {
		printf("Usage: link_stack DEPTH TRACEFILE\n\n");
		exit(1);
	}

	p = link_stack_init(atoi(argv[1]));

	fd = open(argv[2], O_RDONLY);
	if (fd < 0) {
		perror("open");
		exit(1);
	}

	if (qtreader_initialize_fd(&state, fd, 0) == false) {
		fprintf(stderr, "qtreader_initialize_fd failed\n");
		exit(1);
	}

	while (qtreader_next_record(&state, &record) == true) {
		uint32_t insn = record.insn;
		uint64_t insn_addr = record.insn_addr;
		uint64_t next_insn_addr = record.next_insn_addr;
		uint32_t opcode = OPCODE(insn);

		if (record.branch_taken == false)
			continue;

		/*
		 * Look for bcl 20,31,$+4 - this sequence is used for
		 * addressing and should be ignored by the link stack.
		 */
		if ((opcode == 18) && (AA(insn) == 0) && (LINK(insn) == 1)) {
			if ((BO(insn) == 20) && (BI(insn) == 31) &&
			    (BD(insn) == 4)) {
				DBG("bcl 20,31,$+4 at 0x%lx\n", insn_addr);
				continue;
			}
		}

		/* bl, bla, bcl, bcla */
		if (opcode == 18 || opcode == 16) {
			if (LINK(insn)) {
				DBG("PSH %lx\n", insn_addr);
				link_stack_push(p, insn_addr);
			}
		}

		if (opcode == 19) {
			switch (SUB_OPCODE(insn)) {
			/* bclr, bclrl */
			case 16:
				check_bh_bits(insn, insn_addr);

				if (BH(insn) != 1) {
					bool result = link_stack_pop(p,
								next_insn_addr);
					DBG("POP %lx %d\n", insn_addr,
						result);
				}

				if (LINK(insn)) {
					link_stack_push(p, insn_addr);
					DBG("PSH %lx\n", insn_addr);
				}
				break;

			/* bcctrl, bctarl */
			case 528:
			case 560:
				check_bh_bits(insn, insn_addr);

				if (LINK(insn)) {
					link_stack_push(p, insn_addr);
					DBG("PSH %lx\n", insn_addr);
				}
				break;
			}
		}
	}

	print_stats(p);

	return 0;
}

#endif
