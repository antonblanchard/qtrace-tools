/*
 * Basic block vector reduction on a qtrace
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
#include <sys/types.h>
#include <sys/stat.h>

#include "matrix.h"
#include "pam.h"

#include <ccan/htable/htable_type.h>
#include <ccan/hash/hash.h>

#include "qtreader.h"

/* Number of instructions in each interval */ 
#define DEFAULT_PERIOD		10000000UL

#define DEFAULT_DIMENSIONS	127

/* The initial size of our hash table and matrix. This grows as needed. */
#define DEFAULT_PERIODS		1000
#define DEFAULT_BASIC_BLOCKS	10000

#define MAX_K 32

struct obj {
	uint64_t addr;
	uint64_t count;
	uint32_t id;
};

static const uint64_t objaddr(const struct obj *obj)
{
	return obj->addr;
}

static size_t objhash(const uint64_t addr)
{
	return hash64(&addr, 1, 0);
}

static bool cmp(const struct obj *obj, const uint64_t addr)
{
	return obj->addr == addr;
}

HTABLE_DEFINE_TYPE(struct obj, objaddr, objhash, cmp, htable_obj);

static struct htable_obj ht;

static uint32_t basic_block_id;

static struct matrix *matrix;

uint64_t interval = 0;

static uint64_t period = DEFAULT_PERIOD;

static uint32_t dimensions = DEFAULT_DIMENSIONS;

static int verbose;

static uint32_t my_k;

static void initialize(void)
{
	matrix = matrix_create(DEFAULT_PERIODS, DEFAULT_BASIC_BLOCKS);

	if (!htable_obj_init_sized(&ht, DEFAULT_BASIC_BLOCKS)) {
		fprintf(stderr, "htable_obj_init_sized failed\n");
		exit(1);
	}
}

static void add_basic_block(uint64_t addr, uint32_t val)
{
	struct obj *obj;

	obj = htable_obj_get(&ht, addr);
	if (obj) {
		obj->count += val;
	} else {
		obj = malloc(sizeof(*obj));

		if (!obj) {
			perror("malloc");
			exit(1);
		}

		obj->addr = addr;
		obj->count = val;
		obj->id = basic_block_id++;

		htable_obj_add(&ht, obj);
	}
}

static void reset_basic_block_vector(void)
{
	struct obj *obj;
	struct htable_obj_iter i;

	/* Resize in powers of two */
	if (basic_block_id >= matrix->cols)
		matrix_resize(matrix, matrix->rows, matrix->cols * 2);

	if (interval >= matrix->rows)
		matrix_resize(matrix, matrix->rows*2, matrix->cols);

	for (obj = htable_obj_first(&ht, &i); obj; obj = htable_obj_next(&ht, &i)) {
		if (obj->count)
			*matrix_entry(matrix, interval, obj->id) = obj->count;
		obj->count = 0;
	}

	interval++;
}

static bool do_one_pam(struct matrix *b, uint64_t k)
{
	struct pam *pam;
	bool ret = false;

	printf("Testing K=%ld\n", k);

	pam = pam_initialise(b, k);
	if (!pam) {
		fprintf(stderr, "pam_initialise failed\n");
		exit(1);
	}

	while (pam_iteration(pam) == true) {
		if (verbose)
			printf("%ld\n", pam->current_cost);
	}

	printf("Cost: %ld\n", pam->current_cost);

	print_medoids(pam, period);

	printf("\n");

	if (pam->current_cost == 0)
		ret = true;

	pam_destroy(pam);

	return ret;
}

static void do_pam(void)
{
	struct matrix *b;

	/*
	 * For performance we grew the matrix rows and columns in powers of
	 * two. At this point resize it to the actual number of periods and the
	 * maximum basic block id.
	 */
	matrix_resize(matrix, interval, basic_block_id+1);

	if (dimensions != 0)
		b = random_projection(matrix, dimensions);
	else
		b = matrix;

	if (verbose) {
		printf("Matrix:\n");
		matrix_print(b);
	}

	if (my_k) {
		do_one_pam(b, my_k);
	} else {
		uint64_t k;

		for (k = 1; k <= MAX_K; k++) {
			if (do_one_pam(b, k) == true)
				break;
		}
	}

	matrix_destroy(b);
}

static void parse_qtrace(int fd)
{
	struct qtreader_state qtreader_state;
	struct qtrace_record record;
	uint64_t ea = -1UL;
	static uint32_t bb_size = 0;
	static uint64_t instructions = 0;

	initialize();

	if (qtreader_initialize_fd(&qtreader_state, fd, 0) == false) {
		fprintf(stderr, "qtreader_initialize_fd failed\n");
		exit(1);
	}

	while (qtreader_next_record(&qtreader_state, &record) == true) {
		if (ea == -1UL)
			ea = record.insn_addr;

		bb_size++;
		/* What about exceptions? */
		if (record.is_conditional_branch || record.is_unconditional_branch) {
			if (verbose)
				printf("BB 0x%lx length %d\n", ea, bb_size);
			add_basic_block(ea, bb_size);
			bb_size = 0;
			ea = -1UL;
		}

		/* Should we wait for a basic block to terminate? */
		instructions++;
		if (instructions >= period) {
			reset_basic_block_vector();
			instructions = 0;
		}
	}

	qtreader_destroy(&qtreader_state);
}

static void usage(void)
{
	fprintf(stderr, "Usage: qtrace-bbv [OPTION]... [FILE]\n\n");
	fprintf(stderr, "\t-p\t\t\tperiod in instructions (default %ld)\n", DEFAULT_PERIOD);
	fprintf(stderr, "\t-k\t\t\tNumber of medoids (0 to sweep)\n");
	fprintf(stderr, "\t-d\t\t\tdimensionality reduction (default %d, 0 for none)\n", DEFAULT_DIMENSIONS);
	fprintf(stderr, "\t-v\t\t\tprint verbose info\n");
}

int main(int argc, char *argv[])
{
	int fd;

	while (1) {
		signed char c = getopt(argc, argv, "d:k:p:v");
		if (c < 0)
			break;

		switch (c) {
		case 'd':
			dimensions = strtoul(optarg, NULL, 10);
			break;

		case 'k':
			my_k = strtoul(optarg, NULL, 10);
			break;

		case 'p':
			period = strtoul(optarg, NULL, 10);
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

	fd = open(argv[optind], O_RDONLY);
	if (fd < 0) {
		perror("open");
		exit(1);
	}

	parse_qtrace(fd);
	do_pam();

	close(fd);

	return 0;
}
