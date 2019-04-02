/*
 * Copyright (C) 2018 Michael Neuling <mikey@linux.ibm.com>, IBM
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <endian.h>
#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>

#include "bb.h"
#include "ccan/hash/hash.h"
#include "ccan/htable/htable_type.h"

struct obj {
	uint64_t ea;
	int index;
};

static const uint64_t *objea(const struct obj *obj)
{
	return &obj->ea;
}

static size_t objhash(const uint64_t *ea)
{
	return hash64(ea, 1, 0);
}

static bool cmp(const struct obj *obj1, const uint64_t *ea)
{
	return obj1->ea == *ea;
}

HTABLE_DEFINE_TYPE(struct obj, objea, objhash, cmp, htable_obj);


struct bbe {
	uint64_t ea;
	uint64_t size;
	uint64_t hit_count;
	bool valid;
};
struct bb_cache {
	struct htable_obj ht;
	struct bbe *bb;
	int size;
	int next;
	uint64_t instructions_num;
};
struct bb_cache bb;

int bb_debug = 0;

static inline uint64_t bb_instruction_num(struct bbe *t)
{
	return t->size * t->hit_count;
}

static inline void bb_print(struct bbe *t)
{
	float usage = 100.0 * ((double)bb_instruction_num(t)/(double)bb.instructions_num);

	printf("ea:%016"PRIx64" size:% 4"PRId64" "
	       "hit:% 10"PRIi64" %5.2f%% \n",
	       t->ea, t->size, t->hit_count, usage);
}

static int bb_compare_ea(const void *a, const void *b)
{

	struct bbe *bbe_a = (struct bbe *)a;
	struct bbe *bbe_b = (struct bbe *)b;

	if (bbe_a->ea < bbe_b->ea)
		return -1;
	else if (bbe_a->ea > bbe_b->ea)
		return 1;
	else if (bbe_a->size < bbe_b->size)
		return -1;
	else if (bbe_a->size > bbe_b->size)
		return 1;
	else
		return 0;
}

static int bb_compare_num(const void *a, const void *b)
{

	struct bbe *bbe_a = (struct bbe *)a;
	struct bbe *bbe_b = (struct bbe *)b;
	uint64_t a_num, b_num;

	a_num = bb_instruction_num(bbe_a);
	b_num = bb_instruction_num(bbe_b);

	if (bbe_a->valid && !bbe_b->valid)
		return -1;
	else if (!bbe_a->valid && bbe_b->valid)
		return 1;
	else if (a_num > b_num)
		return -1;
	else if (a_num < b_num)
		return 1;
	else
		return 0;
}

void bb_allocate(void)
{
	int size_new;

	struct bbe *t;
//	printf("Allocating new BB size: %i\n", bb.size);

	if (!bb.bb) {
		if (!htable_obj_init_sized(&bb.ht, 1000000)) {
			fprintf(stderr, "htable_obj_init_sized failed\n");
			exit(1);
		}
		/* Allocate initial BB */
		bb.bb = malloc(sizeof(struct bbe));
		assert(bb.bb);
		bb.size = 1;
		memset(bb.bb, 0, sizeof(struct bbe));
		return;
	}

	/* Double the size of the BB */
	size_new = bb.size * 2;
	bb.bb = realloc(bb.bb, size_new*sizeof(struct bbe));
	assert(bb.bb);
	/* zero new part */
	t = &bb.bb[bb.size];
	memset(t, 0, bb.size*sizeof(struct bbe));
	bb.size = size_new;

//	bb_validate();
	return;
}

void bb_init(void)
{
	bb_allocate();
}

/* descructive */
void bb_coalesce(void)
{
	struct bbe *ttest;
	struct bbe *t;
	uint64_t ea;
	int i;

	ttest = &bb.bb[0];
	ea = ttest->ea;
	/* Coalesce consecutive entres with same hit count & incrementing ea */
	for (i = 1; i < bb.next; i++) {
		t = &bb.bb[i];
		if ((t->ea == ea + 4) && abs(t->hit_count - ttest->hit_count) < 4) {
			t->valid = 0;
			ea = t->ea;
			ttest->size++;
		} else {
			ttest = t;
			ea = ttest->ea;
		}
	}
	/* make sure valids are all togetther */
	qsort(bb.bb, bb.next, sizeof(struct bbe), bb_compare_num);
	for (i = 0; i < bb.next; i++)
		if (!bb.bb[i].valid)
			bb.next = i;
}

/* This is descritive of the entries when sort= true */
static void __bb_dump(bool sort)
{
	int i;

	if (sort) {
		qsort(bb.bb, bb.next, sizeof(struct bbe), bb_compare_ea);
		bb_coalesce();
		qsort(bb.bb, bb.next, sizeof(struct bbe), bb_compare_num);
	}
	for (i = 0; i < bb.next; i++) {
		printf("BBDUMP %02i: ", i);
		bb_print(&bb.bb[i]);
	}
	// put back in binary search order
}
void bb_dump(void)
{
	__bb_dump(true);
}

void bb_ea_log(uint64_t ea)
{
	struct bbe *t;

//	bb_debug = 1;
//
	struct obj *obj;

	bb.instructions_num++;
	obj = htable_obj_get(&bb.ht, &ea);
	if (obj) {
		t = &bb.bb[obj->index];
		t->hit_count++;
		return;
	}
	/* Didn't find the entry */
	if (bb.size == bb.next)
		bb_allocate();

	t = &bb.bb[bb.next];
	/* Generate new entry */
	t->size = 1; // FIXME for basic blocks
	t->ea = ea;
	t->valid = true;
	t->hit_count = 1;

	obj = malloc(sizeof(*obj));
	assert(obj);
	obj->ea = ea;
	obj->index = bb.next;
	htable_obj_add(&bb.ht, obj);

	bb.next++;
}
