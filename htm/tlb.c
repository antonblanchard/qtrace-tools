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

#include "tlb.h"

#define TLB_FLAGS_AVALIABLE (TLB_FLAGS_RELOC)
struct tlbe {
	uint64_t ea;
	uint64_t ra;
	uint64_t size;
	uint64_t hit_count;
	uint64_t miss_count;
	bool valid;
};
struct tlb_cache {
	struct tlbe *tlb;
	int size;
	int next;
	int translations;
	int no_translation;
	int translation_changes;
};
struct tlb_cache tlb;

int tlb_debug = 0;

static inline uint64_t tlb_mask_offset(struct tlbe *t)
{
	return t->size - 1;
}

static inline uint64_t tlb_mask_rpn(struct tlbe *t)
{
	return ~(tlb_mask_offset(t));
}

static inline void tlb_pagesize_validate(uint64_t size)
{
	assert((size == 4096) || (size == 65536) || (size == 16777216));
}

static inline void tlb_flags_validate(uint64_t flags)
{
	assert((flags & ~(TLB_FLAGS_AVALIABLE)) == 0);
}

static bool tlb_equal(struct tlbe *t1, struct tlbe *t2)
{
	if (t1->ea != t2->ea)
		return false;
	if (t1->ra != t2->ra)
		return false;
	if (t1->size != t2->size)
		return false;
	if (t1->valid != t2->valid)
		return false;
	/* Don't check count */

	return true;
}

static inline void tlb_entry_validate(struct tlbe *t)
{
	uint64_t mask;

	assert(t->valid);
	tlb_pagesize_validate(t->size);
	mask = tlb_mask_offset(t);
	assert((t->ea & mask) == 0);
	assert((t->ra & mask) == 0);
}

static inline void tlb_print(struct tlbe *t)
{
	printf("ea:%016"PRIx64" ra:%016"PRIx64" size:%08"PRIx64" "
	       "miss:%"PRIi64" hit:%"PRIi64"\n",
	       t->ea, t->ra, t->size, t->miss_count, t->hit_count);
}

static inline bool tlb_match(uint64_t ea, struct tlbe *t)
{
	tlb_entry_validate(t);

	if (tlb_debug > 0) {
		printf("%s ea:%016"PRIx64" ", __func__, ea);
		tlb_print(t);
	}

	if (ea < t->ea)
		return false;
	if (ea >= (t->ea + t->size))
		return false;

	return true;
}


static inline int __tlb_get_index(uint64_t ea, int start)
{
	struct tlbe *t;
	int i;

	/* FIXME: linear search... *barf* */
	for (i = start; i < tlb.next; i++) {
		t = &tlb.tlb[i];
		if (tlb_match(ea, t)) {
			tlb_entry_validate(t);
			/* This hit in the hardware hence we had to do
			 * the translation
			 */
			t->hit_count++;
			return i;
		}
	}
	return -1;
}

static inline int tlb_get_index(uint64_t ea)
{
	return __tlb_get_index(ea, 0);
}

static inline void tlb_validate(void)
{
	struct tlbe *t;
	int i;
	bool valid_last;

	assert(tlb.next <= tlb.size);

	/* Check for overlaps */
	for (i = 0; i < tlb.next; i++) {
		t = &tlb.tlb[i];
		/* Check this ea doesn't match other entries */
		/* Check start of page */
		assert(__tlb_get_index(t->ea, i + 1) == -1);
		/* Check end page */
		assert(__tlb_get_index(t->ea + t->size - 1, i + 1) == -1);
	}

	/* Check for holes */
	valid_last = true;
	for (i = 0; i < tlb.size; i++) {
		t = &tlb.tlb[i];
		assert(!t->valid || valid_last);
		valid_last = t->valid;
	}
}

static inline uint64_t tlb_translate(uint64_t ea, uint64_t flags,
				     struct tlbe *t)
{
	uint64_t ra;

	/* Double check this is a match */
	assert(ea >= t->ea);
	assert(ea < (t->ea + t->size));
	/* Other checks */
	tlb_flags_validate(flags); /* flags unused other than this check */
	tlb_entry_validate(t);

	/* Actual translation */
	ra = ea & tlb_mask_offset(t);
	ra |= t->ra & tlb_mask_rpn(t);

	return ra;
}

void tlb_init(void)
{
	tlb_validate();
}

void tlb_exit(void)
{
	tlb_validate();
}

bool tlb_ra_get(uint64_t ea, uint64_t flags,
		uint64_t *ra, uint64_t *pagesize)
{
	struct tlbe *t;
	int index;

	assert(ra);
	assert(pagesize);

	if ((flags & TLB_FLAGS_RELOC) == 0) {
		*ra = ea & 0x3fffffffffffffff;
		*pagesize = 0x1000;
		return true;
	}

	tlb.translations++;
	/* Find entry */
	index = tlb_get_index(ea);
	if (index < 0) {
		tlb.no_translation++;
		return false;
	}

	/* Get entry */
	t = &tlb.tlb[index];

	/* Do translation */
	*ra = tlb_translate(ea, flags, t);
	*pagesize = t->size;

	return true;
}

static int tlb_compare(const void *a, const void *b)
{
	return ((struct tlbe *)b)->hit_count - ((struct tlbe *)a)->hit_count;
}

void tlb_allocate(void)
{
	int size_new;

	struct tlbe *t;
//	printf("Allocating new TLB size: %i\n", tlb.size);

	if (!tlb.tlb) {
		/* Allocate initial TLB */
		tlb.tlb = malloc(sizeof(struct tlbe));
		assert(tlb.tlb);
		tlb.size = 1;
		memset(tlb.tlb, 0, sizeof(struct tlbe));
		return;
	}

	/* Double the size of the TLB */
	size_new = tlb.size * 2;
	tlb.tlb = realloc(tlb.tlb, size_new*sizeof(struct tlbe));
	assert(tlb.tlb);
	/* zero new part */
	t = &tlb.tlb[tlb.size];
	memset(t, 0, tlb.size*sizeof(struct tlbe));
	tlb.size = size_new;

	/* Since we do a linear search, sort once in a while to help
	 * with hit rate
	 */
	qsort(tlb.tlb, tlb.next, sizeof(struct tlbe), tlb_compare);

	tlb_validate();
	return;
}

void tlb_dump(void)
{
	int i;

	qsort(tlb.tlb, tlb.next, sizeof(struct tlbe), tlb_compare);

	for (i = 0; i < tlb.next; i++) {
		printf("TLBDUMP %02i: ", i);
		tlb_print(&tlb.tlb[i]);
	}
	printf("TLBDUMP no translation: %i of %i\n",
	       tlb.no_translation, tlb.translations);
	printf("TLBDUMP replaced translations: %i\n",
	       tlb.translation_changes);
}

/*
 * Set a new entry.
 * If old entry exists, delete it
 */
void tlb_ra_set(uint64_t ea, uint64_t flags,
		uint64_t ra, uint64_t pagesize)
{
	struct tlbe *t;
	struct tlbe tnew;
	int index;

//	tlb_debug = 1;

	if ((flags & TLB_FLAGS_RELOC) == 0)
		return;

	tlb_pagesize_validate(pagesize);
	tlb_flags_validate(flags);

	index = tlb_get_index(ea);
	if (index < 0) {
		/* No entry found, so put it at the end */
		index = tlb.next;
		if (tlb.size == tlb.next)
			tlb_allocate();
		tlb.next++;
	}
	tlb_debug = 0;

	t = &tlb.tlb[index];

	/* Generate new entry */
	memset(&tnew, 0, sizeof(tnew));
	tnew.size = pagesize;
	tnew.ea = ea & tlb_mask_rpn(&tnew);
	tnew.ra = ra & tlb_mask_rpn(&tnew);
	tnew.valid = true;

	if (tlb_equal(&tnew, t)) {
		/* This missed in the hardware */
		t->miss_count++;
		return;
	} else if (t->valid) { /* new entry */
		/* Same RA but different RA */
		tlb.translation_changes++;
		/*
		printf("TLB different: %i\n", index);
		printf("TLB Existing: "); tlb_print(t);
		printf("TLB New:      "); tlb_print(&tnew);
		*/
	}

	/* Set entry */
	memcpy(t, &tnew, sizeof(tnew));

	/* Check if we've screwed something up  */
	tlb_validate();
}
