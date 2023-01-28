/*
 * Copyright (C) 2022 Jordan Niethe <jniethe5@gmail.com>, IBM
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
#include <sys/mman.h>
#include <sys/stat.h>
#include <archive.h>
#include <string.h>

#include <ppcstats.h>

#include "htm.h"
#include "htm_types.h"
#include "xlate.h"
#include "tlb.h"
#include "pwc.h"
#include "erat.h"
#include "bb.h"
#include "branch.h"

#define NELEM(x) (sizeof(x) / sizeof(*x))

static unsigned int host_page_sizes[] = { 30, 21, 16, 12 };

static int levels[] = { PTE_LEVEL_4, PTE_LEVEL_3, PTE_LEVEL_2, PTE_LEVEL_1 };

static int xlate_htm_levels[] = {
	[XLATE_PGD] = PTE_LEVEL_1,
	[XLATE_PUD] = PTE_LEVEL_2,
	[XLATE_PMD] = PTE_LEVEL_3,
	[XLATE_PTE] = PTE_LEVEL_4,
};

struct xlate_pte_subtype {
	int n;
	enum xlate_pte_type types[2];
};

static struct xlate_pte_subtype xlate_pte_subtypes[] = {
	[XLATE_PGD] = { .n = 1, .types = { XLATE_PGD } },
	[XLATE_PUD] = { .n = 1, .types = { XLATE_PUD } },
	[XLATE_PMD] = { .n = 1, .types = { XLATE_PMD } },
	[XLATE_PTE] = { .n = 2, .types = { XLATE_4K_PTE, XLATE_64K_PTE } },
};


static int xlate_pte_pagesizes[] = {
	[XLATE_PGD] = 40,
	[XLATE_PUD] = 30,
	[XLATE_PMD] = 21,
	[XLATE_PTE] = 0,
	[XLATE_4K_PTE] = 12,
	[XLATE_64K_PTE] = 16
};

static int int_array_max(int arr[], int len)
{
	int max;

	max = 0;
	for (int i = 0; i < len; i++)
		max = (arr[i] > max) ? arr[i] : max;
	return max;
}


struct xlate_parser {
	struct htm_insn_xlate *xlate;
	int i;
};

/*
 * After initialization parser has the same scope as xlate.
 */
static void xlate_parser_init(struct xlate_parser *parser,
			      struct htm_insn_xlate *xlate)
{
	parser->xlate = xlate;
	parser->i = 0;
}

#define X_FINAL_RA	0x110
#define X_NO_FINAL_RA	0x100
#define X_GUEST_PTE	0x220
#define X_NO_GUEST_PTE	0x200
#define X_HOST_RA	0x440
#define X_NO_HOST_RA	0x400
#define _X_LEVEL	0x80
#define X_LEVEL(x)	(_X_LEVEL | (x))
#define X_LEVEL_MASK	0x0f

#define X_ENABLED(x)	((x) & 0xf00)
#define X_VALUE(x)	((x) & 0x0f0)

#define PROCESS_PTE	(X_NO_HOST_RA | X_GUEST_PTE | X_NO_FINAL_RA)
#define NESTED_PTE	(X_HOST_RA | X_GUEST_PTE | X_NO_FINAL_RA)
#define PARTITION_PTE	(X_HOST_RA | X_NO_GUEST_PTE | X_NO_FINAL_RA)

#define NESTED_RA_ADDR	(X_HOST_RA | X_FINAL_RA | X_GUEST_PTE)
#define PROCESS_RA_ADDR	(X_NO_HOST_RA | X_FINAL_RA | X_GUEST_PTE)

static bool xlate_parser_check_walk(struct htm_insn_walk *walk, uint32_t flags)
{
	if ((X_ENABLED(flags) & X_FINAL_RA) &&
	    !!(X_VALUE(flags) & X_FINAL_RA) != walk->final_ra)
		return false;

	if ((X_ENABLED(flags) & X_GUEST_PTE) &&
	    !!(X_VALUE(flags) & X_GUEST_PTE) != walk->guest_pte)
		return false;

	if ((X_ENABLED(flags) & X_HOST_RA) &&
	    !!(X_VALUE(flags) & X_HOST_RA) != walk->host_ra)
		return false;

	if ((flags & _X_LEVEL) && ((flags & X_LEVEL_MASK) != walk->level))
		return false;
	return true;
}

/*
 * Check if the current walk matches flags. On a match return the current
 * walk and advance the parser to the next walk.
 */
static struct htm_insn_walk *xlate_parser_take(struct xlate_parser *parser,
					       uint32_t flags)
{
	struct htm_insn_walk *walk;

	if (!parser->xlate)
		return NULL;

	if (parser->i >= parser->xlate->nwalks)
		return NULL;

	walk = parser->xlate->walks + parser->i;

	if (!xlate_parser_check_walk(walk, flags))
		return NULL;

	parser->i++;
	return walk;
}

/*
 * Check if the current walk matches flags but do not advance the parser.
 */
static struct htm_insn_walk *xlate_parser_peek(struct xlate_parser *parser,
					       uint32_t flags)
{
	struct htm_insn_walk *walk;

	if (!parser->xlate)
		return NULL;

	if (parser->i >= parser->xlate->nwalks)
		return NULL;

	walk = parser->xlate->walks + parser->i;

	if (!xlate_parser_check_walk(walk, flags))
		return NULL;

	return walk;
}

/*
 * Check for a match for flags in the remaining walks.
 */
static struct htm_insn_walk *xlate_parser_scan(struct xlate_parser *parser,
					       uint32_t flags)
{
	struct htm_insn_walk *walk;
	int i;

	walk = NULL;

	if (!parser->xlate)
		return NULL;

	for (i = parser->i; i < parser->xlate->nwalks; i++) {

		walk = parser->xlate->walks + i;

		if (!xlate_parser_check_walk(walk, flags))
			continue;

		return walk;
	}

	return NULL;
}

static struct xlate_address mk_process_real_addr(unsigned int lpid,
						 uint64_t address)
{
	struct xlate_address addr = {
		MSR_HV,
		lpid,
		0,
		address
	};
	return addr;
}

/*
 * If the next walk is a for a process PTE then partition scoped translation is
 * finished and hence the current walk is a leaf.
 */
static int xlate_partition_pte_is_leaf(struct xlate_parser *parser, int level,
				       bool *leaf)
{
	if (xlate_parser_peek(parser, X_GUEST_PTE)) {
		*leaf = true;
		if (level < PTE_LEVEL_1) {
			return 0;
		}
		return -1;
	}
	if (xlate_parser_peek(parser, X_FINAL_RA)) {
		*leaf = true;
		if (level < PTE_LEVEL_1) {
			return 0;
		}
		return -1;
	}
	*leaf = false;
	return 0;
}

/*
 * A radix walk is sent resuming from the lowest PTE level that is not cached.
 * If there are lower PTE levels still in the walk then can not be a leaf.
 */
static int xlate_process_pte_is_leaf(struct xlate_parser *parser, int level,
				     bool *leaf)
{
	for (int i = 0; i < NELEM(levels); i++) {
		if (levels[i] == level)
			break;
		if (xlate_parser_scan(parser,
				      X_NO_FINAL_RA | X_GUEST_PTE |
				      X_LEVEL(levels[i]))) {
			*leaf = false;
			return 0;
		}
	}

	*leaf = true;
	if (level < PTE_LEVEL_2) {
		return 0;
	}

	return -1;
}

/*
 * We want to distinguish between a 4K page table and a 64K page table.
 * The htm trace does not make this distinction giving them both level 0.
 * The 64K and 4K pages themselves are differentiated, so by looking ahead the
 * page table size can be determined.
 */
static int xlate_partition_pte_subtype(struct xlate_parser *parser, int final,
				       int *subtype)
{
	/* XXX: This won't work on nested PTE translations. */
	if (final &&
	    xlate_parser_scan(parser, NESTED_RA_ADDR | X_LEVEL(HTM_FINAL_4K))) {
		*subtype = XLATE_4K_PTE;
		return 0;
	}
	if (final &&
	    xlate_parser_scan(parser, NESTED_RA_ADDR | X_LEVEL(HTM_FINAL_64K))) {
		*subtype = XLATE_64K_PTE;
		return 0;
	}
	return -1;
}

static int xlate_process_pte_subtype(struct xlate_parser *parser, int *subtype)
{
	if (xlate_parser_scan(parser,
			      PROCESS_RA_ADDR | X_LEVEL(HTM_FINAL_4K))) {
		*subtype = XLATE_4K_PTE;
		return 0;
	}
	if (xlate_parser_scan(parser,
			      PROCESS_RA_ADDR | X_LEVEL(HTM_FINAL_64K))) {
		*subtype = XLATE_64K_PTE;
		return 0;
	}
	return -1;
}



static int xlate_partition_subtype(struct xlate_parser *parser, int type,
				   int *subtype)
{
	if (type == XLATE_PTE)
		return xlate_partition_pte_subtype(parser, 1, subtype);

	*subtype = type;
	return 0;
}

static int xlate_process_subtype(struct xlate_parser *parser, int type,
				 int *subtype)
{
	if (type == XLATE_PTE)
		return xlate_process_pte_subtype(parser, subtype);

	*subtype = type;
	return 0;
}

static int xlate_decode_process_pte(struct xlate_parser *parser, int type,
				    struct xlate_address addr,
				    struct xlate_pte *pte)
{
	struct htm_insn_walk *walk;
	uint64_t flags;
	int subtype = type;
	int level;

	level = xlate_htm_levels[type];

	walk = xlate_parser_take(parser, PROCESS_PTE | X_LEVEL(level));
	if (walk) {
		bool leaf;

		if (xlate_process_pte_is_leaf(parser, level, &leaf) < 0)
			return -1;
		if (xlate_process_subtype(parser, type, &subtype) < 0)
			return -1;

		pwc_insert(subtype, addr, walk->ra_address, leaf);
		goto out;
	}

	for (int i = 0; i < xlate_pte_subtypes[type].n; i++) {
		uint64_t real_address;
		int ret;

		subtype = xlate_pte_subtypes[type].types[i];
		ret = pwc_get(subtype, addr, &real_address, &flags);
		if (ret < 0)
			continue;

		if (flags & (PWC_LEAF | PWC_NOT_LEAF))
			goto out;

		if (xlate_parser_peek(parser, NESTED_PTE | X_LEVEL(level))) {
			bool leaf;

			if (xlate_process_pte_is_leaf(parser, level, &leaf) < 0)
				return -1;
			pwc_insert(subtype, addr, real_address, leaf);
			goto out;
		}
	}

out:
	if (pwc_get(subtype, addr, &pte->address, &flags) < 0)
		return -1;

	pte->leaf = (flags & PWC_LEAF) ? 1 : 0;
	pte->page_size = xlate_pte_pagesizes[subtype];

	return 0;
}

static int xlate_decode_partition_pte(struct xlate_parser *parser, int type,
				      struct xlate_address addr,
				      struct xlate_pte *pte)
{
	struct htm_insn_walk *walk;
	uint64_t flags;
	int subtype;
	int level;

	level = xlate_htm_levels[type];

	walk = xlate_parser_take(parser, PARTITION_PTE | X_LEVEL(level));
	if (walk) {
		bool leaf;

		if (xlate_partition_pte_is_leaf(parser, level, &leaf) < 0)
			return -1;
		if (xlate_partition_subtype(parser, type, &subtype) < 0)
			return -1;

		pwc_insert(subtype, addr, walk->ra_address, leaf);
		goto out;
	}

	for (int i = 0; i < xlate_pte_subtypes[type].n; i++) {
		uint64_t real_address;
		bool leaf;
		int ret;

		subtype = xlate_pte_subtypes[type].types[i];
		ret = pwc_get(subtype, addr, &real_address, &flags);
		if (ret < 0)
			continue;

		if (flags & (PWC_LEAF | PWC_NOT_LEAF))
			goto out;

		if (xlate_partition_pte_is_leaf(parser, level, &leaf) < 0)
			return -1;
		pwc_insert(subtype, addr, real_address, leaf);
		goto out;
	}
	return -1;

out:
	if (pwc_get(subtype, addr, &pte->address, &flags) < 0)
		return -1;

	pte->leaf = (flags & PWC_LEAF) ? 1 : 0;
	pte->page_size = xlate_pte_pagesizes[subtype];

	return 0;
}

static int xlate_partition_pgdp(struct xlate_parser *parser,
				struct xlate_address addr,
				struct xlate_pte *pte)
{
	return xlate_decode_partition_pte(parser, XLATE_PGD, addr, pte);
}

static int xlate_partition_pudp(struct xlate_parser *parser,
				struct xlate_address addr,
				struct xlate_pte *pte)
{
	return xlate_decode_partition_pte(parser, XLATE_PUD, addr, pte);
}

static int xlate_partition_pmdp(struct xlate_parser *parser,
				struct xlate_address addr,
				struct xlate_pte *pte)
{
	return xlate_decode_partition_pte(parser, XLATE_PMD, addr, pte);
}

static int xlate_partition_ptep(struct xlate_parser *parser,
				struct xlate_address addr,
				struct xlate_pte *pte, int final)
{
	return xlate_decode_partition_pte(parser, XLATE_PTE, addr, pte);
}

static int xlate_partition_real_addr(struct xlate_parser *parser, uint32_t flag,
				     struct xlate_address addr,
				     unsigned int page_size,
				     uint64_t *real_address)
{
	struct htm_insn_walk *walk;
	uint64_t partition_real_address;

	walk = xlate_parser_take(parser, flag);
	if (walk) {
		partition_real_address = walk->ra_address;
		pwc_tlb_insert(page_size, addr, partition_real_address);
	} else {
		if (!pwc_tlb_get(page_size, addr, &partition_real_address))
			return -1;
	}

	*real_address = partition_real_address;
	return 0;
}


static int xlate_partition_translate(struct xlate_parser *parser, uint32_t flag,
				     struct xlate_address addr,
				     uint64_t *partion_real_addressp,
				     uint64_t host_ptes[], int *nr_ptes,
				     unsigned int *page_size)
{
	struct xlate_pte pte = { 0 };
	uint64_t partition_real_address;
	int ret;

	ret = xlate_partition_pgdp(parser, addr, &pte);
	if (ret < 0)
		return -1;

	host_ptes[0] = pte.address;

	ret = xlate_partition_pudp(parser, addr, &pte);
	if (ret < 0)
		return -1;

	host_ptes[1] = pte.address;

	if (pte.leaf) {
		*nr_ptes = 2;
		goto final;
	}

	ret = xlate_partition_pmdp(parser, addr, &pte);
	if (ret < 0)
		return -1;

	host_ptes[2] = pte.address;

	if (pte.leaf) {
		*nr_ptes = 3;
		goto final;
	}

	ret = xlate_partition_ptep(parser, addr, &pte, flag & X_FINAL_RA);
	if (ret < 0)
		return -1;

	host_ptes[3] = pte.address;
	*nr_ptes = 4;

final:
	*page_size = pte.page_size;
	ret = xlate_partition_real_addr(parser, flag, addr, *page_size,
					&partition_real_address);
	if (ret < 0)
		return -1;

	*partion_real_addressp = partition_real_address;
	return 0;
}

static int xlate_nested_real_addr(struct xlate_parser *parser,
				  struct xlate_address addr,
				  uint64_t *real_address, uint64_t host_ptes[],
				  int *nr_ptes, unsigned int *page_size)
{
	return xlate_partition_translate(parser,
					 X_HOST_RA | X_GUEST_PTE | X_FINAL_RA,
					 addr, real_address, host_ptes, nr_ptes,
					 page_size);
}

static int xlate_nested_process_table(struct xlate_parser *parser,
				      struct xlate_address addr)
{
	uint64_t host_ptes[4];
	uint64_t real_address;
	unsigned int page_size;
	int nr_ptes;

	return xlate_partition_translate(parser, NESTED_PTE | X_LEVEL(7),
					 addr, &real_address, host_ptes,
					 &nr_ptes, &page_size);
}

static int xlate_nested_pgdp(struct xlate_parser *parser,
			     struct xlate_address addr,
			     uint64_t *real_address, uint64_t host_ptes[],
			     int *nr_ptes)
{
	unsigned int page_size;

	return xlate_partition_translate(parser,
					 NESTED_PTE | X_LEVEL(PTE_LEVEL_1),
					 addr, real_address, host_ptes, nr_ptes,
					 &page_size);
}

static int xlate_nested_pudp(struct xlate_parser *parser,
			     struct xlate_address addr,
			     uint64_t *real_address, uint64_t host_ptes[],
			     int *nr_ptes)
{
	unsigned int page_size;

	return xlate_partition_translate(parser,
					 NESTED_PTE | X_LEVEL(PTE_LEVEL_2),
					 addr, real_address, host_ptes, nr_ptes,
					 &page_size);
}

static int xlate_nested_pmdp(struct xlate_parser *parser,
			     struct xlate_address addr,
			     uint64_t *real_address, uint64_t host_ptes[],
			     int *nr_ptes)
{
	unsigned int page_size;

	return xlate_partition_translate(parser,
					 NESTED_PTE | X_LEVEL(PTE_LEVEL_3),
					 addr, real_address, host_ptes, nr_ptes,
					 &page_size);
}

static int xlate_nested_ptep(struct xlate_parser *parser,
			     struct xlate_address addr,
			     uint64_t *real_address, uint64_t host_ptes[],
			     int *nr_ptes)
{
	unsigned int page_size;

	return xlate_partition_translate(parser, NESTED_PTE | X_LEVEL(0),
					 addr, real_address, host_ptes, nr_ptes,
					 &page_size);
}


static int xlate_process_pgdp(struct xlate_parser *parser,
			      struct xlate_address addr,
			      struct xlate_pte *pte)
{
	return xlate_decode_process_pte(parser, XLATE_PGD, addr, pte);
}

static int xlate_process_pudp(struct xlate_parser *parser,
			      struct xlate_address addr,
			      struct xlate_pte *pte)
{
	return xlate_decode_process_pte(parser, XLATE_PUD, addr, pte);
}


static int xlate_process_pmdp(struct xlate_parser *parser,
			      struct xlate_address addr,
			      struct xlate_pte *pte)
{
	return xlate_decode_process_pte(parser, XLATE_PMD, addr, pte);
}

static uint64_t xlate_process_ptep(struct xlate_parser *parser,
				   struct xlate_address addr,
				   struct xlate_pte *pte)
{
	return xlate_decode_process_pte(parser, XLATE_PTE, addr, pte);
}

static int xlate_process_real_addr(struct xlate_parser *parser,
				   struct xlate_address addr,
				   uint64_t partition_real_address,
				   unsigned int guest_page_size,
				   uint64_t *process_real_addressp)
{
	uint64_t process_real_address;
	struct htm_insn_walk *walk;

	walk = xlate_parser_take(parser, X_NO_HOST_RA | X_GUEST_PTE | X_FINAL_RA);
	if (walk) {
		process_real_address = walk->ra_address;
		pwc_tlb_insert(guest_page_size, addr, process_real_address);
		*process_real_addressp = process_real_address;
		return 0;
	}

	return -1;
}

static int xlate_decode_nested_radix(struct xlate_parser *parser,
				     struct xlate_address addr,
				     uint64_t real_address, struct qtrace_radix *rec,
				     uint64_t *real_addressp,
				     uint32_t *host_page_shiftp,
				     uint32_t *guest_page_shiftp)
{
	unsigned int guest_page_size, host_page_size;
	struct xlate_address process_real_addr;
	struct xlate_pte pte = { 0 };
	int nr_ptes[MAX_RADIX_WALKS] = { 0 };
	struct htm_insn_walk *walk;
	uint64_t calculated_host_real_address;
	int ret;

	xlate_parser_take(parser, X_HOST_RA | X_NO_GUEST_PTE | X_LEVEL(7));

	walk = xlate_parser_take(parser, X_GUEST_PTE | X_LEVEL(7));
	if (walk) {
		process_real_addr = mk_process_real_addr(addr.lpid, walk->ra_address);
		xlate_nested_process_table(parser, process_real_addr);
	}

	ret = xlate_process_pgdp(parser, addr, &pte);
	if (ret < 0)
		return -1;

	rec->guest_real_addrs[0] = pte.address;

	process_real_addr = mk_process_real_addr(addr.lpid, rec->guest_real_addrs[0]);
	ret = xlate_nested_pgdp(parser, process_real_addr,
				&rec->host_real_addrs[0], rec->host_ptes[0],
				&nr_ptes[0]);
	if (ret < 0)
		return -1;

	ret = xlate_process_pudp(parser, addr, &pte);
	if (ret < 0)
		return -1;

	rec->guest_real_addrs[1] = pte.address;

	process_real_addr = mk_process_real_addr(addr.lpid, rec->guest_real_addrs[1]);
	ret = xlate_nested_pudp(parser, process_real_addr,
				&rec->host_real_addrs[1], rec->host_ptes[1],
				&nr_ptes[1]);
	if (ret < 0)
		return -1;

	ret = xlate_process_pmdp(parser, addr, &pte);
	if (ret < 0)
		return -1;

	rec->guest_real_addrs[2] = pte.address;

	process_real_addr = mk_process_real_addr(addr.lpid, rec->guest_real_addrs[2]);
	ret = xlate_nested_pmdp(parser, process_real_addr,
				&rec->host_real_addrs[2], rec->host_ptes[2],
				&nr_ptes[2]);
	if (ret < 0)
		return -1;

	if (pte.leaf) {
		guest_page_size = pte.page_size;
		ret = xlate_process_real_addr(parser, addr, real_address, guest_page_size,
					      &rec->guest_real_addrs[3]);
		if (ret < 0)
			return -1;

		process_real_addr = mk_process_real_addr(addr.lpid, rec->guest_real_addrs[3]);
		ret = xlate_nested_real_addr(parser, process_real_addr,
					     &calculated_host_real_address, rec->host_ptes[3],
					     &nr_ptes[3], &host_page_size);
		if (ret < 0)
			return -1;

		rec->nr_pte_walks = 4;
	} else {
		ret = xlate_process_ptep(parser, addr, &pte);
		if (ret < 0)
			return -1;

		rec->guest_real_addrs[3] = pte.address;
		guest_page_size = pte.page_size;

		process_real_addr = mk_process_real_addr(addr.lpid, rec->guest_real_addrs[3]);
		ret = xlate_nested_ptep(parser, process_real_addr,
					&rec->host_real_addrs[3],
					rec->host_ptes[3], &nr_ptes[3]);
		if (ret < 0)
			return -1;

		ret = xlate_process_real_addr(parser, addr, real_address, guest_page_size,
					      &rec->guest_real_addrs[4]);
		if (ret < 0)
			return -1;

		process_real_addr = mk_process_real_addr(addr.lpid, rec->guest_real_addrs[4]);
		ret = xlate_nested_real_addr(parser, process_real_addr,
					     &calculated_host_real_address, rec->host_ptes[4],
					     &nr_ptes[4],
					     &host_page_size);
		if (ret < 0)
			return -1;

		rec->nr_pte_walks = 5;
	}

	*host_page_shiftp = host_page_size;
	*guest_page_shiftp = guest_page_size;
	rec->nr_ptes = int_array_max(nr_ptes, MAX_RADIX_WALKS);
	*real_addressp = calculated_host_real_address;
	return 0;
}

static int xlate_decode_guest_real(struct xlate_parser *parser,
				   struct xlate_address addr,
				   struct qtrace_radix *rec,
				   uint32_t *host_page_shiftp)
{
	uint64_t host_ra;
	int nr_ptes;
	int ret;

	rec->nr_pte_walks = 1;
	rec->type = GUEST_REAL;
	ret = xlate_partition_translate(parser, X_HOST_RA, addr, &host_ra,
					rec->host_ptes[0], &nr_ptes,
					host_page_shiftp);
	if (ret < 0) {
		return -1;
	}

	rec->nr_ptes = nr_ptes;

	return 0;
}

int xlate_lookup(struct htm_insn_msr *msr,
		 bool relocation,
		 uint64_t address, uint64_t real_address,
		 struct qtrace_radix *rec, uint32_t *host_page_shiftp,
		 uint32_t *guest_page_shiftp)
{
	memset(rec, 0, sizeof(*rec));
	*host_page_shiftp = 0;
	*guest_page_shiftp = 0;

	if (!msr->msrhv && relocation) {
		for (int i = 0; i < NELEM(host_page_sizes); i++) {
			if (erat_get(host_page_sizes[i], address,
				     real_address, rec, host_page_shiftp, guest_page_shiftp)) {
				rec->guest_real_addrs[rec->nr_pte_walks - 1] &= ~((1ull << *guest_page_shiftp) - 1);
				rec->guest_real_addrs[rec->nr_pte_walks - 1] |= address & ((1ull << *guest_page_shiftp) - 1);


				return 0;
			}
		}
		return -1;
	}

	if (!msr->msrhv && !relocation) {
		*host_page_shiftp = 0;
		*guest_page_shiftp = 0;
		for (int i = 0; i < NELEM(host_page_sizes); i++) {
			if (erat_get(host_page_sizes[i], address,
				     real_address, rec, host_page_shiftp, guest_page_shiftp)) {
				*guest_page_shiftp = 0;
				return 0;
			}
		}
		return -1;
	}
	return 0;
}

int xlate_decode(struct htm_insn_xlate *xlate, struct htm_insn_msr *msr,
		 bool relocation,
		 uint64_t address, uint64_t real_address,
		 struct qtrace_radix *rec, uint32_t *host_page_shiftp,
		 uint32_t *guest_page_shiftp)
{
	struct htm_insn_xlate merged_xlate = { 0 };
	struct xlate_parser parser;
	int ret;

	memset(rec, 0, sizeof(*rec));
	*host_page_shiftp = 0;
	*guest_page_shiftp = 0;

	if (pwc_partial_lookup(&merged_xlate, xlate)) {
		xlate = &merged_xlate;
	}

	xlate_parser_init(&parser, xlate);

	if (msr->msrhv && relocation) {
		/* Partition Scoped Only */
		fprintf(stderr, "Hypervisor Partition Scoped not handled\n");
		assert(0);
	} else if (!msr->msrhv && relocation) {
		struct xlate_address addr;
		uint64_t host_ra;

		addr = mk_xlate_addr(0, xlate->lpid, xlate->pid, address);
		ret = xlate_decode_nested_radix(&parser, addr, real_address, rec,
						&host_ra, host_page_shiftp,
						guest_page_shiftp);
		if (ret < 0) {
			goto err;
		}

		assert((host_ra & ~((1ull<<12)-1)) == (real_address));

		erat_insert(*host_page_shiftp, address, real_address, rec,
				*guest_page_shiftp);
	} else if (msr->msrhv && !relocation) {
		/* Hypervisor Real Mode */
		;
	} else {
		 /* Supervisor Real */
		struct xlate_address addr;

		addr = mk_xlate_addr(0, xlate->lpid, xlate->pid, address);
		ret = xlate_decode_guest_real(&parser, addr, rec,
					      host_page_shiftp);
		if (ret < 0) {
			goto err;
		}

		erat_insert(*host_page_shiftp, address, real_address, rec,
			    *host_page_shiftp);
	}

	if (parser.i != (!parser.xlate ? 0 : parser.xlate->nwalks)) {
		goto err;
	}

	return 0;

err:
	memset(rec, 0, sizeof(*rec));
	*host_page_shiftp = 0;
	*guest_page_shiftp = 0;
	return -1;
}

void xlate_init(void)
{
	pwc_init();
	erat_init();
}
