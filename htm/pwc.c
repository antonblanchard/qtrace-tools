/*
 * Page Walk Cache (pwc) simulates the operation of the hardware Radix MMU to
 * track the complete radix walk for addresses. When memory accesses are
 * performed over the course of a HTM trace the hardware combined PWC/TLB
 * caches are primed and fewer XLATE records are in the trace. pwc "fills in
 * the blanks" so every memory access can include the entire radix walk for
 * qtrace output.
 *
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
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>

#include "ccan/hash/hash.h"
#include "ccan/htable/htable_type.h"
#include <ccan/list/list.h>

#include "pwc.h"
#include "xlate.h"

// #define DEBUG

#ifdef DEBUG
#define DBG(A...) fprintf(stderr, "pwc: " A)
#else
#define DBG(A...) do { } while(0)
#endif

/*
 * pde_obj is the key/value pair used by htable_pde.
 */
struct pde_obj {
	uint64_t offset; /* Offset within a Page Directory */
	bool leaf; /* Page Table Entry or a Page Directory Entry? */
};


static struct pde_obj *new_pde_obj(uint64_t offset, bool leaf)
{
	struct pde_obj *obj;

	obj = calloc(1, sizeof(*obj));
	if (!obj) {
		perror("calloc");
		exit(1);
	}

	obj->offset = offset;
	obj->leaf = leaf;

	return obj;
}

static const uint64_t *pde_obj_key(const struct pde_obj *e)
{
	return &e->offset;
}

static size_t pde_obj_hash(const uint64_t *key)
{
	return hash64(key, 1, 0);
}

static bool pde_obj_cmp(const struct pde_obj *e, const uint64_t *key)
{
	return e->offset == *key;
}

/*
 * htable_pde tracks which entries in a Page Directory are Page Table Entries
 * and which are Page Directory Entries.
 *
 * This is necessary as page directory may contain a mixture of PTEs and PDEs.
 */
HTABLE_DEFINE_TYPE(struct pde_obj, pde_obj_key, pde_obj_hash, pde_obj_cmp,
		   htable_pde);

/*
 * page_walk_cache_key is the key for htable_pwc.
 * When used for Page Directories level is the page directory level.
 * When used for RPNs level is the page size.
 */
struct page_walk_cache_key {
	int level; /* RPNs: page size. PDE/PTEs: page directory level. */
	struct xlate_address addr; /* Fully Qualified Address. */
};

/*
 * page_walk_cache_val is the value for htable_pwc.
 */
struct page_walk_cache_val {
	uint64_t real_address; /* Real address of the Page Directory/Table. */
	struct htable_pde pde_leaf_map; /* Which entries are leafs. */
};

struct page_walk_obj {
	struct page_walk_cache_key key;
	struct page_walk_cache_val val;
};


static struct page_walk_obj *new_page_walk_obj(int level, int msr,
					       unsigned int lpid,
					       unsigned int pid,
					       uint64_t address,
					       uint64_t real_address)
{
	struct page_walk_obj *obj;

	obj = calloc(1, sizeof(*obj));
	if (!obj) {
		perror("calloc");
		exit(1);
	}

	obj->key.level = level;
	obj->key.addr.lpid = lpid;
	obj->key.addr.msr = msr;
	obj->key.addr.pid = pid;
	obj->key.addr.address = address;
	obj->val.real_address = real_address;

	return obj;
}

static const struct page_walk_cache_key *page_walk_obj_key(const struct page_walk_obj *e)
{
	return &e->key;
}

static size_t page_walk_obj_hash(const struct page_walk_cache_key *key)
{
	return hash64(key, 1, 0);
}

static bool page_walk_obj_cmp(const struct page_walk_obj *e,
			      const struct page_walk_cache_key *key)
{
	return (e->key.addr.address == key->addr.address) &&
	       (e->key.level == key->level) &&
	       (e->key.addr.lpid == key->addr.lpid) &&
	       (e->key.addr.pid == key->addr.pid) &&
	       (e->key.addr.msr == key->addr.msr);
}

/*
 * htable_pwc maps a fully qualified address and page directory level to the
 * real address of a Page Directory/Entry Entry.
 *
 * It is also used to map effective page numbers to real page numbers.
 *
 * For the Page Directory/Entry use case it also tracks which entries are
 * leafs.
 */
HTABLE_DEFINE_TYPE(struct page_walk_obj, page_walk_obj_key, page_walk_obj_hash,
		   page_walk_obj_cmp,
		   htable_pwc);

/* page_walk_cache is the cache for Page Directory/Table Entries for a trace. */
static struct htable_pwc page_walk_cache;

/* tlb_cache is the cache for RPNs for a trace. */
static struct htable_pwc tlb_cache;

/*
 * pwc_tlb_insert() creates an entry in tlb_cache mapping the effective page
 * number from addr of level size to a RPN.
 */
void pwc_tlb_insert(int level, struct xlate_address addr,
		    uint64_t real_address)
{
	struct page_walk_obj *new_obj, *old_obj;
	uint64_t page_address, rpn;

	switch (level) {
	case 12:
		page_address = pte_address_4k(addr.address);
		rpn = pte_address_4k(real_address);
		break;
	case 16:
		page_address = pte_address_64k(addr.address);
		rpn = pte_address_64k(real_address);
		break;
	case 21:
		page_address = pte_address_2m(addr.address);
		rpn = pte_address_2m(real_address);
		break;
	case 30:
		page_address = pte_address_1g(addr.address);
		rpn = pte_address_1g(real_address);
		break;
	default:
		assert(0);
	}

	new_obj = new_page_walk_obj(level, addr.msr, addr.lpid, addr.pid,
				 page_address, rpn);

	old_obj = htable_pwc_get(&tlb_cache, &new_obj->key);
	if (old_obj) {
		old_obj->val.real_address = new_obj->val.real_address;
		free(new_obj);
	} else {
		htable_pwc_add(&tlb_cache, new_obj);
	}
}

/*
 * pwc_tlb_get() looks up a RPN from the EPN from addr of level size in
 * tlb_cache. Returns true if present in tlb_cache and returns the real address
 * combining the RPN and page offset in real_address. Otherwise returns false.
 */
bool pwc_tlb_get(int level, struct xlate_address addr,
		 uint64_t *real_address)
{
	struct page_walk_cache_key key = { 0 };
	uint64_t offset, page_address;
	struct page_walk_obj *obj;

	switch (level) {
	case 12:
		page_address = pte_address_4k(addr.address);
		offset = page_offset_4k(addr.address);
		break;
	case 16:
		page_address = pte_address_64k(addr.address);
		offset = page_offset_64k(addr.address);
		break;
	case 21:
		page_address = pte_address_2m(addr.address);
		offset = page_offset_2m(addr.address);
		break;
	case 30:
		page_address = pte_address_1g(addr.address);
		offset = page_offset_1g(addr.address);
		break;
	default:
		assert(0);
	}

	key.level = level;
	key.addr.lpid = addr.lpid;
	key.addr.pid = addr.pid;
	key.addr.address = page_address;
	key.addr.msr = addr.msr;

	obj = htable_pwc_get(&tlb_cache, &key);

	if (!obj)
		return false;

	*real_address = obj->val.real_address + offset;
	return true;
}

/*
 * pwc_insert() creates an entry in page_walk_cache tracking the real address of
 * given level page directory of a fully qualified address. It tracks if that
 * entry is a leaf node.
 */
void pwc_insert(int level, struct xlate_address addr,
		uint64_t real_address, bool leaf)
{
	struct page_walk_obj *new_obj, *old_obj;
	uint64_t offset, page_address;

	switch (level) {
	case XLATE_PGD:
		page_address = pgd_address(addr.address);
		offset = pgd_index(addr.address);
		break;
	case XLATE_PUD:
		page_address = pgdp_address(addr.address);
		offset = pud_index(addr.address);
		break;
	case XLATE_PMD:
		page_address = pudp_address(addr.address);
		offset = pmd_index(addr.address);
		break;
	case XLATE_64K_PTE:
		page_address = pmdp_address(addr.address);
		offset = page_table_index_64k(addr.address);
		break;
	case XLATE_4K_PTE:
		page_address = pmdp_address(addr.address);
		offset = page_table_index_4k(addr.address);
		break;
	default:
		assert(0);
	}

	new_obj = new_page_walk_obj(level, addr.msr, addr.lpid, addr.pid,
				 page_address, real_address - offset);

	old_obj = htable_pwc_get(&page_walk_cache, &new_obj->key);
	if (old_obj) {
		struct pde_obj *pde;

		old_obj->val.real_address = new_obj->val.real_address;
		pde = htable_pde_get(&(old_obj->val.pde_leaf_map), &offset);
		if (pde) {
			pde->leaf = leaf;
		} else {
			htable_pde_add(&(old_obj->val.pde_leaf_map),
				       new_pde_obj(offset, leaf));
		}
		free(new_obj);
	} else {
		htable_pde_init(&(new_obj->val.pde_leaf_map));
		htable_pde_add(&new_obj->val.pde_leaf_map,
			       new_pde_obj(offset, leaf));
		htable_pwc_add(&page_walk_cache, new_obj);
	}

}

/*
 * pwc_get() looks up the entry for level of page directory of a fully qualified
 * address in page_walk_cache. Return 0 if found and return the real address of
 * the entry in real_address. If the entry is known to be or not be a leaf
 * return that in flags. If only the Page Directory containing the entry if
 * found return 0 in flags.
 *
 * Return -1 if the entry is not found.
 */
int pwc_get(int level, struct xlate_address addr, uint64_t *real_address,
	    uint64_t *flags)
{
	struct page_walk_cache_key key = { 0 };
	uint64_t offset, page_address;
	struct page_walk_obj *obj;
	struct pde_obj *pde;

	switch (level) {
	case XLATE_PGD:
		page_address = pgd_address(addr.address);
		offset = pgd_index(addr.address);
		break;
	case XLATE_PUD:
		page_address = pgdp_address(addr.address);
		offset = pud_index(addr.address);
		break;
	case XLATE_PMD:
		page_address = pudp_address(addr.address);
		offset = pmd_index(addr.address);
		break;
	case XLATE_64K_PTE:
		page_address = pmdp_address(addr.address);
		offset = page_table_index_64k(addr.address);
		break;
	case XLATE_4K_PTE:
		page_address = pmdp_address(addr.address);
		offset = page_table_index_4k(addr.address);
		break;
	default:
		assert(0);
	}

	key.level = level;
	key.addr.lpid = addr.lpid;
	key.addr.pid = addr.pid;
	key.addr.address = page_address;
	key.addr.msr = addr.msr;


	obj = htable_pwc_get(&page_walk_cache, &key);

	if (!obj)
		return -1;

	*real_address = obj->val.real_address + offset;

	pde = htable_pde_get(&obj->val.pde_leaf_map, &offset);
	if (pde)
		*flags = pde->leaf ? PWC_LEAF : PWC_NOT_LEAF;
	else
		*flags = 0;

	return 0;
}

/*
 * reverse_walk_cache maps host real address to guest real addresses. This is
 * necessary is there are instances in the HTM trace where a walk resumes from
 * the host real address of a process scoped PDE without including the guest
 * real address.
 */
static struct htable_pwc reverse_walk_cache;

/*
 * pwc_reverse_insert() creates an entry in reverse_walk_cache mapping a host
 * RPN of size level to a guest RPN.
 */
void pwc_reverse_insert(int level, struct xlate_address addr,
			uint64_t guest_real_address)
{
	struct page_walk_obj *new_obj, *old_obj;
	uint64_t host_rpn, guest_rpn;

	switch (level) {
	case 12:
		host_rpn = pte_address_4k(addr.address);
		guest_rpn = pte_address_4k(guest_real_address);
		break;
	case 16:
		host_rpn = pte_address_64k(addr.address);
		guest_rpn = pte_address_64k(guest_real_address);
		break;
	case 21:
		host_rpn = pte_address_2m(addr.address);
		guest_rpn = pte_address_2m(guest_real_address);
		break;
	case 30:
		host_rpn = pte_address_1g(addr.address);
		guest_rpn = pte_address_1g(guest_real_address);
		break;
	default:
		assert(0);
	}

	new_obj = new_page_walk_obj(level, addr.msr, addr.lpid, addr.pid, host_rpn,
				 guest_rpn);

	old_obj = htable_pwc_get(&reverse_walk_cache, &new_obj->key);
	if (old_obj) {
		old_obj->val.real_address = new_obj->val.real_address;
		free(new_obj);
	} else {
		htable_pwc_add(&reverse_walk_cache, new_obj);
	}
}

/*
 * pwc_reverse_get() looks up the guest_real_address corresponding to a host RPN
 * in reverse_walk_cache. Returns true and the guest real address in
 * guest_real_address if found. Otherwise false.
 */
bool pwc_reverse_get(int level, struct xlate_address addr,
		     uint64_t *guest_real_address)
{
	struct page_walk_cache_key key = { 0 };
	struct page_walk_obj *obj;
	uint64_t offset, rpn;

	switch (level) {
	case 12:
		/* 4 K Pages */
		offset = page_offset_4k(addr.address);
		rpn = pte_address_4k(addr.address);
		break;
	case 16:
		/* 64 K Pages */
		offset = page_offset_64k(addr.address);
		rpn = pte_address_64k(addr.address);
		break;
	case 21:
		/* 2M Pages */
		offset = page_offset_2m(addr.address);
		rpn = pte_address_2m(addr.address);
		break;
	case 30:
		/* 1G Pages */
		offset = page_offset_1g(addr.address);
		rpn = pte_address_1g(addr.address);
		break;
	default:
		assert(0);
	}

	key.level = level;
	key.addr.lpid = addr.lpid;
	key.addr.pid = addr.pid;
	key.addr.address = rpn;
	key.addr.msr = addr.msr;

	obj = htable_pwc_get(&reverse_walk_cache, &key);

	if (!obj)
		return false;

	*guest_real_address = obj->val.real_address + offset;
	return true;
}

/*
 * partial_cache_list is a linked link of fragments of interrupted HTM XLATE
 * records.
 */
struct partial_cache_list {
	struct list_head nodes;
	unsigned int nnodes;
};

/*
 * partial_cache_node is an entry in the partial_cache_list list.
 */
struct partial_cache_node {
	struct htm_insn_xlate walk;
	struct list_node list;
};

/*
 * partial_cache contains the currently unused HTM XLATE fragments encountered
 * during a trace.
 */
static struct partial_cache_list partial_cache;

/*
 * xlate_merge() combines two partial htm_insn_xlate records, old and new, into
 * combined. The actual merge is done in a temporary htm_insn_xlate so it is
 * safe to pass e.g. old in as combined.
 *
 * The merge relies on old and new overlapping and sharing a walk record.
 * combined is filled with the walks from old until that overlap and then the
 * walks from new are used.
 *
 * Returns 0 on success and -1 on failure.
 */
static int xlate_merge(struct htm_insn_xlate *combined,
		       struct htm_insn_xlate *old,
		       struct htm_insn_xlate *new)
{
	struct htm_insn_xlate temp = { 0 };
	int i, j;

	assert(old->lpid == new->lpid);
	assert(old->pid == new->pid);

	temp.d_side = old->d_side;
	temp.lpid = old->lpid;
	temp.pid = old->pid;

	i = j = 0;
	while (i < old->nwalks) {
		if (old->walks[i].ra_address == new->walks[0].ra_address)
			break;

		if (old->walks[i].exception) {
			break;
		}

		temp.walks[i] = old->walks[i];
		i++;
	}

	if (i == old->nwalks) {
		assert(0);
	}

	while (j < new->nwalks)
		temp.walks[i++] = new->walks[j++];

	temp.nwalks = i;
	*combined = temp;

	return 0;
}

/*
 * xlate_match() checks if a and b share a walk record. Return true if they do.
 */
static bool xlate_match(struct htm_insn_xlate *a,
		       struct htm_insn_xlate *b)
{
	uint64_t needle;

	needle = b->walks[0].ra_address;

	if (a->lpid != b->lpid)
		return false;

	if (a->pid != b->pid)
		return false;

	for (int i = 0; i < a->nwalks; i++) {
		if (needle == a->walks[i].ra_address)
			return true;
	}
	return false;
}

static void xlate_dump(struct htm_insn_xlate *xlate)
{
	DBG("BEGIN XLATE DUMP\n");
	DBG("LPID: %x PID: %x NWALKS: %x\n", xlate->lpid,
		xlate->pid, xlate->nwalks);

	for (int i = 0; i < xlate->nwalks; i++) {
		DBG("LEVEL: %d ", xlate->walks[i].level);
		DBG("FINAL RA: %d ", xlate->walks[i].final_ra);
		DBG("EXCEPTION: %d ", xlate->walks[i].exception);
		DBG("HOST_RA: %d ", xlate->walks[i].host_ra);
		DBG("GUEST_PTE: %d ", xlate->walks[i].guest_pte);
		DBG("RA: 0x%016lx\n", xlate->walks[i].ra_address);
	}
	DBG("END XLATE DUMP\n");
}

/*
 * pwc_partial_insert() adds an interrupted walk to partial_cache. A single walk
 * may be interrupted multiple times so before adding it check for existing
 * walks in partial_cache that overlap.
 */
void pwc_partial_insert(struct htm_insn_xlate *partial_walk)
{
	struct partial_cache_node *n;

	xlate_dump(partial_walk);
	list_for_each(&partial_cache.nodes, n, list) {
		if (xlate_match(&n->walk, partial_walk)) {
			xlate_merge(&n->walk, &n->walk, partial_walk);
			return;
		}
	}

	n = calloc(1, sizeof(*n));
	if (!n) {
		perror("calloc");
		exit(1);
	}

	n->walk = *partial_walk;
	list_add_tail(&partial_cache.nodes, &n->list);
	partial_cache.nnodes++;
}

/*
 * pwc_partial_lookup() searches partial_cache for any walks that overlap with
 * partial_walk. If there is a match it removed from partial_cache and the
 * merge of it and partial_walk is returned in merged_walk and return true.
 */
bool pwc_partial_lookup(struct htm_insn_xlate *merged_walk,
			struct htm_insn_xlate *partial_walk)
{
	struct partial_cache_node *n;

	list_for_each(&partial_cache.nodes, n, list) {
		if (xlate_match(&n->walk, partial_walk)) {
			xlate_merge(merged_walk, &n->walk, partial_walk);
			list_del(&n->list);
			partial_cache.nnodes--;
			free(n);
			return true;
		}
	}
	return false;
}

/*
 * xlate_match_address() checks if xlate's final record matches with
 * the effective address or real_address. Returns true if it does.
 */
static bool xlate_match_address(struct htm_insn_xlate *xlate,
				uint64_t address,
				uint64_t real_address)
{
	for (int i = 0; i < xlate->nwalks; i++) {
		if (!xlate->walks[i].final_ra)
			continue;

		if (!xlate->walks[i].host_ra) {
			if ((address & ~0xc00000000000000f) ==
			    xlate->walks[i].ra_address)
				return true;
		}

		if (real_address == xlate->walks[i].ra_address)
			return true;
	}
	return false;
}

/*
 * pwc_address_lookup() searches partial_cache for any walks that match address
 * and real_address. If there is a match it is removed from partial_cache and
 * returned in xlate and return true.
 */
bool pwc_address_lookup(struct htm_insn_xlate *xlate, uint64_t address,
			uint64_t real_address)
{
	struct partial_cache_node *n;

	list_for_each(&partial_cache.nodes, n, list) {
		if (xlate_match_address(&n->walk, address, real_address)) {
			*xlate = n->walk;
			list_del(&n->list);
			partial_cache.nnodes--;
			free(n);
			return true;
		}
	}
	return false;
}

/*
 * pwc_init() initializes the global state. Size is arbitrary.
 */
void pwc_init(void)
{
	assert(htable_pwc_init_sized(&page_walk_cache, 10000000));
	assert(htable_pwc_init_sized(&tlb_cache, 10000000));
	assert(htable_pwc_init_sized(&reverse_walk_cache, 10000000));

	partial_cache.nnodes = 0;
	list_head_init(&partial_cache.nodes);
}
