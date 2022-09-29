/*
 * Copyright (C) 2022 Jordan Niethe <jniethe5@gmail.com>, IBM
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#ifndef __XLATE_H__
#define __XLATE_H__

#include <inttypes.h>
#include <stdbool.h>

#include <qtlib/qtrace_record.h>
#include "htm_types.h"

struct xlate_address {
	int msr;
	unsigned int lpid;
	unsigned int pid;
	uint64_t address;
};

struct xlate_pte {
	uint64_t address;
	unsigned int page_size;
	bool leaf;
};

enum xlate_pte_type {
	XLATE_PGD,
	XLATE_PUD,
	XLATE_PMD,
	XLATE_PTE,
	XLATE_4K_PTE,
	XLATE_64K_PTE,
};

#define PTE_LEVEL_1 0x6
#define PTE_LEVEL_2 0x4
#define PTE_LEVEL_3 0x2
#define PTE_LEVEL_4 0x0

#define HTM_FINAL_64K 0x01
#define HTM_FINAL_4K 0x00

static inline struct xlate_address mk_xlate_addr(int msr, unsigned int lpid,
						 unsigned int pid,
						 uint64_t address)
{
	struct xlate_address addr;

	addr = (struct xlate_address) {
		msr,
		lpid,
		pid,
		address
	};
	return addr;
}

/*
 * Values adapted from the Linux kernel.
 */
#define MAX_RA_BITS 52
#define RA_MASK ((1ull << MAX_RA_BITS)-1)

#define PAGE_SHIFT_4K 12
#define PAGE_SIZE_4K (1ull << PAGE_SHIFT_4K)
#define PAGE_MASK_4K (~(PAGE_SIZE_4K-1))
#define PAGE_RA_MASK_4K (PAGE_MASK_4K & RA_MASK)

#define PAGE_SHIFT_64K 16
#define PAGE_SIZE_64K (1ull << PAGE_SHIFT_64K)
#define PAGE_MASK_64K (~(PAGE_SIZE_64K-1))
#define PAGE_RA_MASK_64K (PAGE_MASK_64K & RA_MASK)

#define PTE_INDEX_SHIFT_4K 9
#define PTE_INDEX_SIZE_4K (1ull << PTE_INDEX_SHIFT_4K)
#define PTE_INDEX_MASK_4K (((PTE_INDEX_SIZE_4K-1)) & RA_MASK)

#define PTE_INDEX_SHIFT_64K 5
#define PTE_INDEX_SIZE_64K (1ull << PTE_INDEX_SHIFT_64K)
#define PTE_INDEX_MASK_64K (((PTE_INDEX_SIZE_64K-1)) & RA_MASK)

#define PMD_SHIFT (PAGE_SHIFT_4K + PTE_INDEX_SHIFT_4K)
#define PMD_SIZE (1ull << PMD_SHIFT)
#define PMD_MASK (~(PMD_SIZE-1))
#define PMD_RA_MASK (PMD_MASK & RA_MASK)

#define PMD_INDEX_SHIFT 9
#define PMD_INDEX_SIZE (1ull << PMD_INDEX_SHIFT)
#define PMD_INDEX_MASK (((PMD_INDEX_SIZE-1)) & RA_MASK)

#define PUD_SHIFT (PMD_SHIFT + PMD_INDEX_SHIFT)
#define PUD_SIZE (1ull << PUD_SHIFT)
#define PUD_MASK (~(PUD_SIZE-1))
#define PUD_RA_MASK (PUD_MASK & RA_MASK)

#define PUD_INDEX_SHIFT 9
#define PUD_INDEX_SIZE (1ull << PUD_INDEX_SHIFT)
#define PUD_INDEX_MASK (((PUD_INDEX_SIZE-1)) & RA_MASK)

#define PGD_SHIFT (PUD_SHIFT + PUD_INDEX_SHIFT)
#define PGD_SIZE (1ull << PGD_SHIFT)
#define PGD_MASK (~(PGD_SIZE-1))
#define PGD_RA_MASK (PGD_MASK & RA_MASK)

#define PGD_INDEX_SHIFT 13
#define PGD_INDEX_SIZE (1ull << PGD_INDEX_SHIFT)
#define PGD_INDEX_MASK (((PGD_INDEX_SIZE-1)) & RA_MASK)

static inline uint64_t pte_address_4k(uint64_t address)
{
	return address & PAGE_RA_MASK_4K;
}

static inline uint64_t pte_address_64k(uint64_t address)
{
	return address & PAGE_RA_MASK_64K;
}

static inline uint64_t pte_address_2m(uint64_t address)
{
	return address & PMD_RA_MASK;
}

static inline uint64_t pte_address_1g(uint64_t address)
{
	return address & PUD_RA_MASK;
}

static inline uint64_t page_table_index_4k(uint64_t address)
{
	return ((address >> PAGE_SHIFT_4K) & PTE_INDEX_MASK_4K) << 3;
}

static inline uint64_t page_table_index_64k(uint64_t address)
{
	return ((address >> PAGE_SHIFT_64K) & PTE_INDEX_MASK_64K) << 3;
}

static inline uint64_t pmdp_address(uint64_t address)
{
	return address & PMD_RA_MASK;
}

static inline uint64_t pmd_index(uint64_t address)
{
	return ((address >> PMD_SHIFT) & PMD_INDEX_MASK) << 3;
}

static inline uint64_t pudp_address(uint64_t address)
{
	return address & PUD_RA_MASK;
}

static inline uint64_t pud_index(uint64_t address)
{
	return ((address >> PUD_SHIFT) & PUD_INDEX_MASK) << 3;
}

static inline uint64_t pgdp_address(uint64_t address)
{
	return address & PGD_RA_MASK;
}

static inline uint64_t pgd_index(uint64_t address)
{
	return ((address >> PGD_SHIFT) & PGD_INDEX_MASK) << 3;
}

static inline uint64_t pgd_address(uint64_t address)
{
	return 0;
}

static inline uint64_t address_aligned_4k(uint64_t address)
{
	return address & PAGE_MASK_4K;
}

static inline uint64_t address_aligned_64k(uint64_t address)
{
	return address & PAGE_MASK_64K;
}

static inline uint64_t address_aligned_2m(uint64_t address)
{
	return address & PMD_MASK;
}

static inline uint64_t address_aligned_1g(uint64_t address)
{
	return address & PUD_MASK;
}

static inline uint64_t page_offset_4k(uint64_t address)
{
	return address & ~PAGE_MASK_4K;
}

static inline uint64_t page_offset_64k(uint64_t address)
{
	return address & ~PAGE_MASK_64K;
}

static inline uint64_t page_offset_2m(uint64_t address)
{
	return address & ~PMD_MASK;
}

static inline uint64_t page_offset_1g(uint64_t address)
{
	return address & ~PUD_MASK;
}

int xlate_decode(struct htm_insn_xlate *xlates, struct htm_insn_msr *msr,
		 bool relocation,
		 uint64_t address, uint64_t real_address,
		 struct qtrace_radix *rec, uint32_t *host_page_shiftp,
		 uint32_t *guest_page_shiftp);

int xlate_lookup(struct htm_insn_msr *msr,
		 bool relocation,
		 uint64_t address, uint64_t real_address,
		 struct qtrace_radix *rec, uint32_t *host_page_shiftp,
		 uint32_t *guest_page_shiftp);

void xlate_init(void);

#endif /* __XLATE_H__ */
