/*
 * Copyright (C) 2022 Jordan Niethe <jniethe5@gmail.com>, IBM
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */


#ifndef __PWC_H__
#define __PWC_H__

#include <stdint.h>
#include <unistd.h>
#include <stdbool.h>
#include "pwc.h"
#include "xlate.h"

#define MSR_HV 0x2

#define PWC_LEAF 0x01
#define PWC_NOT_LEAF 0x02

void pwc_init(void);

void pwc_insert(int level, struct xlate_address addr,
		uint64_t real_address, bool leaf);

int pwc_get(int level, struct xlate_address addr, uint64_t *real_address,
	    uint64_t *flags);

bool pwc_tlb_get(int level, struct xlate_address addr,
		 uint64_t *real_address);
void pwc_tlb_insert(int level, struct xlate_address addr,
		    uint64_t real_address);

bool pwc_partial_lookup(struct htm_insn_xlate *merged_walk,
			struct htm_insn_xlate *partial_walk);

void pwc_partial_insert(struct htm_insn_xlate *partial_walk);

#endif /* __PWC_H__ */
