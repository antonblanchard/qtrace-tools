/*
 * Copyright (C) 2018 Michael Neuling <mikey@linux.ibm.com>, IBM
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */


#ifndef __TLB_H__
#define __TLB_H__

#include <stdint.h>
#include <unistd.h>
#include <stdbool.h>

#define TLB_FLAGS_RELOC (1 << 0)

extern void tlb_init(void);
extern void tlb_exit(void);
extern void tlb_dump(void);

/* Setup a translation */
extern void tlb_ra_set(uint64_t ea, uint64_t flags,
		       uint64_t ra, uint64_t pagesize);

/* Do a translation */
extern bool tlb_ra_get(uint64_t ea, uint64_t flags,
		       uint64_t *ra, uint64_t *pagesize);

#endif /* __TLB_H__ */
