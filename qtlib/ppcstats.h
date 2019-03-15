/*
 * Copyright (C) 2018 Michael Neuling <mikey@neuling.org>, IBM
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */
#ifndef __PPCSTATS_H__
#define __PPCSTATS_H__

#include <unistd.h>
#include <stdint.h>

#define PPCSTATS_STATS 0x1
#define PPCSTATS_IMIX  0x2

void ppcstats_init(uint64_t flags);
void ppcstats_log_inst(unsigned long ea, uint32_t insn);
void ppcstats_print(void);

#endif /* __PPCSTATS_H__ */
