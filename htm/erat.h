/*
 * Copyright (C) 2022 Jordan Niethe <jniethe5@gmail.com>, IBM
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */


#ifndef __ERAT_H__
#define __ERAT_H__

#include <stdint.h>
#include <unistd.h>
#include <stdbool.h>
#include "xlate.h"

void erat_init(void);

bool erat_get(unsigned int page_shift, uint64_t address,
	      uint64_t real_address, struct qtrace_radix *rec,
	      unsigned int *host_page_shift,
	      unsigned int *guest_page_shift);

void erat_insert(unsigned int host_page_shift, uint64_t address,
		 uint64_t real_address, struct qtrace_radix *rec,
		 uint32_t guest_page_shift);

#endif /* __ERAT_H__ */
