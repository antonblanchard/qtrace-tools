/*
 * Copyright (C) 2018 Michael Neuling <mikey@linux.ibm.com>, IBM
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */


#ifndef __BB_H__
#define __BB_H__

#include <stdint.h>
#include <unistd.h>
#include <stdbool.h>

extern void bb_init(void);
extern void bb_exit(void);
extern void bb_dump(void);

/* Setup a translation */
extern void bb_ea_log(uint64_t ea);

#endif /* __BB_H__ */
