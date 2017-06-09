/*
 * Copyright (C) 2017 Anton Blanchard <anton@au.ibm.com>, IBM
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */
#ifndef __BRANCH_H__
#define __BRANCH_H__

#include <stdbool.h>
#include <stdint.h>

static inline bool is_conditional_branch(uint32_t insn)
{
	int opcode = insn >> (32-6);

	if (opcode == 16)
		return true;

	if (opcode == 19) {
		int sub_opcode = (insn >> 1) & 0x3ff;

		switch (sub_opcode) {
		case 16:	/* bclr */
		case 528:	/* bcctr */
		case 560:	/* bctar */
			return true;
		}
	}

	return false;
}

static inline bool is_unconditional_branch(uint32_t insn)
{
	int opcode = insn >> (32-6);

	/* Include sc, scv */
	if (opcode == 17 || opcode == 18)
		return true;

	if (opcode == 19) {
		int sub_opcode = (insn >> 1) & 0x3ff;

		switch (sub_opcode) {
		case 50:	/* rfi */
		case 18:	/* rfid */
		case 274:	/* hrfid */
		case 82:	/* rfscv */
			return true;
		}
	}

	return false;
}

static inline bool is_branch(uint32_t insn)
{
	if (is_conditional_branch(insn) || is_unconditional_branch(insn))
		return true;

	return false;
}

#endif
