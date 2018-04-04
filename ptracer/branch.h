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

#define OPCODE(insn)            ((insn) >> 26)
#define SUB_OPCODE(insn)        (((insn) >> 1) & 0x3ff)
#define BO(insn)                (((insn) >> 21) & 0x1f)

/*
 * A conditional branch is unconditional if the BO field is 0b1X1XX
 */
static bool branch_conditional_is_conditional(uint32_t insn)
{
	return !!((BO(insn) & 0x14) != 0x14);
}

static inline bool is_conditional_branch(uint32_t insn)
{
	uint32_t opcode = OPCODE(insn);

	if ((opcode == 16) && branch_conditional_is_conditional(insn))
		return true;

	if (opcode == 19) {
		uint32_t sub_opcode = SUB_OPCODE(insn);

		switch (sub_opcode) {
		case 16:	/* bclr */
		case 528:	/* bcctr */
		case 560:	/* bctar */
			if (branch_conditional_is_conditional(insn))
				return true;
			break;
		}
	}

	return false;
}

static inline bool is_unconditional_branch(uint32_t insn)
{
	uint32_t opcode = insn >> (32-6);

	if ((opcode == 16) && !branch_conditional_is_conditional(insn))
		return true;

	/* Include sc, scv */
	if (opcode == 17 || opcode == 18)
		return true;

	if (opcode == 19) {
		uint32_t sub_opcode = SUB_OPCODE(insn);

		switch (sub_opcode) {
		case 16:	/* bclr */
		case 528:	/* bcctr */
		case 560:	/* bctar */
			if (!branch_conditional_is_conditional(insn))
				return true;
			break;

		case 50:	/* rfi */
		case 18:	/* rfid */
		case 274:	/* hrfid */
		case 82:	/* rfscv */
			return true;
			break;
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
