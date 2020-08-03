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

#define BRANCH_ABSOLUTE 0x2

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

static inline bool is_offset_in_branch_range(long offset)
{
	/*
	 * Powerpc branch instruction is :
	 *
	 *  0         6                 30   31
	 *  +---------+----------------+---+---+
	 *  | opcode  |     LI         |AA |LK |
	 *  +---------+----------------+---+---+
	 *  Where AA = 0 and LK = 0
	 *
	 * LI is a signed 24 bits integer. The real branch offset is computed
	 * by: imm32 = SignExtend(LI:'0b00', 32);
	 *
	 * So the maximum forward branch should be:
	 *   (0x007fffff << 2) = 0x01fffffc =  0x1fffffc
	 * The maximum backward branch should be:
	 *   (0xff800000 << 2) = 0xfe000000 = -0x2000000
	 */
	return (offset >= -0x2000000 && offset <= 0x1fffffc && !(offset & 0x3));
}

static inline unsigned int create_branch(unsigned long addr,
			   unsigned long target, int flags)
{
	unsigned int instruction;
	long offset;

	offset = target;
	if (! (flags & BRANCH_ABSOLUTE))
		offset = offset - (unsigned long)addr;

	/* Check we can represent the target in the instruction format */
	if (!is_offset_in_branch_range(offset))
		return 0;

	/* Mask out the flags and target, so they don't step on each other. */
	instruction = 0x48000000 | (flags & 0x3) | (offset & 0x03FFFFFC);

	return instruction;
}

static inline unsigned int create_cond_branch(unsigned long addr,
				unsigned long target, int flags)
{
	unsigned int instruction;
	long offset;

	offset = target;
	if (! (flags & BRANCH_ABSOLUTE))
		offset = offset - (unsigned long)addr;

	/* Check we can represent the target in the instruction format */
	if (offset < -0x8000 || offset > 0x7FFF || offset & 0x3)
		return 0;

	/* Mask out the flags and target, so they don't step on each other. */
	instruction = 0x40000000 | (flags & 0x3FF0003) | (offset & 0xFFFC);

	return instruction;
}

static inline unsigned int branch_opcode(unsigned int instr)
{
	return (instr >> 26) & 0x3F;
}

static inline int instr_is_branch_iform(unsigned int instr)
{
	return branch_opcode(instr) == 18;
}

static inline int instr_is_branch_bform(unsigned int instr)
{
	return branch_opcode(instr) == 16;
}

static inline unsigned long branch_iform_target(const unsigned int instr)
{
	signed long imm;

	imm = instr & 0x3FFFFFC;

	/* If the top bit of the immediate value is set this is negative */
	if (imm & 0x2000000)
		imm -= 0x4000000;

	return (unsigned long)imm;
}

static inline unsigned long branch_bform_target(const unsigned int instr)
{
	signed long imm;

	imm = instr & 0xFFFC;

	/* If the top bit of the immediate value is set this is negative */
	if (imm & 0x8000)
		imm -= 0x10000;

	return (unsigned long)imm;
}

static inline int has_branch_target(const unsigned int instr)
{
	if (instr_is_branch_iform(instr))
		return 1;
	else if (instr_is_branch_bform(instr))
		return 1;

	return 0;
}

static inline int is_branch_absolute(const unsigned int instr)
{
	if (instr & BRANCH_ABSOLUTE)
		return 1;
	return 0;
}

static inline uint64_t branch_target(const unsigned int instr, unsigned long pc)
{
	if (has_branch_target(instr)) {
		unsigned long addr;
		if (instr_is_branch_iform(instr))
			addr = branch_iform_target(instr);
		else /* if (instr_is_branch_bform(instr)) */
			addr = branch_bform_target(instr);
		if (!is_branch_absolute(pc))
			addr += pc;
		return addr;
	}

	return 0;
}

static inline unsigned int set_branch_target(unsigned int insn, unsigned long iaddr, unsigned long btarget)
{
	if (instr_is_branch_iform(insn))
		return create_branch(iaddr, btarget, insn);
	else if (instr_is_branch_bform(insn))
		return create_cond_branch(iaddr, btarget, insn);
	else
		return insn;
}

#endif
