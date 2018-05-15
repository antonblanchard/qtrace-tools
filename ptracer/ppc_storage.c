/*
 * Copyright (C) 2017 Anton Blanchard <anton@au.ibm.com>, IBM
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

#define CACHELINE_SIZE 128

#define PPC_FIELD(value, from, len) \
	(((value) >> (32 - (from) - (len))) & ((1 << (len)) - 1))
#define PPC_SEXT(v, bs) \
	((((unsigned long) (v) & (((unsigned long) 1 << (bs)) - 1)) \
	  ^ ((unsigned long) 1 << ((bs) - 1))) \
	 - ((unsigned long) 1 << ((bs) - 1)))

#define PPC_OPC(insn)	PPC_FIELD(insn, 0, 6)
#define PPC_RT(insn)	PPC_FIELD(insn, 6, 5)
#define PPC_RA(insn)	PPC_FIELD(insn, 11, 5)
#define PPC_RB(insn)	PPC_FIELD(insn, 16, 5)
#define PPC_NB(insn)	PPC_FIELD(insn, 16, 5)
#define PPC_D(insn)	PPC_SEXT(PPC_FIELD(insn, 16, 16), 16)
#define PPC_DS(insn)	PPC_SEXT(PPC_FIELD(insn, 16, 14), 14)
#define PPC_DQ(insn)	PPC_SEXT(PPC_FIELD(insn, 16, 12), 12)

static bool handle_xform_masked(uint32_t insn, unsigned long *gprs,
				unsigned long mask, unsigned long *addr)
{
	if (PPC_RA(insn) != 0)
		*addr = gprs[PPC_RA(insn)];

	*addr += gprs[PPC_RB(insn)];

	*addr &= mask;

	return true;
}

static bool handle_xform(uint32_t insn, unsigned long *gprs,
			 unsigned long *addr)
{
	return handle_xform_masked(insn, gprs, -1UL, addr);
}

static bool handle_dform(uint32_t insn, unsigned long *gprs,
			 unsigned long *addr)
{
	if (PPC_RA(insn) != 0)
		*addr = gprs[PPC_RA(insn)];

	*addr += PPC_D(insn);

	return true;
}

static bool handle_dqform(uint32_t insn, unsigned long *gprs,
			  unsigned long *addr)
{
	if (PPC_RA(insn) != 0)
		*addr = gprs[PPC_RA(insn)];

	*addr += PPC_DQ(insn) << 4;

	return true;
}

static bool handle_dsform(uint32_t insn, unsigned long *gprs,
			  unsigned long *addr)
{
	if (PPC_RA(insn) != 0)
		*addr = gprs[PPC_RA(insn)];

	*addr += PPC_DS(insn) << 2;

	return true;
}

static bool extended_31(uint32_t insn, unsigned long *gprs,
			unsigned long *addr, unsigned long *size)
{
	int subopc = PPC_FIELD(insn, 21, 10);

	switch (subopc) {
	case 7:		/* lvebx */
	case 135:	/* stvebx */
		*size = 1;
		return handle_xform(insn, gprs, addr);

	case 39:	/* lvehx */
	case 167:	/* stvehx */
		*size = 2;
		return handle_xform_masked(insn, gprs, ~0x1, addr);

	case 71:	/* lvewx */
	case 199:	/* stvewx */
		*size = 4;
		return handle_xform_masked(insn, gprs, ~0x3, addr);

	case 103:	/* lvx */
	case 231:	/* stvx */
	case 359:	/* lvxl */
	case 487:	/* stvxl */
		*size = 16;
		return handle_xform_masked(insn, gprs, ~0xf, addr);

	case 269:	/* lxvl */
	case 301:	/* lxvll */
	case 397:	/* stxvl */
	case 429:	/* stxvll */
		/* Length is in the top byte of RB */
                *size = (gprs[PPC_RB(insn)] >> 56);
		if (*size > 16)
			*size = 16;

		*addr = 0;
		if (PPC_RA(insn) != 0)
			*addr = gprs[PPC_RA(insn)];

		return true;

	case 781:	/* lxsibzx */
	case 909:	/* stxsibx */
		*size = 1;
		return handle_xform(insn, gprs, addr);

	case 813:	/* lxsihzx */
	case 941:	/* stxsihx */
		*size = 2;
		return handle_xform(insn, gprs, addr);

	case 12:	/* lxsiwzx */
	case 76:	/* lxsiwax */
	case 140:	/* stxsiwx */
	case 364:	/* lxvwsx */
	case 524:	/* lxsspx */
	case 652:	/* stxsspx */
		*size = 4;
		return handle_xform(insn, gprs, addr);

	case 332:	/* lxvdsx */
	case 588:	/* lxsdx */
	case 716:	/* stxsdx */
		*size = 8;
		return handle_xform(insn, gprs, addr);

	case 268:	/* lxvx */ /* XXX ?? PPC ISA spec issue? */
	case 396:	/* stxvx */
	case 780:	/* lxvw4x */
	case 908:	/* stxvw4x */
	case 812:	/* lxvh8x */
	case 940:	/* stxvh8x */
	case 844:	/* lxvd2x */
	case 972:	/* stxvd2x */
	case 876:	/* lxvb16x */
	case 1004:	/* stxvb16x */
		*size = 16;
		return handle_xform(insn, gprs, addr);

	case 52:	/* lbarx */
	case 694:	/* stbcx. */
	case 87:	/* lbzx */
	case 119:	/* lbzux */
	case 215:	/* stbx */
	case 247:	/* stbux */
	case 853:	/* lbzcix */
	case 981:	/* stbcix */
		*size = 1;
		return handle_xform(insn, gprs, addr);

	case 116:	/* lharx */
	case 726:	/* sthcx. */
	case 279:	/* lhzx */
	case 311:	/* lhzux */
	case 343:	/* lhax */
	case 375:	/* lhaux */
	case 407:	/* sthx */
	case 439:	/* sthux */
	case 790:	/* lhbrx */
	case 918:	/* sthbrx */
	case 821:	/* lhzcix */
	case 949:	/* sthcix */
		*size = 2;
		return handle_xform(insn, gprs, addr);

	case 20:	/* lwarx */
	case 150:	/* stwcx. */
	case 23:	/* lwzx */
	case 151:	/* stwx */
	case 55:	/* lwzux */
	case 341:	/* lwax */
	case 373:	/* lwaux */
	case 183:	/* stwux */
	case 534:	/* lwbrx */
	case 662:	/* stwbrx */
	case 789:	/* lwzcix */
	case 917:	/* stwcix */
		*size = 4;
		return handle_xform(insn, gprs, addr);

	case 84:	/* ldarx */
	case 214:	/* stdcx. */
	case 21:	/* ldx */
	case 149:	/* stdx */
	case 53:	/* ldux */
	case 181:	/* stdux */
	case 532:	/* ldbrx */
	case 660:	/* stdbrx */
	case 885:	/* ldcix */
	case 1013:	/* stdcix */
	case 309:	/* ldmx */
		*size = 8;
		return handle_xform(insn, gprs, addr);

	case 276:	/* lqarx */
	case 182:	/* stqcx. */
		*size = 16;
		return handle_xform(insn, gprs, addr);

	case 535:	/* lfsx */
	case 567:	/* lfsux */
	case 663:	/* stfsx */
	case 695:	/* stfsux */
	case 855:	/* lfiwax */
	case 887:	/* lfiwzx */
	case 983:	/* stfiwx */
		*size = 4;
		return handle_xform(insn, gprs, addr);

	case 599:	/* lfdx */
	case 631:	/* lfdux */
	case 727:	/* stfdx */
	case 759:	/* stfdux */
		*size = 8;
		return handle_xform(insn, gprs, addr);

	case 791:	/* lfdpx */
	case 919:	/* stfdpx */
		*size = 16;
		return handle_xform(insn, gprs, addr);

	case 22:	/* icbt */
	case 54:	/* dcbst */
	case 86:	/* dcbf */
	case 246:	/* dcbtst */
	case 278:	/* dcbt */
	case 982:	/* icbi */
	case 1014:	/* dcbz */
		*size = CACHELINE_SIZE;
		return handle_xform_masked(insn, gprs, ~(CACHELINE_SIZE-1), addr);

	case 533:	/* lswx */
	case 661:	/* stswx */
	case 597:	/* lswi */
	case 725:	/* stswi */
		/* XXX FIXME */
		assert(0);
		break;

	case 582:	/* lwat */
	case 710:	/* stwat */
		/* XXX FIXME */
		assert(0);
		break;

	case 614:	/* ldat */
	case 742:	/* stdat */
		/* XXX FIXME */
		assert(0);
		break;

	case 774:	/* copy */
	case 902:	/* paste */
		*size = CACHELINE_SIZE;
		return handle_xform(insn, gprs, addr);
	}

	return false;
}

static bool extended_57(uint32_t insn, unsigned long *gprs,
			unsigned long *addr, unsigned long *size)
{
	int subopc = PPC_FIELD(insn, 30, 2);

	switch (subopc) {
	case 0:		/* lfdp */
		*size = 16;
		return handle_dsform(insn, gprs, addr);

	case 2:		/* lxsd */
		*size = 8;
		return handle_dsform(insn, gprs, addr);

	case 3:		/* lxssp */
		*size = 4;
		return handle_dsform(insn, gprs, addr);
	}

	return false;
}

static bool extended_58(uint32_t insn, unsigned long *gprs,
			unsigned long *addr, unsigned long *size)
{
	int subopc = PPC_FIELD(insn, 30, 2);

	switch (subopc) {
	case 0:		/* ld */
	case 1:		/* ldu */
		*size = 8;
		return handle_dsform(insn, gprs, addr);

	case 2:		/* lwa */
		*size = 4;
		return handle_dsform(insn, gprs, addr);
	}

	return false;
}

static bool extended_61(uint32_t insn, unsigned long *gprs,
			unsigned long *addr, unsigned long *size)
{
	int subopc = PPC_FIELD(insn, 29, 3);

	switch (subopc) {

	case 0:		/* stfdp */
	case 4:		/* stfdp */
		*size = 16;
		return handle_dsform(insn, gprs, addr);

	case 1:		/* lxv */
	case 5:		/* stxv */
		*size = 16;
		return handle_dqform(insn, gprs, addr);

	case 2:		/* stxsd */
	case 6:		/* stxsd */
		*size = 8;
		return handle_dsform(insn, gprs, addr);

	case 3:		/* stxssp */
	case 7:		/* stxssp */
		*size = 4;
		return handle_dsform(insn, gprs, addr);
	}

	return false;
}

static bool extended_62(uint32_t insn, unsigned long *gprs,
			unsigned long *addr, unsigned long *size)
{
	int subopc = PPC_FIELD(insn, 30, 2);

	switch (subopc) {
	case 0:		/* std */
	case 1:		/* stdu */
		*size = 8;
		return handle_dsform(insn, gprs, addr);

	case 2:		/* stq */
		*size = 16;
		return handle_dsform(insn, gprs, addr);
	}

	return false;
}

bool is_storage_insn(uint32_t insn, unsigned long *gprs, unsigned long *addr,
		     unsigned long *size)
{
	unsigned long _gprs[32];
	unsigned long _addr;
	unsigned long _size;

	int opcode = PPC_OPC(insn);

	if (!gprs) {
		/* Unused */
		gprs = _gprs;
		addr = &_addr;
		size = &_size;
	}

	*addr = 0;
	*size = 0;

	switch (opcode) {
	case 31:
		return extended_31(insn, gprs, addr, size);

	case 57:
		return extended_57(insn, gprs, addr, size);

	case 58:
		return extended_58(insn, gprs, addr, size);

	case 61:
		return extended_61(insn, gprs, addr, size);

	case 62:
		return extended_62(insn, gprs, addr, size);

	case 32:	/* lwz */
	case 33:	/* lwzu */
	case 36:	/* stw */
	case 37:	/* stwu */
		*size = 4;
		return handle_dform(insn, gprs, addr);

	case 34:	/* lbz */
	case 35:	/* lbzu */
	case 38:	/* stb */
	case 39:	/* stbu */
		*size = 1;
		return handle_dform(insn, gprs, addr);

	case 40:	/* lhz */
	case 41:	/* lhzu */
	case 42:	/* lha */
	case 43:	/* lhau */
	case 44:	/* sth */
	case 45:	/* sthu */
		*size = 2;
		return handle_dform(insn, gprs, addr);

	case 48:	/* lfs */
	case 49:	/* lfsu */
	case 52:	/* stfs */
	case 53:	/* stfsu */
		*size = 4;
		return handle_dform(insn, gprs, addr);

	case 50:	/* lfd */
	case 51:	/* lfdu */
	case 54:	/* stfd */
	case 55:	/* stfdu */
		*size = 8;
		return handle_dform(insn, gprs, addr);

	case 56:	/* lq */
		*size = 16;
		return handle_dqform(insn, gprs, addr);

	case 46:	/* lmw */
	case 47:	/* stmw */
		*size = 4 * (32 - PPC_RT(insn));
		return handle_dform(insn, gprs, addr);
	}

	return false;
}
