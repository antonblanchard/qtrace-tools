/*
 * Copyright (C) 2022 Jordan Niethe <jniethe5@gmail.com>, IBM
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#ifndef __HTM_TYPES_H__
#define __HTM_TYPES_H__

#include <inttypes.h>
#include <stdbool.h>

struct htm_insn_info {
	unsigned int opcode;
	bool branch;
	bool ucode;
	bool valid;
	bool iea;
	bool ira;
	bool dea;
	bool dra;
	bool esid;
	unsigned int flags;
	bool software_tlb;
};

struct htm_insn_info_p10 {
	unsigned int opcode;
	bool branch;
	bool prefix;
	int dea;
	int dra;
	bool esid;
	unsigned int eabits;
};

struct htm_insn_iea {
	uint64_t address;
	bool msrhv;
	bool msrir;
};

struct htm_insn_ira {
	uint64_t address;
	unsigned int page_size;
	bool esid_to_irpn;
};

struct htm_insn_dea {
	uint64_t address;
};

struct htm_insn_dra {
	uint64_t page_address;
	unsigned int page_size;
	bool dh;
};

struct htm_insn_dra_p10 {
	uint64_t page_address;
};

struct htm_insn_esid {
	uint64_t esid;
};

struct htm_insn_vsid {
	unsigned int segment_size;
	uint64_t vsid;
	bool ks;
	bool kp;
	bool n;
	bool c;
	bool ta;
	unsigned int lp;
};

struct htm_insn_ieara {
	bool valid;
	uint64_t address;
	uint64_t real_address;
};

struct htm_insn_msr {
	bool msrhv;
	bool msrpr;
	bool msrir;
	bool msrdr;
	bool msree;
	bool msrs;
	unsigned int msrts;
	bool msrle;
	bool msrsf;
};

struct htm_insn_walk {
	bool final_ra;
	bool exception;
	bool guest_pte;
	bool host_ra;
	bool final_record;
	unsigned int level;
	unsigned int page_size;
	uint64_t ra_address;
};


struct htm_insn_xlate {
	bool d_side;
	unsigned int lpid;
	unsigned int pid;
	int nwalks;
	struct htm_insn_walk walks[37];
};

struct htm_insn_prefix {
	unsigned int prefix;
};

struct htm_insn {
	struct htm_insn_info info;
	struct htm_insn_iea iea;
	struct htm_insn_ira ira;
	struct htm_insn_dea dea;
	struct htm_insn_dra dra;
	struct htm_insn_esid esid;
	struct htm_insn_vsid vsid;
};

struct htm_insn_p10 {
	struct htm_insn_ieara ieara;
	struct htm_insn_info_p10 info;
	struct htm_insn_msr msr;
	struct htm_insn_dea dea[2];
	struct htm_insn_dra_p10 dra[2];
	struct htm_insn_esid esid;
	struct htm_insn_vsid vsid;
	struct htm_insn_xlate xlates[3];
	struct htm_insn_prefix prefix;
};

#endif /* __HTM_TYPES_H__ */