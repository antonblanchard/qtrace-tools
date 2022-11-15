/*
 * Copyright (C) 2018 Amitay Isaacs <aisaacs@au.ibm.com>, IBM
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <endian.h>
#include <assert.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <archive.h>
#include <string.h>

#include <ppcstats.h>

#include "htm.h"
#include "htm_types.h"
#include "tlb.h"
#include "bb.h"
#include "branch.h"

#define HTM_STAMP_RECORD	0xACEFF0
#define HTM_STAMP_COMPLETE	0xACEFF1
#define HTM_STAMP_PAUSE		0xACEFF2
#define HTM_STAMP_MARK		0xACEFF3
#define HTM_STAMP_SYNC		0xACEFF4
#define HTM_STAMP_TIME		0xACEFF8

#define REC_TYPE_XLATE		1
#define REC_TYPE_INST		2
#define REC_TYPE_IEARA		3

static inline unsigned int htm_uint32(uint64_t value)
{
	assert(value <= UINT32_MAX);

	return (unsigned int)(value & UINT32_MAX);
}

/* Big-endian format, 0-msb, 31-lsb */
static inline uint32_t htm_bits_32(uint32_t value, int start, int end)
{
	uint32_t mask;
	int nbits;

	assert(start >= 0 && start <= 31);
	assert(end >= 0 && end <= 31);
	assert(start <= end);

	nbits = end - start + 1;

	mask = ~(UINT32_MAX << nbits) << (31 - end);
	return (value & mask) >> (31 - end);
}

/* Big-endian format, 0-msb, 63-lsb */
static inline uint64_t htm_bits(uint64_t value, int start, int end)
{
	uint64_t mask;
	int nbits;

	assert(start >= 0 && start <= 63);
	assert(end >= 0 && end <= 63);
	assert(start <= end);

	nbits = end - start + 1;

	mask = ~(UINT64_MAX << nbits) << (63 - end);
	return (value & mask) >> (63 - end);
}

static inline bool htm_bit(uint64_t value, int bit)
{
	if (htm_uint32(htm_bits(value, bit, bit)) == 1) {
		return true;
	};

	return false;
}


struct htm_decode_state {
	struct archive *a;
	uint64_t read_offset;
	int nr, nr_rewind, error_count;
	struct htm_decode_stat stat;
	htm_record_fn_t fn;
	uint64_t prev;
	bool rewind;
	void *private_data;

	/* instruction state */
	uint64_t prev_addr;
	bool prev_insn_branch;
	uint64_t insn_addr;
	uint64_t insn_real_addr;
	uint32_t insn;

	unsigned int insn_page_size;
	unsigned int data_page_size;
};
static int eof = 0;
static inline int htm_read(struct htm_decode_state *state, uint8_t *buf,
			   size_t len)
{
	ssize_t size;

	assert(len == 8);

	if (state->rewind) {
		*(uint64_t *)buf = state->prev;
		state->rewind = false;
		state->read_offset += len;
		return 1;
	}

	size = archive_read_data(state->a, buf, len);
	if (size < 0)
		return size;
	if (eof && size == 0)
		return 0;
	state->read_offset += len;
	if (size == 0) {
		eof = 1;
	}
	return 1;
}

static void htm_rewind(struct htm_decode_state *state, uint64_t value)
{
	uint32_t word1, word2;

	/* Are we rewinding to same location? */
	if (state->nr_rewind == state->nr) {
		fprintf(stderr, "Trace corrupted too badly to parse\n");
		fprintf(stderr, "nr: %i seek:%lx\n",
			state->nr, state->read_offset);
		assert(0);
	}

	state->read_offset -= 8;

	/* rewind state info */
	state->rewind = true;
	state->nr_rewind = state->nr;
	state->nr--;
	state->stat.total_records_scanned--;
	word1 = htm_bits(value, 0, 31);
	word2 = htm_bits(value, 32, 63);
	state->stat.checksum -= (word1 + word2);
}

static int htm_decode_fetch_internal(struct htm_decode_state *state, uint64_t *value)
{
	uint64_t v;
	union {
		uint8_t bytes[8];
		uint64_t value;
	} i;
	uint32_t word1, word2;
	int ret;

	ret = htm_read(state, i.bytes, sizeof(i.bytes));
	state->prev =  i.value;
	if (ret <= 0) {
		return -1;
	}

	v = be64toh(i.value);

	assert(value);

	*value = v;

	word1 = htm_bits(v, 0, 31);
	word2 = htm_bits(v, 32, 63);

	state->nr++;
	state->stat.total_records_scanned++;
	state->stat.checksum += (word1 + word2);

	return 0;
}

static int htm_decode_stamp(struct htm_decode_state *state,
			    uint64_t value);

/*
 * On P10 timestamp records may come at any time, just skip them.
 */
static int htm_decode_fetch(struct htm_decode_state *state, uint64_t *value)
{
	uint64_t v;
	int r;

	*value = 0;
	r = htm_decode_fetch_internal(state, &v);
	if (r)
		return r;
	if (htm_bits(v, 0, 19) == 0xaceff) {
		r = htm_decode_stamp(state, v);
		if (r)
			return r;
		r = htm_decode_fetch(state, &v);
	}
	*value = v;
	return r;
}

static int htm_decode_record(struct htm_decode_state *state,
			     uint64_t value,
			     struct htm_record *rec)
{
	assert(htm_bits(value, 0, 23) == HTM_STAMP_RECORD);

	rec->type = HTM_RECORD_RECORD;
	rec->record.counter = htm_uint32(htm_bits(value, 24, 31));

	return 0;
}

static int htm_decode_complete(struct htm_decode_state *state,
			       uint64_t value,
			       struct htm_record *rec)
{
	assert(htm_bits(value, 0, 23) == HTM_STAMP_COMPLETE);

	rec->type = HTM_RECORD_COMPLETE;
	rec->complete.elapsed_time = htm_uint32(htm_bits(value, 36, 63));

	return 0;
}

static int htm_decode_pause(struct htm_decode_state *state,
			    uint64_t value,
			    struct htm_record *rec)
{
	assert(htm_bits(value, 0, 23) == HTM_STAMP_PAUSE);

	rec->type = HTM_RECORD_PAUSE;
	rec->pause.elapsed_time = htm_uint32(htm_bits(value, 36, 63));

	return 0;
}

static int htm_decode_mark(struct htm_decode_state *state,
			   uint64_t value,
			   struct htm_record *rec)
{
	assert(htm_bits(value, 0, 23) == HTM_STAMP_MARK);

	rec->type = HTM_RECORD_MARK;
	rec->mark.group_id = htm_uint32(htm_bits(value, 24, 27));
	rec->mark.chip_id = htm_uint32(htm_bits(value, 28, 30));
	rec->mark.unit_id = htm_uint32(htm_bits(value, 31, 40));
	rec->mark.marker_info = htm_uint32(htm_bits(value, 41, 52));
	assert(htm_bits(value, 53, 62) == 0);
	rec->mark.marker_dropped = htm_bit(value, 63);

	return 0;
}

static int htm_decode_sync(struct htm_decode_state *state,
			   uint64_t value,
			   struct htm_record *rec)
{
	assert(htm_bits(value, 0, 23) == HTM_STAMP_SYNC);

	rec->type = HTM_RECORD_SYNC;

	return 0;
}

static int htm_decode_time(struct htm_decode_state *state,
			   uint64_t value,
			   struct htm_record *rec)
{
	unsigned int indicator;

	assert((htm_bits(value, 0, 23) & HTM_STAMP_TIME) == HTM_STAMP_TIME);

	rec->type = HTM_RECORD_TIME;
	indicator = htm_uint32(htm_bits(value, 20, 27));
	if (indicator == 0x80) {
		rec->time.normal_timestamp = true;
		rec->time.elapsed_time = htm_uint32(htm_bits(value, 36, 63));

		state->stat.total_cycles += rec->time.elapsed_time;
	} else if (indicator == 0x90) {
		rec->time.marker_dropped = true;
	} else if (indicator == 0xA0) {
		rec->time.record_dropped_counter_overflow = true;
		rec->time.record_dropped_counter = htm_uint32(htm_bits(value, 28, 35));
	} else if (indicator == 0xB0) {
		rec->time.elapsed_time_overflow = true;
	} else if (indicator == 0x88) {
		rec->time.cresp_record_dropped = true;
	} else if (indicator == 0x84) {
		rec->time.trigger_dropped = true;
	} else if (indicator == 0x82) {
		rec->time.trace_full_asserted = true;
	}

	state->stat.total_timestamps_scanned++;
	state->stat.total_timestamps_processed++;

	return 0;
}

static int htm_decode_stamp(struct htm_decode_state *state,
			    uint64_t value)
{
	struct htm_record rec = { 0 };
	unsigned int type;
	int ret = -1;

	state->stat.total_records_processed++;

	type = htm_uint32(htm_bits(value, 0, 23));

	if (type == HTM_STAMP_RECORD) {
		ret = htm_decode_record(state, value, &rec);
	} else if (type == HTM_STAMP_COMPLETE) {
		ret = htm_decode_complete(state, value, &rec);
	} else if (type == HTM_STAMP_PAUSE) {
		ret = htm_decode_pause(state, value, &rec);
	} else if (type == HTM_STAMP_MARK) {
		ret = htm_decode_mark(state, value, &rec);
	} else if (type == HTM_STAMP_SYNC) {
		ret = htm_decode_sync(state, value, &rec);
	} else if ((type & HTM_STAMP_TIME) == HTM_STAMP_TIME) {
		ret = htm_decode_time(state, value, &rec);
	}

	if (ret < 0) {
		return -1;
	}

	if (state->fn)
		state->fn(&rec, state->private_data);

	return 0;
}

static int htm_get_rec_type(uint64_t value)
{
	unsigned int tag;

	tag = htm_uint32(htm_bits(value, 36, 55));
	if (tag != 0xABCDF) {
		return 0;
	}

	return htm_bits(value, 34, 35);
}

static int htm_decode_insn_ieara(struct htm_decode_state *state,
				 uint64_t value,
				 struct htm_insn_ieara *rec)
{
	int ret;

	ret = htm_decode_fetch(state, &value);
	if (ret < 0)
		return -1;
	rec->address = htm_bits(value, 0, 56) << 7;

	ret = htm_decode_fetch(state, &value);
	if (ret < 0)
		return -1;
	rec->real_address = htm_bits(value, 0, 39) << 12;
	rec->valid = true;

	return 0;
}

static int htm_decode_insn_info_p10(struct htm_decode_state *state,
				    uint64_t value,
				    struct htm_insn_info_p10 *rec)
{
	unsigned int tag;

	tag = htm_uint32(htm_bits(value, 36, 55));
	if (tag != 0xABCDF) {
		return -1;
	}

	if (htm_bits(value, 34, 35) != REC_TYPE_INST) {
		return -1;
	}

	rec->opcode = htm_uint32(htm_bits(value, 0, 31));

	rec->branch = htm_bit(value, 32);
	rec->prefix = htm_bit(value, 33);
	rec->eabits = htm_uint32(htm_bits(value, 56, 61)) << 2;
	switch (htm_bits(value, 62, 63)) {
	case 1:
		rec->dea = 1;
		rec->dra = 1;
		break;
	case 2:
		rec->dea = 2;
		rec->dra = 2;
		break;
	case 3:
		rec->dea = 1;
		rec->dra = 1;
		rec->esid = true;
		break;
	}

	return 0;
}

static int htm_decode_insn_msr(struct htm_decode_state *state,
			       uint64_t value,
			       struct htm_insn_msr *msr)
{
	msr->msrhv = htm_bit(value, 0);
	msr->msrpr = htm_bit(value, 1);
	msr->msrir = htm_bit(value, 2);
	msr->msrdr = htm_bit(value, 3);
	msr->msree = htm_bit(value, 4);
	msr->msrs = htm_bit(value, 5);
	msr->msrts = htm_uint32(htm_bits(value, 6, 7));
	msr->msrle = htm_bit(value, 8);
	msr->msrsf = htm_bit(value, 9);

	return 0;
}

static int htm_decode_insn_xlate(struct htm_decode_state *state,
				 uint64_t value,
				 struct htm_insn_xlate *xlate)
{
	int i, ret;
	unsigned int tag;

	tag = htm_uint32(htm_bits(value, 36, 55));
	if (tag != 0xABCDF) {
		return -1;
	}

	if (htm_bits(value, 34, 35) != REC_TYPE_XLATE) {
		return -1;
	}

	xlate->d_side = htm_bit(value, 0);
	xlate->lpid = htm_uint32(htm_bits(value, 1, 12));
	xlate->pid = htm_uint32(htm_bits(value, 13, 32));

	for (i = 0; i < 38; i++) {
		ret = htm_decode_fetch(state, &value);
		if (ret < 0) {
			return -1;
		}
		xlate->walks[i].final_ra = htm_bit(value, 0);
		xlate->walks[i].exception = htm_bit(value, 1);
		xlate->walks[i].guest_pte = htm_bit(value, 2);
		xlate->walks[i].host_ra = htm_bit(value, 3);
		xlate->walks[i].final_record = htm_bit(value, 7);
		xlate->walks[i].level = htm_uint32(htm_bits(value, 4, 6));

		switch (xlate->walks[i].level) {
		case 0:
			xlate->walks[i].page_size = 12;
			if (xlate->d_side)
				state->stat.total_instruction_pages_4k++;
			else
				state->stat.total_data_pages_4k++;
			break;
		case 1:
			xlate->walks[i].page_size = 16;
			if (xlate->d_side)
				state->stat.total_instruction_pages_64k++;
			else
				state->stat.total_data_pages_64k++;
			break;
		case 2:
			xlate->walks[i].page_size = 21;
			break;
		case 3:
			xlate->walks[i].page_size = 24;
			break;
		case 4:
			xlate->walks[i].page_size = 30;
			break;
		case 6:
			xlate->walks[i].page_size = 40;
			break;
		}

		xlate->walks[i].ra_address = htm_bits(value, 8, 60) << 3;

		if (xlate->walks[i].final_record) {
			break;
		}
	}

	if (i == 38) {
		return -1;
	}

	xlate->nwalks = i;

	if (xlate->d_side) {
		state->data_page_size = xlate->walks[xlate->nwalks - 1].page_size;
	} else {
		state->insn_page_size = xlate->walks[xlate->nwalks - 1].page_size;
	}

	return 0;
}

static int htm_decode_insn_prefix(struct htm_decode_state *state,
				  uint64_t value,
				  struct htm_insn_prefix *rec)
{
	rec->prefix = htm_uint32(htm_bits(value, 0, 31));

	return 0;
}

static int htm_decode_insn_info(struct htm_decode_state *state,
				uint64_t value,
				struct htm_insn_info *rec)
{
	unsigned int tag;

	tag = htm_uint32(htm_bits(value, 36, 55));
	if (tag != 0xABCDE) {
		return -1;
	}

	rec->opcode = htm_uint32(htm_bits(value, 0, 31));
	if (rec->opcode == 0) {
		return -1;
	}
	rec->branch = htm_bit(value, 32);
	rec->ucode = htm_bit(value, 33);
	rec->valid = htm_bit(value, 56);
	rec->iea = htm_bit(value, 57);
	rec->ira = htm_bit(value, 58);
	rec->dea = htm_bit(value, 59);
	rec->dra = htm_bit(value, 60);
	rec->esid = htm_bit(value, 61);
	rec->flags = htm_uint32(htm_bits(value, 62, 63));

	return 0;
}

static int htm_decode_insn_iea(struct htm_decode_state *state,
			       uint64_t value,
			       struct htm_insn_iea *rec)
{
	unsigned int tag;

	tag = htm_uint32(htm_bits(value, 0, 19));
	if (tag == 0xACEFF) {
		return -2;
	}
	tag = htm_uint32(htm_bits(value, 36, 55));
	if (tag == 0xABCDE) {
		return -2;
	}

	rec->address = value & 0xfffffffffffffffc;
	rec->msrhv = htm_bit(value, 62);
	rec->msrir = htm_bit(value, 63);

	return 0;
}

static int htm_decode_insn_ira(struct htm_decode_state *state,
			       uint64_t value,
			       struct htm_insn_ira *rec)
{
	unsigned int tag;
	uint64_t address, mask;
	uint8_t page_size;

	tag = htm_uint32(htm_bits(value, 0, 19));
	if (tag == 0xACEFF) {
		return -2;
	}
	tag = htm_uint32(htm_bits(value, 36, 55));
	if (tag == 0xABCDE) {
		return -2;
	}

	tag = htm_uint32(htm_bits(value, 41, 63));
	if (tag != 0) {
		return -1;
	}

	page_size = htm_uint32(htm_bits(value, 38, 39));
	rec->esid_to_irpn = htm_bit(value, 40);

	switch (page_size) {
		case 1:
			rec->page_size = 12;
			break;
		case 2:
			rec->page_size = 16;
			break;
		case 3:
			rec->page_size = 24;
			break;
		default:
			printf("Invalid insn page size of %u\n", page_size);
			return -1;
	}

	address = htm_bits(value, 0, 37) << 12;
	mask = 1;
	mask = (mask << rec->page_size) - 1;

	rec->address = address | (state->insn_addr & mask);

	/* documented
	rec->page_address = htm_bits(value, 18, 51);
	rec->page_size = htm_uint32(htm_bits(value, 52, 53));
	*/

	return 0;
}

static int htm_decode_insn_dea_p10(struct htm_decode_state *state,
				   uint64_t value,
				   struct htm_insn_dea *rec)
{
	rec->address = value;

	return 0;
}

static int htm_decode_insn_dea(struct htm_decode_state *state,
			       uint64_t value,
			       struct htm_insn_dea *rec)
{
	unsigned int tag;

	tag = htm_uint32(htm_bits(value, 0, 19));
	if (tag == 0xACEFF) {
		return -2;
	}
	tag = htm_uint32(htm_bits(value, 36, 55));
	if (tag == 0xABCDE) {
		return -2;
	}

	rec->address = value;

	return 0;
}

static int htm_decode_insn_dra(struct htm_decode_state *state,
			       uint64_t value,
			       struct htm_insn_dra *rec)
{
	unsigned int tag;
	uint64_t address;
	uint8_t page_size;

	tag = htm_uint32(htm_bits(value, 0, 19));
	if (tag == 0xACEFF) {
		return -2;
	}
	tag = htm_uint32(htm_bits(value, 36, 55));
	if (tag == 0xABCDE) {
		return -2;
	}

	page_size = htm_uint32(htm_bits(value, 0, 1));

	switch (page_size) {
		case 0:
			/* Used for MMU off and 4k pages */
			rec->page_size = 12;
			break;
		case 1:
			rec->page_size = 16;
			break;
		case 3:
			rec->page_size = 24;
			break;
		default:
			printf("Invalid data page size %u\n", page_size);
			return -1;
	}

	address = htm_bits(value, 2, 39) << 12;

	rec->page_address = address ;

	rec->dh = htm_bit(value, 63);

	/* documented
	rec->page_address = htm_bits(value, 18, 51);
	rec->page_size = htm_uint32(htm_bits(value, 52, 53));
	*/

	return 0;
}

static int htm_decode_insn_dra_p10(struct htm_decode_state *state,
				   uint64_t value,
				   struct htm_insn_dra_p10 *rec)
{
	uint64_t address;

	address = htm_bits(value, 0, 40) << 12;
	rec->page_address = address;

	return 0;
}

static int htm_decode_insn_esid(struct htm_decode_state *state,
				uint64_t value,
				struct htm_insn_esid *rec)
{
	unsigned int tag;

	tag = htm_uint32(htm_bits(value, 0, 19));
	if (tag == 0xACEFF) {
		return -2;
	}
	tag = htm_uint32(htm_bits(value, 36, 55));
	if (tag == 0xABCDE) {
		return -2;
	}

	rec->esid = htm_bits(value, 0, 35);

	return 0;
}

static int htm_decode_insn_vsid(struct htm_decode_state *state,
				uint64_t value,
				struct htm_insn_vsid *rec)
{
	unsigned int tag;

	tag = htm_uint32(htm_bits(value, 0, 19));
	if (tag == 0xACEFF) {
		return -2;
	}
	tag = htm_uint32(htm_bits(value, 36, 55));
	if (tag == 0xABCDE) {
		return -2;
	}

	rec->segment_size = htm_uint32(htm_bits(value, 0, 1));
	rec->vsid = htm_bits(value, 2, 51);
	rec->ks = htm_bit(value, 52);
	rec->kp = htm_bit(value, 53);
	rec->n = htm_bit(value, 54);
	rec->c = htm_bit(value, 56);
	rec->ta = htm_bit(value, 57);
	rec->lp = (htm_uint32(htm_bits(value, 55, 55)) << 2) |
		  htm_uint32(htm_bits(value, 58, 59));

	return 0;
}

static unsigned int htm_insn_type(uint64_t value)
{
	unsigned int tag;

	tag = htm_uint32(htm_bits(value, 36, 55));

	return tag;
}

#define MAJOR_OPCODE(insn)	(((insn) >> 26) & 0x3f)
#define MINOR_OPCODE(insn)	(((insn) >> 1) & 0x1f)

#define PPC32_BIT(x) (31 - x)

/*
 * Based on the Branch Recoding described in the POWER10 Processor
 * Specification.
 */
static uint32_t insn_recode_p10(uint32_t opcode, uint64_t iea)
{
	uint32_t ppc_opcode = 0;
	uint32_t branch_type;
	uint32_t msb_mode;
	unsigned int link_bit;
	uint64_t target_ea = 0;
	unsigned int bo;
	unsigned int bi;
	unsigned int bh;

	msb_mode = htm_bits_32(opcode, 2, 3);
	branch_type = htm_bits_32(opcode, 11, 12);

	link_bit = htm_bits_32(opcode, 1, 1);

	switch (branch_type) {
	case 0: /* I - Form  */
		if (msb_mode == 2) {

			target_ea = (htm_bits_32(opcode, 4, 10) << 17 |
				     htm_bits_32(opcode, 15, 31)) << 2;
			ppc_opcode = 0x48000000 | target_ea | 0x2 | link_bit;
		} else {
			uint64_t target_ea = 0;
			uint64_t instr_ea_msb = iea >> 26;
			uint64_t disp;

			switch (msb_mode) {
			case 0:
				target_ea = (instr_ea_msb << 26);
				break;
			case 1:
				target_ea = ((instr_ea_msb+1) << 26);
				break;

			case 3:
				target_ea = ((instr_ea_msb-1) << 26);
				break;

			}

			target_ea |= (htm_bits_32(opcode, 4, 10) << 17 |
				      htm_bits_32(opcode, 15, 31)) << 2;
			disp = target_ea - iea;
			ppc_opcode = 0x48000000 | (disp & 0x03fffffc) | link_bit;
		}
		break;
	case 1: /* B - Form */
		if (msb_mode == 2) {
			bo = htm_bits_32(opcode, 5, 8) << 1;
			bo |= htm_bits_32(opcode, 13, 13);
			bi = (htm_bits_32(opcode, 10, 10) << 5) |
			     htm_bits_32(opcode, 15, 18);

			target_ea = (htm_bits_32(opcode, 4, 4) << 13 |
				    htm_bits_32(opcode, 19, 31)) << 2;
			ppc_opcode = 0x40000000 | 0x2 | target_ea |
				     bo << PPC32_BIT(10) | bi << PPC32_BIT(15) |
				     link_bit;
		} else {
			uint64_t instr_ea_msb = iea >> 16;
			uint64_t disp;

			bo = htm_bits_32(opcode, 5, 8) << 1;
			bo |= htm_bits_32(opcode, 13, 13);
			bi = (htm_bits_32(opcode, 10, 10) << 4) |
			     htm_bits_32(opcode, 15, 18);

			switch (msb_mode) {
			case 0:
				target_ea = (instr_ea_msb << 16);
				break;
			case 1:
				target_ea = ((instr_ea_msb+1) << 16);
				break;
			case 3:
				target_ea = ((instr_ea_msb-1) << 16);
				break;
			}

			target_ea |= (htm_bits_32(opcode, 4, 4) << 13 |
				    htm_bits_32(opcode, 19, 31)) << 2;
			disp = target_ea - iea;
			ppc_opcode = 0x40000000 | (disp & 0x0000fffc) |
				     bo << PPC32_BIT(10) | bi << PPC32_BIT(15) |
				     link_bit;
		}
		break;
	case 2: /* bclr */
		bo = htm_bits_32(opcode, 5, 8) << 1;
		if (bo & 2) // hint bit
			bo |= htm_bits_32(opcode, 13, 13);
		bi = (htm_bits_32(opcode, 10, 10) << 4) |
		     htm_bits_32(opcode, 15, 18);
		bh = htm_bits_32(opcode, 21, 22);

		ppc_opcode = 0x4c000020 | bo << PPC32_BIT(10) | bi << PPC32_BIT(15) |
			     bh << PPC32_BIT(20) | link_bit;

		break;
	case 3: /* bcctr, bctar, stop instructions */
		bo = htm_bits_32(opcode, 5, 8) << 1;
		if (bo & 2) // hint bit
			bo |= htm_bits_32(opcode, 13, 13);
		bi = (htm_bits_32(opcode, 10, 10) << 4) |
		     htm_bits_32(opcode, 15, 18);
		bh = htm_bits_32(opcode, 21, 22);

		switch (MAJOR_OPCODE(opcode)) {
		case 17: /* sc */
			ppc_opcode = opcode & ~0x1e0000;
			break;
		case 19:
			switch (MINOR_OPCODE(opcode)) {
			case 82: /* rfscv */
			case 18: /* rfid */
			case 274: /* hrfid */
			case 370: /* stop */
			case 146: /* rfebb */
				ppc_opcode = opcode & ~0x1e0000;
				break;
			}
			break;
		case 31: /* mtmsr, mtmsrd */
			ppc_opcode = opcode & ~0x1e0000;
			break;
		default:
			ppc_opcode = 0x4c000420 | bo << PPC32_BIT(10) | bi << PPC32_BIT(15) |
				     bh << PPC32_BIT(20) | link_bit;
			if (opcode & (1ul << PPC32_BIT(20))) {
				ppc_opcode |= 0x00000040;
			}
			break;
		}
		break;
	}
	return ppc_opcode;
}

static uint32_t insn_recode(unsigned int predecode, uint32_t opcode, uint64_t iea)
{
	uint32_t ppc_opcode = 0;
	uint32_t branch_type;
	uint32_t msb_mode;
	uint32_t linkmask;

	if (predecode != 0x100) {
		return opcode;
	}

	branch_type = (opcode >> 28) & 0x3;
	msb_mode = (opcode >> 26) & 0x3;

	if ((branch_type == 0) && !(opcode & 0x2)) {
		branch_type = 1;
	}

	if (branch_type != 0) {
		opcode = (opcode & 0xfc007fff) |
			 ((opcode << 1) & 0x03ff0000) |
			 ((opcode >> 10) & 0x00008000);
	}

	linkmask = (opcode & 0x40000000) >> 30;
	opcode = (opcode & 0xbffffffe) | linkmask;

	switch (branch_type) {
	case 0:
		if (msb_mode == 2) {
			ppc_opcode = 0x48000000 | (opcode & 0x03ffffff) | 0x2;
		} else {
			uint64_t target_ea = opcode & 0x03fffffc;
			uint64_t instr_ea_msb = iea >> 26;
			uint64_t disp;

			switch (msb_mode) {
			case 0:
				target_ea |= (instr_ea_msb << 26);
				break;
			case 1:
				target_ea |= ((instr_ea_msb+1) << 26);
				break;

			case 3:
				target_ea |= ((instr_ea_msb-1) << 26);
				break;

			}
			disp = target_ea - iea;
			ppc_opcode = 0x48000000 | (disp & 0x03fffffc) | (opcode & 0x1);
		}
		break;

	case 1:
		if (msb_mode == 2) {
			ppc_opcode = 0x40000002 | (opcode & 0x03ffffff);
		} else {
			uint64_t target_ea = opcode & 0x0000fffc;
			uint64_t instr_ea_msb = iea >> 16;
			uint64_t disp;

			switch (msb_mode) {
			case 0:
				target_ea |= (instr_ea_msb << 16);
				break;
			case 1:
				target_ea |= ((instr_ea_msb+1) << 16);
				break;
			case 3:
				target_ea |= ((instr_ea_msb-1) << 16);
				break;
			}

			disp = target_ea - iea;
			ppc_opcode = 0x40000000 | (disp & 0x0000fffc) | (opcode & 0x03ff0001);
		}
		if (predecode == 0x120 || predecode == 0x130) {
			if ((ppc_opcode & 0x00400000) == 0x00000000) {
				ppc_opcode &= 0xffdfffff;
			}
		}
		break;

	case 2:
		ppc_opcode = 0x4c000020 | (opcode & 0x03fff801);
		break;

	case 3:
		ppc_opcode = 0x4c000420 | (opcode & 0x03fff801);
		if (opcode & 0x00002000) {
			ppc_opcode |= 0x00000040;
		}
		break;

	default:
		ppc_opcode = 0xffffffff;
		printf("Unknown branch type\n");
		return ppc_opcode;
	}

#if 0
	if (branch_type > 0) {
		uint32_t bo_bits_012 = (ppc_opcode >> 23) & 0x7;
		if ((bo_bits_012 == 1) || (bo_bits_012 == 3) || (bo_bits_012 == 6)) {
			uint32_t recoded_bit_30;

			ppc_opcode &= 0xffdfffff;
			recoded_bit_30 = (ppc_opcode >> 1) & 0x1;
			ppc_opcode |= (recoded_bit_30 << 21);
		}
	}
#endif

	return ppc_opcode;
}

static int insn_demunge(uint32_t opcode, uint64_t iea, uint32_t *insn)
{
	uint32_t ppc_opcode;

	ppc_opcode = insn_recode(0x100, opcode, iea);
	if (ppc_opcode == 0xffffffff) {
		return -1;
	}

	*insn = ppc_opcode;
	return 0;
}

static int insn_demunge_p10(uint32_t opcode, uint64_t iea, uint32_t *insn)
{
	uint32_t ppc_opcode;

	ppc_opcode = insn_recode_p10(opcode, iea);
	if (ppc_opcode == 0xffffffff) {
		return -1;
	}

	*insn = ppc_opcode;
	return 0;
}

#define IS_ISEL(insn)	((MAJOR_OPCODE(insn) == 31) && (MINOR_OPCODE(insn) == 15))
#define IS_BLR(insn)	((MAJOR_OPCODE(insn) == 19) && (MINOR_OPCODE(insn) == 16))
#define IS_BCTR(insn)	((MAJOR_OPCODE(insn) == 19) && (MINOR_OPCODE(insn) == 528))

#define OPCODE_UNKNOWN	0
#define OPCODE_RFSCV	1
#define OPCODE_RFID	2
#define OPCODE_HRFID	3
#define OPCODE_SC1	4
#define OPCODE_SC2	5
#define OPCODE_SCV_LIKE	6

int opcode_type(uint32_t opcode)
{
	if (opcode == 0x4c0000a4) {
		return OPCODE_RFSCV;
	} else if (opcode == 0x4c000024) {
		return OPCODE_RFID;
	} else if (opcode == 0x4c000224) {
		return OPCODE_HRFID;
	} else if (opcode == 0x44000002) {
		return OPCODE_SC1;
	} else if (opcode == 0x44000022) {
		return OPCODE_SC2;
	} else if ((opcode & 0xFFFFF001) == 0x44000001) {
		return OPCODE_SCV_LIKE;
	} else {
		return OPCODE_UNKNOWN;
	}
}

/* This is basically ilog2() */
static unsigned int pagesize_to_shift(uint64_t size)
{
	if (size == 4096)
		return 12;
	if (size == 65536)
		return 16;
	if (size == 16777216)
		return 24;
	assert(1);
	return 0;
}

static int htm_decode_insn_p10(struct htm_decode_state *state,
			   uint64_t value)
{
	struct htm_insn_p10 insn = { { 0 } };
	struct htm_record rec;
	int nxlates = 0;
	int optype;
	int ret;

	state->stat.total_records_processed++;
	state->stat.total_instruction_scanned++;

	while ((htm_get_rec_type(value) == REC_TYPE_IEARA) ||
		((htm_get_rec_type(value) == REC_TYPE_XLATE) && (nxlates < 3))) {
		if (htm_get_rec_type(value) == REC_TYPE_XLATE) {
			ret = htm_decode_insn_xlate(state, value, &insn.xlates[nxlates]);
			if (ret < 0) {
				goto fail;
			}

			ret = htm_decode_fetch(state, &value);
			if (ret < 0) {
				goto fail;
			}
			nxlates++;
		}
		if (htm_get_rec_type(value) == REC_TYPE_IEARA) {
			ret = htm_decode_insn_ieara(state, value, &insn.ieara);
			if (ret < 0) {
				goto fail;
			}
			ret = htm_decode_fetch(state, &value);
			if (ret < 0) {
				goto fail;
			}
		}
	}

	ret = htm_decode_insn_info_p10(state, value, &insn.info);
	if (ret < 0) {
		goto fail;
	}

	state->stat.total_instructions_processed++;

	ret = htm_decode_fetch(state, &value);
	if (ret < 0) {
		goto fail;
	}

	ret = htm_decode_insn_msr(state, value, &insn.msr);
	if (ret < 0) {
		goto fail;
	}

	if (insn.info.prefix) {
		ret = htm_decode_fetch(state, &value);
		if (ret < 0) {
			goto fail;
		}

		if (!state->fn || !state->private_data) {
			insn.info.prefix = 0;
			goto prefix_done;
		}
		ret = htm_decode_insn_prefix(state, value, &insn.prefix);
		if (ret < 0) {
			/* invalid record so as invalid and retry */
			insn.info.prefix = 0;
			htm_rewind(state, value);
			goto done;
		}
	}

prefix_done:
	for (int i = 0; i < insn.info.dea || i < insn.info.dra; i++) {
		if (insn.info.dea) {
			ret = htm_decode_fetch(state, &value);
			if (ret < 0) {
				goto fail;
			}

			if (!state->fn || !state->private_data) {
				insn.info.dea = 0;
				goto dea_done;
			}

			if (insn.info.esid) {
				ret = htm_decode_insn_esid(state, value, &insn.esid);
			} else {
				ret = htm_decode_insn_dea_p10(state, value, &insn.dea[i]);
			}
			if (ret < 0) {
				/* invalid record so as invalid and retry */
				insn.info.dea = 0;
				insn.info.dra = 0;
				htm_rewind(state, value);
				goto done;
			}
		}

dea_done:
		if (insn.info.dra) {
			ret = htm_decode_fetch(state, &value);
			if (ret < 0) {
				goto fail;
			}

			if (!state->fn || !state->private_data) {
				insn.info.dra = 0;
				goto done;
			}

			if (insn.info.esid) {
				ret = htm_decode_insn_vsid(state, value, &insn.vsid);
			} else {
				ret = htm_decode_insn_dra_p10(state, value, &insn.dra[i]);
			}
			if (ret < 0) {
				/* invalid record so mark so dra as invalid and retry */
				insn.info.dra = 0;
				htm_rewind(state, value);
				goto done;
			}
		}
	}

done:
	if (insn.ieara.valid) {
		state->insn_addr = insn.ieara.address;
		state->insn_real_addr = insn.ieara.real_address;
	}

	state->insn_addr = (state->insn_addr & ~0x7f) | insn.info.eabits;

	if (insn.info.branch && !IS_ISEL(insn.info.opcode)) {
		ret = insn_demunge_p10(insn.info.opcode, state->insn_addr, &state->insn);
		if (ret < 0) {
			goto fail;
		}
	} else {
		state->insn = insn.info.opcode;
	}

	if (IS_BLR(state->insn) || IS_BCTR(state->insn)) {
		state->insn &= ~0xe000;
	}

	// FIXME: skip if stats only
	bb_ea_log(state->insn_addr);

	ppcstats_log_inst(state->insn_addr, state->insn);
	if (!state->fn || !state->private_data)
		return 0;

	optype = opcode_type(state->insn);
	if (optype == OPCODE_RFSCV ||
	    optype == OPCODE_RFID ||
	    optype == OPCODE_HRFID ||
	    optype == OPCODE_SC1 ||
	    optype == OPCODE_SC2 ||
	    optype == OPCODE_SCV_LIKE) {
		insn.info.branch = true;
	}

	state->prev_addr = state->insn_addr;
	state->prev_insn_branch = insn.info.branch;

	rec.type = HTM_RECORD_INSN;
	rec.insn.insn = insn.info.prefix ? insn.prefix.prefix : state->insn;
	rec.insn.insn_addr = state->insn_addr;
	rec.insn.branch = insn.info.branch;
	rec.insn.conditional_branch = is_conditional_branch(rec.insn.insn);

	if (!insn.info.esid && state->insn_page_size) {
		rec.insn.insn_ra_valid = true;
		rec.insn.insn_ra = state->insn_real_addr |
			(state->insn_addr & ((1ul << state->insn_page_size) - 1));
		rec.insn.insn_page_shift_valid = true;
		rec.insn.insn_page_shift = state->insn_page_size;
	} else {
		rec.insn.insn_ra_valid = false;
		rec.insn.insn_page_shift_valid = false;
	}

	if (!insn.info.esid && insn.info.dea) {
		rec.insn.data_addr_valid = true;
		rec.insn.data_addr = insn.dea[0].address;
	} else {
		rec.insn.data_addr_valid = false;
	}

	if (insn.info.dra && !insn.info.esid && state->data_page_size) {
		rec.insn.data_ra_valid = true;
		rec.insn.data_ra = insn.dra[0].page_address;
		if (rec.insn.data_addr_valid)
			/* Pull the page offset out of the dea */
			rec.insn.data_ra |= insn.dea[0].address &
				((1 << state->data_page_size) - 1);

		rec.insn.data_page_shift_valid = true;
		rec.insn.data_page_shift = state->data_page_size;
	} else {
		rec.insn.data_ra_valid = false;
		rec.insn.data_page_shift_valid = false;
	}

	if (state->fn && state->private_data)
		state->fn(&rec, state->private_data);

	if (insn.info.prefix) {
		memset(&rec, 0, sizeof(rec));
		rec.type = HTM_RECORD_INSN;
		rec.insn.insn = state->insn;
		rec.insn.insn_addr = state->insn_addr + 4;

		if (state->fn && state->private_data)
			state->fn(&rec, state->private_data);
	}

	return 0;

fail:
	return ret;
}

static int htm_decode_insn(struct htm_decode_state *state,
			   uint64_t value)
{
	struct htm_insn insn = { { 0 } };
	struct htm_record rec;
	uint64_t tlb_flags, tlb_pagesize;
	int optype;
	int ret;

	state->stat.total_records_processed++;
	state->stat.total_instruction_scanned++;

	ret = htm_decode_insn_info(state, value, &insn.info);
	if (ret < 0) {
		goto fail;
	}

	if (insn.info.valid) {
		state->stat.total_instructions_processed++;
	} else {
		goto fail;
	}

	insn.info.software_tlb = false;
	if (insn.info.iea) {
		ret = htm_decode_fetch(state, &value);
		if (ret < 0) {
			goto fail;
		}

		ret = htm_decode_insn_iea(state, value, &insn.iea);
		if (ret < 0) {
			/* invalid record so as invalid and retry */
			insn.info.iea = 0;
			insn.info.ira = 0;
			insn.info.dea = 0;
			insn.info.dra = 0;
			state->insn_addr += 4;
			htm_rewind(state, value);
			goto done;
		} else {
			state->insn_addr = insn.iea.address;
			tlb_flags = insn.iea.msrir ? TLB_FLAGS_RELOC : 0;
			/* Only lookup translation in the TLB if we
			 * didn't get one in the trace
			 */
			if ((state->fn && state->private_data) &&
			    (!insn.info.ira &&
			     tlb_ra_get(state->insn_addr, tlb_flags,
					&insn.ira.address, &tlb_pagesize))){
				insn.info.ira = true;
				insn.ira.page_size = pagesize_to_shift(tlb_pagesize);
				insn.ira.esid_to_irpn = 0; // FIXME ??
				insn.info.software_tlb = true;
			}
		}
	} else {
		state->insn_addr += 4;
	}
	// FIXME: skip if stats only
	bb_ea_log(state->insn_addr);

	if (insn.info.ira & !insn.info.software_tlb) {
		ret = htm_decode_fetch(state, &value);
		if (ret < 0) {
			goto fail;
		}
		if (!state->fn || !state->private_data) {
			insn.info.ira = 0;
			goto ira_done;
		}

		ret = htm_decode_insn_ira(state, value, &insn.ira);
		if (ret < 0) {
			/* invalid record so as invalid and retry */
			insn.info.ira = 0;
			insn.info.dea = 0;
			insn.info.dra = 0;
			htm_rewind(state, value);
			goto done;
		}

		if (insn.ira.page_size == 12) {
			state->stat.total_instruction_pages_4k++;
		} else if (insn.ira.page_size == 16) {
			state->stat.total_instruction_pages_64k++;
		} else if (insn.ira.page_size == 24) {
			state->stat.total_instruction_pages_16m++;
		}

		if (insn.info.esid) {
			state->stat.instructions_with_i_vsid++;
		} else {
			state->stat.instructions_without_i_vsid++;
		}

		tlb_flags = insn.iea.msrir ? TLB_FLAGS_RELOC : 0;
		tlb_pagesize = 1 << insn.ira.page_size;

		tlb_ra_set(state->insn_addr, tlb_flags, insn.ira.address,
			   tlb_pagesize);
		state->stat.instructions_with_ira++;
	} else {
		state->stat.instructions_without_ira++;
	}
ira_done:

	if (insn.info.dea) {
		ret = htm_decode_fetch(state, &value);
		if (ret < 0) {
			goto fail;
		}

		if (!state->fn || !state->private_data){
			insn.info.dea = 0;
			goto dea_done;
		}

		if (insn.info.esid) {
			ret = htm_decode_insn_esid(state, value, &insn.esid);
		} else {
			ret = htm_decode_insn_dea(state, value, &insn.dea);
		}
		if (ret < 0) {
			/* invalid record so as invalid and retry */
			insn.info.dea = 0;
			insn.info.dra = 0;
			htm_rewind(state, value);
			goto done;
		}
	}

dea_done:
	if (insn.info.dra == 1) {
		ret = htm_decode_fetch(state, &value);
		if (ret < 0) {
			goto fail;
		}

		if (!state->fn || !state->private_data){
			insn.info.dra = 0;
			goto done;
		}

		if (insn.info.esid) {
			ret = htm_decode_insn_vsid(state, value, &insn.vsid);
		} else {
			ret = htm_decode_insn_dra(state, value, &insn.dra);
		}
		if (ret < 0) {
			/* invalid record so mark so dra as invalid and retry */
			insn.info.dra = 0;
			htm_rewind(state, value);
			goto done;
		}

		if (insn.info.esid) {
			if (insn.vsid.segment_size == 0) {
				state->stat.total_vsid_with_segment_0++;
			} else if (insn.vsid.segment_size == 1) {
				state->stat.total_vsid_with_segment_1++;
			} else if (insn.vsid.segment_size == 2) {
				state->stat.total_vsid_with_segment_2++;
			} else if (insn.vsid.segment_size == 3) {
				state->stat.total_vsid_with_segment_3++;
			}

			state->stat.instructions_with_d_vsid++;
		} else {
			if (insn.dra.page_size == 1) {
				state->stat.total_data_pages_4k++;
			} else if (insn.dra.page_size == 2) {
				state->stat.total_data_pages_64k++;
			} else if (insn.dra.page_size == 3) {
				state->stat.total_data_pages_16m++;
			}

			state->stat.instructions_without_d_vsid++;
		}
	}
done:
	if (insn.info.branch && !IS_ISEL(insn.info.opcode)) {
		ret = insn_demunge(insn.info.opcode, state->insn_addr, &state->insn);
		if (ret < 0) {
			goto fail;
		}
	} else {
		state->insn = insn.info.opcode;
	}

	if (IS_BLR(state->insn) || IS_BCTR(state->insn)) {
		state->insn &= ~0xe000;
	}

	ppcstats_log_inst(state->insn_addr, state->insn);
	if (!state->fn || !state->private_data)
		return 0;

	optype = opcode_type(state->insn);
	if (optype == OPCODE_RFSCV ||
	    optype == OPCODE_RFID ||
	    optype == OPCODE_HRFID ||
	    optype == OPCODE_SC1 ||
	    optype == OPCODE_SC2 ||
	    optype == OPCODE_SCV_LIKE) {
		insn.info.branch = true;
	}

	if (state->prev_addr != 0 &&
	    state->insn_addr != 0 &&
	    state->prev_addr + 4 != state->insn_addr) {
		insn.info.branch = true;

		if (!state->prev_insn_branch) {
			if ((state->insn_addr & 0xfffffffffffff07fULL) == 0) {
				state->stat.total_interrupts++;
			}
		} else {
			state->stat.total_branches_after_nonbranches++;
		}
	}

	state->prev_addr = state->insn_addr;
	state->prev_insn_branch = insn.info.branch;

	rec.type = HTM_RECORD_INSN;
	rec.insn.insn = state->insn;
	rec.insn.insn_addr = state->insn_addr;

	if (insn.info.ira && !insn.info.esid && insn.ira.page_size > 0) {
		rec.insn.insn_ra_valid = true;
		rec.insn.insn_ra = insn.ira.address;
		rec.insn.insn_page_shift_valid = true;
		rec.insn.insn_page_shift = insn.ira.page_size;
	} else {
		rec.insn.insn_ra_valid = false;
		rec.insn.insn_page_shift_valid = false;
	}

	if (insn.info.dea) {
		rec.insn.data_addr_valid = true;
		rec.insn.data_addr = insn.dea.address;
	} else {
		rec.insn.data_addr_valid = false;
	}

	if (insn.info.dra && !insn.info.esid && insn.dra.page_size > 0) {
		rec.insn.data_ra_valid = true;
		rec.insn.data_ra = insn.dra.page_address;
		if (rec.insn.data_addr_valid)
			/* Pull the page offset out of the dea */
			rec.insn.data_ra |= insn.dea.address &
				((1 << insn.dra.page_size) - 1 );

		rec.insn.data_page_shift_valid = true;
		rec.insn.data_page_shift = insn.dra.page_size;
	} else {
		rec.insn.data_ra_valid = false;
		rec.insn.data_page_shift_valid = false;
	}

	if (state->fn && state->private_data)
		state->fn(&rec, state->private_data);

	return 0;

fail:
	return ret;
}

/**
 * return value:
 *  -1 : error
 *   0 : eof
 *   1 : success
 */
static int htm_decode_one(struct htm_decode_state *state)
{
	uint64_t value;
	unsigned int tag, type;
	int ret;

	ret = htm_decode_fetch_internal(state, &value);
	if (ret < 0) {
		return ret;
	}
	if (value == 0)
		return 1; /* skip zero data */

	tag = htm_uint32(htm_bits(value, 0, 19));
	if (tag == 0xACEFF) {
		ret = htm_decode_stamp(state, value);
	} else {
		type = htm_insn_type(value);
		if (type == 0xABCDE) {
			ret = htm_decode_insn(state, value);
		} else if (type == 0xABCDF) {
			ret = htm_decode_insn_p10(state, value);
		}
		if (ret == -2) {
			/*
			 * Incomplete instruction sequence.
			 * Retry as next record.
			 */
			htm_rewind(state, value);
		}
	}

	if (ret < 0) {
		printf("Invalid record:%d offset:%li data:%016"PRIx64" \n",
		       state->nr, state->read_offset, value);
		if (state->error_count++ > 100) {
			printf("Trace corrupted too badly to parse\n");
			assert(0);
		}

		return 1;
	} else {
		state->error_count = 0;
	}

	return 1;
}

/**
 * return value:
 *  -1 : error
 *   0 : success
 */
int htm_decode(int fd, htm_record_fn_t fn, void *private_data,
	       struct htm_decode_stat *result)
{
	int ret;

	struct archive *a = archive_read_new();
	struct archive_entry *ae;
	int r;

	archive_read_support_filter_all(a);
	archive_read_support_format_all(a);
	archive_read_support_format_raw(a);
	r = archive_read_open_fd(a, fd, 16384);
	if (r != ARCHIVE_OK) {
		fprintf(stderr, "File not ok \n");
		return 1;
	}
	r = archive_read_next_header(a, &ae);
	if (r != ARCHIVE_OK) {
		fprintf(stderr, "File not ok \n");
		return 1;
	}

	struct htm_decode_state state = {
		.fn = fn,
		.a = a,
		.read_offset = 0,
		.private_data = private_data,
	};

	tlb_init();
	bb_init();

	do {
		ret = htm_decode_one(&state);
	} while (ret > 0);

	if (result != NULL) {
		*result = state.stat;
	}

	tlb_exit();

	return ret;
}

