/*
 * Copyright (C) 2018 Amitay Isaacs <aisaacs@au.ibm.com>, IBM
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#ifndef __HTM_H__
#define __HTM_H__

#include <inttypes.h>
#include <stdbool.h>

#include <qtlib/qtrace_record.h>

enum htm_record_type {
	HTM_RECORD_RECORD = 1,
	HTM_RECORD_COMPLETE,
	HTM_RECORD_PAUSE,
	HTM_RECORD_MARK,
	HTM_RECORD_SYNC,
	HTM_RECORD_TIME,
	HTM_RECORD_INSN,
};

struct htm_record_record {
	unsigned int counter;
};

struct htm_record_complete {
	unsigned int elapsed_time;
};

struct htm_record_pause {
	unsigned int elapsed_time;
};

struct htm_record_mark {
	unsigned int group_id;
	unsigned int chip_id;
	unsigned int unit_id;
	unsigned int marker_info;
	bool marker_dropped;
};

struct htm_record_sync {
};

struct htm_record_time {
	bool normal_timestamp;
	unsigned int elapsed_time;
	bool marker_dropped;
	bool record_dropped_counter_overflow;
	unsigned int record_dropped_counter;
	bool elapsed_time_overflow;
	bool cresp_record_dropped;
	bool trigger_dropped;
	bool trace_full_asserted;
};

struct htm_record {
	enum htm_record_type type;
	union {
		struct htm_record_record record;
		struct htm_record_complete complete;
		struct htm_record_pause pause;
		struct htm_record_mark mark;
		struct htm_record_sync sync;
		struct htm_record_time time;
		struct qtrace_record insn;
	};
};

struct htm_decode_stat {
	uint64_t checksum;

	unsigned int total_records_scanned;
	unsigned int total_records_processed;
	unsigned int total_instruction_scanned;
	unsigned int total_instructions_processed;
	unsigned int total_timestamps_scanned;
	unsigned int total_timestamps_processed;
	unsigned int total_cycles;
	unsigned int total_interrupts;
	unsigned int total_branches_after_nonbranches;
	unsigned int pipeline_cpi;
	unsigned int chtm_cpi;
	unsigned int unique_esid_with_irpn;
	unsigned int unique_esid_without_irpn;
	unsigned int instructions_with_ira;
	unsigned int instructions_without_ira;

	unsigned int instructions_with_i_vsid;
	unsigned int instructions_without_i_vsid;
	unsigned int instructions_with_d_vsid;
	unsigned int instructions_without_d_vsid;
	unsigned int total_instructions_with_esid;
	unsigned int total_instructions_with_vsid;
	unsigned int total_vsid_with_segment_0;
	unsigned int total_vsid_with_segment_1;
	unsigned int total_vsid_with_segment_2;
	unsigned int total_vsid_with_segment_3;
	unsigned int total_data_pages_4k;
	unsigned int total_data_pages_64k;
	unsigned int total_data_pages_16m;
	unsigned int total_instruction_pages_4k;
	unsigned int total_instruction_pages_64k;
	unsigned int total_instruction_pages_16m;
};

typedef void (*htm_record_fn_t)(struct htm_record *rec, void *private_data);

int htm_decode(int fd, htm_record_fn_t fn, void *private_data,
	       struct htm_decode_stat *stat);

#endif /* __HTM_H__ */
