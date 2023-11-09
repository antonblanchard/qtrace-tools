/*
 * Copyright (C) 2018 Amitay Isaacs <aisaacs@au.ibm.com>, IBM
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

#include <qtlib/qtwriter.h>

#include <ppcstats.h>
#include "htm.h"
#include "tlb.h"
#include "bb.h"

static void print_record_record(struct htm_record_record *r)
{
	printf("REC  ");
	printf("counter = %d", r->counter);
	printf("\n");
}

static void print_record_complete(struct htm_record_complete *r)
{
	printf("END  ");
	printf("cycles = %d", r->elapsed_time);
	printf("\n");
}

static void print_record_pause(struct htm_record_pause *r)
{
	printf("PAUSE");
	printf("cycles = %d", r->elapsed_time);
	printf("\n");
}

static void print_record_mark(struct htm_record_mark *r)
{
	printf("MARK ");
	printf("group = %d, chip = %d, unit = %d, marker = %d, set = %d",
	       r->group_id, r->chip_id, r->unit_id, r->marker_info, r->marker_dropped);
	printf("\n");
}

static void print_record_sync(struct htm_record_sync *r)
{
	printf("SYNC ");
	printf("\n");
}

static void print_record_time(struct htm_record_time *r)
{
	printf("TIME ");
	if (r->normal_timestamp) {
		printf("cycles = %d", r->elapsed_time);
	} else if (r->marker_dropped) {
		printf("markers dropped");
	} else if (r->record_dropped_counter_overflow) {
		printf("record dropped counter overflow, counter= %d", r->record_dropped_counter);
	} else if (r->elapsed_time_overflow) {
		printf("elapsed time overflow");
	} else if (r->cresp_record_dropped) {
		printf("CResp record dropped");
	} else if (r->trigger_dropped) {
		printf("trigger dropped");
	} else if (r->trace_full_asserted) {
		printf("trace full asserted");
	}
	printf("\n");
}

static void print_record_insn(struct qtrace_record *r)
{
	printf("INSN ");
	printf(" iea:%016"PRIx64, r->insn_addr);
	printf(" op:%08x", r->insn);
	if (r->insn_ra_valid)
		printf(" ira:%016"PRIx64, r->insn_ra);
	if (r->insn_page_shift_valid)
		printf(" ipgsize:%i", r->insn_page_shift);
	if (r->data_addr_valid)
		printf(" dea:%016"PRIx64, r->data_addr);
	if (r->data_ra_valid)
		printf(" dra:%016"PRIx64, r->data_ra);
	if (r->data_page_shift_valid)
		printf(" dpgsize:%i", r->data_page_shift);
	printf("\n");
}

struct decoder_state {
	struct qtwriter_state qt;
	bool debug, detail;
};

static void print_record(struct htm_record *rec, void *private_data)
{
	struct decoder_state *state = (struct decoder_state *)private_data;

	switch (rec->type) {
		case HTM_RECORD_RECORD:
			if (state->debug) {
				print_record_record(&rec->record);
			}
			break;

		case HTM_RECORD_COMPLETE:
			if (state->debug) {
				print_record_complete(&rec->complete);
			}
			break;

		case HTM_RECORD_PAUSE:
			if (state->debug) {
				print_record_pause(&rec->pause);
			}
			break;

		case HTM_RECORD_MARK:
			if (state->debug) {
				print_record_mark(&rec->mark);
			}
			break;

		case HTM_RECORD_SYNC:
			if (state->debug) {
				print_record_sync(&rec->sync);
			}
			break;

		case HTM_RECORD_TIME:
			if (state->debug) {
				print_record_time(&rec->time);
			}
			break;

		case HTM_RECORD_INSN:
			if (state->debug || state->detail) {
				print_record_insn(&rec->insn);
			}
			qtwriter_write_record(&state->qt, &rec->insn);
			break;

		default:
			printf("UNKNOWN record\n");
	}
}

static void print_stat(struct htm_decode_stat *stat)
{
	printf("%48s : 0x%016"PRIx64"\n", "RAW Checksum", stat->checksum);
	printf("%48s : %u\n", "Total Records Scanned", stat->total_records_scanned);
	printf("%48s : %u\n", "Total Records Processed", stat->total_records_processed);
	printf("%48s : %u\n", "Total Instructions Scanned", stat->total_instruction_scanned);
	printf("%48s : %u\n", "Total Instructions Processed", stat->total_instructions_processed);
	printf("%48s : %u\n", "Total TimeStamps Scanned", stat->total_timestamps_scanned);
	printf("%48s : %u\n", "Total TimeStamps Processed", stat->total_timestamps_processed);
	printf("%48s : %u\n", "Total Cycles for Processed Instructions", stat->total_cycles);
	printf("%48s : %u\n", "Total Interrupts Processed", stat->total_interrupts);
	printf("%48s : %u\n", "Total Branches taken after Non branches", stat->total_branches_after_nonbranches);
	printf("%48s : %u\n", "Pipeline CPI", stat->pipeline_cpi);
	printf("%48s : %u\n", "CHTM CPI", stat->chtm_cpi);
	printf("%48s : %u\n", "Unique ESIDs with IRPNs", stat->unique_esid_with_irpn);
	printf("%48s : %u\n", "Unique ESIDs without IRPNs", stat->unique_esid_without_irpn);
	printf("%48s : %u\n", "Instructions with IRAs", stat->instructions_with_ira);
	printf("%48s : %u\n", "Instructions without IRAs", stat->instructions_without_ira);
	printf("%48s : %u\n", "SLBMTE Instructions", 0);
	printf("%48s : %u\n", "SLBIA Instructions", 0);
	printf("%48s : %u\n", "RFID Instructions", 0);
	printf("%48s : %u\n", "Total Instructions With I-VSIDs", stat->instructions_with_i_vsid);
	printf("%48s : %u\n", "Total Instructions Without I-VSIDs", stat->instructions_without_i_vsid);
	printf("%48s : %u\n", "Total Instructions With D-VSIDs", stat->instructions_with_d_vsid);
	printf("%48s : %u\n", "Total Instructions Without D-VSIDs", stat->instructions_without_d_vsid);
	printf("%48s : %u\n", "Total Instruction Records with ESID record", stat->total_instructions_with_esid);
	printf("%48s : %u\n", "Total Instruction Records with VSID record", stat->total_instructions_with_vsid);
	printf("%48s : %u\n", "Total VSID records with Segment Size 0", stat->total_vsid_with_segment_0);
	printf("%48s : %u\n", "Total VSID records with Segment Size 1", stat->total_vsid_with_segment_1);
	printf("%48s : %u\n", "Total VSID records with Segment Size 2", stat->total_vsid_with_segment_2);
	printf("%48s : %u\n", "Total VSID records with Segment Size 3", stat->total_vsid_with_segment_3);
	printf("%48s : %u\n", "Total Instructions With I-XLATEs", stat->instructions_with_i_xlate);
	printf("%48s : %u\n", "Total Instructions missing I-XLATEs ERAT", stat->instructions_without_i_xlate_erat);
	printf("%48s : %u\n", "Total Instructions missing I-XLATEs PWC", stat->instructions_without_i_xlate_pwc);
	printf("%48s : %u\n", "Total Instructions missing I-XLATEs without IEARA", stat->instructions_without_i_xlate_ieara);
	printf("%48s : %u\n", "Total Instructions With D-XLATEs", stat->instructions_with_d_xlate);
	printf("%48s : %u\n", "Total Instructions Without D-XLATEs ERAT", stat->instructions_without_d_xlate_erat);
	printf("%48s : %u\n", "Total Instructions Without D-XLATEs PWC", stat->instructions_without_d_xlate_pwc);
	printf("%48s : %u\n", "4K data pages", stat->total_data_pages_4k);
	printf("%48s : %u\n", "64K data pages", stat->total_data_pages_64k);
	printf("%48s : %u\n", "2M data pages", stat->total_data_pages_2m);
	printf("%48s : %u\n", "16M data pages", stat->total_data_pages_16m);
	printf("%48s : %u\n", "1G data pages", stat->total_data_pages_1g);
	printf("%48s : %u\n", "4K instruction pages", stat->total_instruction_pages_4k);
	printf("%48s : %u\n", "64K instruction pages", stat->total_instruction_pages_64k);
	printf("%48s : %u\n", "2M instruction pages", stat->total_instruction_pages_2m);
	printf("%48s : %u\n", "16M instruction pages", stat->total_instruction_pages_16m);
	printf("%48s : %u\n", "1G instruction pages", stat->total_instruction_pages_1g);
	tlb_dump();
}

static void usage(const char *prog)
{
	fprintf(stderr, "Usage: %s [-Ddsib]... [-o <outfile.qt>] <htmdump>\n\n", prog);
	fprintf(stderr, "\t-D \t\t\tDebug info\n");
	fprintf(stderr, "\t-d \t\t\tDump with some details\n");
	fprintf(stderr, "\t-s \t\t\tDump stats\n");
	fprintf(stderr, "\t-i \t\t\tDump instruction mix\n");
	fprintf(stderr, "\t-b \t\t\tBasic block anaylsis\n");
}

int main(int argc, char * const argv[])
{
	struct decoder_state state;
	struct htm_decode_stat stat;
	const char *input = NULL;
	const char *output = NULL;
	char path[PATH_MAX];
	int opt, ret, fd;
	bool debug = false;
	bool detail = false;
	bool show_stats_only = false;
	bool show_imix_only = false;
	bool basic_block_only = false;

	while ((opt = getopt(argc, argv, "Ddo:sib")) != -1) {
		switch (opt) {
			case 'D':
				debug = true;
				detail = true;
				break;

			case 'd':
				detail = true;
				break;

			case 'o':
				output = optarg;
				break;

			case 's':
				show_stats_only = true;
				break;

			case 'i':
				show_imix_only = true;
				break;

			case 'b':
				basic_block_only = true;
				break;

			default: /* '?' */
				usage(argv[0]);
				exit(0);
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "Expected arguments after options\n");
		usage(argv[0]);
		exit(1);
	}

	input = argv[optind];
	if (output == NULL) {
		ret = snprintf(path, sizeof(path), "%s.qt", input);
	} else {
		if (show_stats_only || basic_block_only || show_imix_only) {
			fprintf(stderr, "ERROR: -s/-i/-b and -o options incompatible\n");
			exit(1);
		}
		ret = snprintf(path, sizeof(path), "%s", output);
	}
	if (ret >= sizeof(path)) {
		fprintf(stderr, "Output file name too long\n");
		exit(1);
	}

	fd = open(input, O_RDONLY);
	if (fd == -1) {
		fprintf(stderr, "Failed to open %s - %s\n",
			argv[1], strerror(errno));
		exit(1);
	}


	if (show_stats_only || show_imix_only) {
		uint64_t flags = 0;
		if (show_stats_only)
			flags |= PPCSTATS_STATS;
		if (show_imix_only)
			flags |= PPCSTATS_IMIX;
		ppcstats_init(flags);
	}

	if (!show_stats_only && !basic_block_only && !show_imix_only) {
		if (!qtwriter_open(&state.qt, path, 0)) {
			fprintf(stderr, "Failed to open output file %s\n", path);
			close(fd);
			exit(1);
		}
		state.debug = debug;
		state.detail = detail;

		htm_decode(fd, print_record, &state, &stat);
	} else
		htm_decode(fd, NULL, NULL, &stat);

	if (detail || debug) {
		print_stat(&stat);
	}

	/* FIXME: This is a layering violation, but YOLO */
	if (show_stats_only || show_imix_only)
		ppcstats_print();

	if (basic_block_only)
		bb_dump();

	if (!show_stats_only && !basic_block_only && !show_imix_only)
		qtwriter_close(&state.qt);
	close(fd);

	exit(0);
}
