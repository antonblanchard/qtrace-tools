#ifndef __QTRACE_RECORD_H__
#define __QTRACE_RECORD_H__

#include <stdint.h>
#include <stdbool.h>
#include "qtrace.h"

enum branch_type {
	BRANCH,
	CALL,
	RETURN,
	ADDRESSING,
	SYSTEM_CALL_EXCEPTION,
	ASYNC_EXCEPTION,
	EXCEPTION_RETURN
};

struct qtrace_register_info {
	uint16_t index;
	uint64_t value;
};

#define QTRACE_MAX_GPRS_OUT  32
#define QTRACE_MAX_FPRS_OUT   3
#define QTRACE_MAX_SPRS_OUT   4
#define QTRACE_MAX_VMXRS_OUT  3
#define QTRACE_MAX_VSXRS_OUT  3

struct qtrace_reg_state {
	uint8_t nr_gprs_in;
	uint8_t nr_fprs_in;
	uint8_t nr_vmxs_in;
	uint8_t nr_vsxs_in;
	uint8_t nr_sprs_in;
	uint8_t nr_gprs_out;
	uint8_t nr_fprs_out;
	uint8_t nr_vmxs_out;
	uint8_t nr_vsxs_out;
	uint8_t nr_sprs_out;
	struct qtrace_register_info gprs_in[QTRACE_MAX_GPRS_OUT];
	struct qtrace_register_info gprs_out[QTRACE_MAX_GPRS_OUT];
	struct qtrace_register_info fprs_in[QTRACE_MAX_FPRS_OUT];
	struct qtrace_register_info fprs_out[QTRACE_MAX_FPRS_OUT];
	struct qtrace_register_info sprs_in[QTRACE_MAX_SPRS_OUT];
	struct qtrace_register_info sprs_out[QTRACE_MAX_SPRS_OUT];
};

struct qtrace_record {
	uint32_t insn;
	uint64_t insn_addr;
	bool insn_ra_valid;
	uint64_t insn_ra;
	bool insn_page_shift_valid;
	uint32_t insn_page_shift;
	bool data_addr_valid;
	uint64_t data_addr;
	bool data_ra_valid;
	uint64_t data_ra;
	bool data_page_shift_valid;
	uint32_t data_page_shift;

	bool branch;
	bool conditional_branch;

	bool guest_insn_page_shift_valid;
	uint32_t guest_insn_page_shift;

	bool guest_data_page_shift_valid;
	uint32_t guest_data_page_shift;

	/*
	 * The rest of the fields are populated by qtreader if enabled,
	 * but are not required by qtwriter.
	 */
	bool branch_taken;
	bool branch_direct;
	enum branch_type branch_type;

	struct qtrace_reg_state regs;

	bool tlbie;
	bool tlbie_local;
	uint8_t tlbie_ric;
	bool tlbie_prs;
	bool tlbie_r;
	uint8_t tlbie_is;
	uint16_t tlbie_set;
	uint32_t tlbie_page_shift;
	uint64_t tlbie_addr;
	uint32_t tlbie_lpid;
	uint32_t tlbie_pid;

	bool node_valid;
	uint8_t node;
	uint8_t term_code;
	uint8_t term_node;

	/* We might want to add BH target unpredictable and static branch hints */

	uint64_t next_insn_addr;
};

#endif
