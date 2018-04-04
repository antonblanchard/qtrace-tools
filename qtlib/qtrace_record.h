#ifndef __QTRACE_RECORD_H__
#define __QTRACE_RECORD_H__

#include <stdint.h>
#include <stdbool.h>

struct qtrace_record {
	uint32_t insn;
	uint64_t insn_addr;
	bool insn_rpn_valid;
	uint64_t insn_rpn;
	bool insn_page_size_valid;
	uint32_t insn_page_size;
	bool data_addr_valid;
	uint64_t data_addr;
	bool data_rpn_valid;
	uint64_t data_rpn;
	bool data_page_size_valid;
	uint32_t data_page_size;

	bool branch;
	bool conditional_branch;

	/*
	 * The rest of the fields are populated by qtreader if enabled,
	 * but are not required by qtwriter.
	 */
	bool branch_taken;
	bool branch_direct;
	enum branch_type {
		BRANCH,
		CALL,
		RETURN,
		ADDRESSING,
		SYSTEM_CALL_EXCEPTION,
		ASYNC_EXCEPTION,
		EXCEPTION_RETURN
	} branch_type;

	/* We might want to add BH target unpredictable and static branch hints */

	uint64_t next_insn_addr;
};

#endif
