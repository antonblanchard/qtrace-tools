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
	bool is_conditional_branch;
	bool is_unconditional_branch;
};

#endif
