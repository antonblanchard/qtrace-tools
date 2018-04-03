#include <string.h>

#include "qtrace.h"
#include "qtwriter.h"

int main(void)
{
	struct qtwriter_state state;
	struct qtrace_record record;

	memset(&state, 0, sizeof(state));
	state.version = 0x10000000;

	qtwriter_open(&state, "test.qt", 0);

	memset(&record, 0, sizeof(record));
	record.insn = 0x60000000;
	record.insn_addr = 0x10000000;
	qtwriter_write_record(&state, &record);

	record.insn_addr = 0x10000004;
	qtwriter_write_record(&state, &record);

	record.insn_addr = 0x10000008;
	record.data_addr_valid = true;
	record.data_addr = 0xacebabe;
	qtwriter_write_record(&state, &record);

	qtwriter_close(&state);
}
