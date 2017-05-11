#include <stdint.h>

void qtrace_open(char *filename);
void qtrace_close(void);
void qtrace_add_record(uint32_t insn, unsigned long insn_addr);
void qtrace_add_storage_record(uint32_t insn, unsigned long insn_addr,
			       unsigned long storage_addr,
			       unsigned long storage_size);
