#ifndef __QTRACE__OLD_H__
#define __QTRACE__OLD_H__

#include <stdint.h>

void qtrace_open(char *filename);
void qtrace_close(void);
void qtrace_add_record(uint32_t insn, uint32_t *insn_addr);
void qtrace_add_storage_record(uint32_t insn, uint32_t *insn_addr,
			       unsigned long storage_addr,
			       unsigned long storage_size);

#endif
