#ifndef __PPC_STORAGE_H__
#define __PPC_STORAGE_H__

#include <stdint.h>

bool is_storage_insn(uint32_t insn, unsigned long *gprs, unsigned long *addr,
		     unsigned long *size);

#endif
