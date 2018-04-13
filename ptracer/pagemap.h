#ifndef __PAGEMAP_H__
#define __PAGEMAP_H__

#include <stdint.h>
#include <sys/types.h>

bool init_pagemaps(pid_t pid, unsigned long basesz, unsigned long hugesz);
bool ea_to_pa(unsigned long ea, unsigned long *pa, unsigned long *pshift, bool i_side);

#endif
