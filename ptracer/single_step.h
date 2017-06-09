#ifndef __SINGLE_STEP_H__
#define __SINGLE_STEP_H__
#include <stdint.h>
#include <stdbool.h>

bool is_larx(uint32_t insn);
typedef void (*callback)(pid_t pid, uint32_t *pc);
unsigned long step_over_atomic(pid_t pid, uint32_t *p, callback fn);
void single_step_untraced(pid_t pid);
#endif
