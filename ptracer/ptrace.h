#ifndef __PTRACE_H__
#define __PTRACE_H__

#include <stdint.h>
#include <sys/types.h>

#define PTRACE_SEIZE_OPTIONS (PTRACE_O_TRACECLONE|PTRACE_O_TRACEVFORK|PTRACE_O_TRACEFORK|PTRACE_O_TRACEEXIT|PTRACE_O_TRACEEXEC)

uint32_t *read_pc(pid_t pid);
uint32_t read_insn(pid_t pid, uint32_t *pc);
void write_insn(pid_t pid, uint32_t *pc, uint32_t insn);
void capture_all_threads(pid_t pid);
void release_all_non_tracing_threads(pid_t pid);
void detach_all_threads(void);
pid_t do_exec(char *argv[]);
#endif
