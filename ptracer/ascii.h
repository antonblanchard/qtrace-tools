#ifndef __ASCII_H__
#define __ASCII_H__

#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>

FILE *ascii_fout;

void ascii_open(char *filename);
void ascii_close(void);
void ascii_add_record(pid_t pid, uint32_t insn, uint32_t *insn_addr);

#endif
