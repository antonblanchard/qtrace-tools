#ifndef __QTWRITER_H__
#define __QTWRITER_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

#include "qtrace_record.h"

struct qtwriter_state {
	uint32_t version;
	uint32_t magic;
	struct qtrace_record prev_record;
	bool header_written;
	int fd;
	void *mem;
	size_t size;
	void *ptr;
};

bool qtwriter_open(struct qtwriter_state *state, char *filename,
		   uint32_t magic);
bool qtwriter_write_record(struct qtwriter_state *state,
			   struct qtrace_record *record);
void qtwriter_close(struct qtwriter_state *state);

#ifdef __cplusplus
}
#endif

#endif
