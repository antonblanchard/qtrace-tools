#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>

#include "pids.h"

int nr_pids;
struct pid pids[MAX_PIDS];

#ifdef DEBUG
static void dump_pids(void)
{
	unsigned long i;

	for (i = 0; i < nr_pids; i++)
		printf("%d %d\n", i, pids[i].pid);
}
#endif

struct pid *add_pid(pid_t pid)
{
	struct pid *p;

	if (nr_pids == MAX_PIDS) {
		fprintf(stderr, "Too many threads, need to bump MAX_PIDS\n");
		return NULL;
	}

	p = &pids[nr_pids++];
	p->pid = pid;

	return p;
}

struct pid *find_pid(pid_t pid)
{
	unsigned long i;

	for (i = 0; i < nr_pids; i++) {
		if (pids[i].pid == pid)
			break;
	}

	if (i == nr_pids) {
		fprintf(stderr, "WARNING: unknown pid %d\n", pid);
		return NULL;
	}

	return &pids[i];
}

void remove_pid(pid_t pid)
{
	unsigned long i;

	for (i = 0; i < nr_pids; i++) {
		if (pids[i].pid == pid)
			break;
	}

	if (i == nr_pids) {
		fprintf(stderr, "WARNING: unknown pid %d\n", pid);
		return;
	}

	for (; i < (nr_pids-1); i++)
		pids[i] = pids[i+1];

	nr_pids--;
}
