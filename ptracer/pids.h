#ifndef __PIDS_H__
#define __PIDS_H__

#include <unistd.h>
#include <sys/types.h>

#define MAX_PIDS 30000

struct pid {
	unsigned long pid;
	int perf_fd;
};

extern int nr_pids;
extern struct pid pids[];

struct pid *add_pid(pid_t pid);
struct pid *find_pid(pid_t pid);
void remove_pid(pid_t pid);
#endif
