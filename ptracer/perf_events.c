/*
 * Copyright (C) 2017 Anton Blanchard <anton@au.ibm.com>, IBM
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include <linux/perf_event.h>

#include "pids.h"
#include "perf_events.h"

static long sys_perf_event_open(struct perf_event_attr *attr, pid_t pid,
				int cpu, int group_fd, unsigned long flags)
{
	return syscall(SYS_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static void setup_sigio(unsigned long pid, int fd)
{
	/*
	 * We want the thread to stop when the counter overflows, so we
	 * send the signal in band and consume it via ptrace()
	 */
	if (fcntl(fd, F_SETFL, O_NONBLOCK|O_ASYNC) == -1) {
		perror("fnctl(F_SETFL)");
		exit(1);
	}

	/* Use a signal that is almost certainly unused */
	if (fcntl(fd, F_SETSIG, SIGSTKFLT) == -1) {
		perror("fnctl(F_SETSIG)");
		exit(1);
	}

	if (fcntl(fd, F_SETOWN, pid) == -1) {
		perror("fnctl(F_SETOWN)");
		exit(1);
	}
}

static void setup_insn_counter(struct pid *pid, unsigned long insns)
{
	struct perf_event_attr attr;

	memset(&attr, 0, sizeof(attr));

	attr.size = sizeof(attr);

	/* Count userspace instructions only */
	attr.exclude_kernel = 1;
	attr.exclude_hv = 1;
	attr.exclude_idle = 1;

	/* Enable on exec */
	attr.disabled = 1;
	attr.enable_on_exec = 1;

	/* Count instructions */
	attr.type = PERF_TYPE_HARDWARE;
	attr.config = PERF_COUNT_HW_INSTRUCTIONS;
	attr.sample_period = insns;

	pid->perf_fd = sys_perf_event_open(&attr, pid->pid, -1, -1, 0);
	if (pid->perf_fd < 0) {
		perror("sys_perf_event_open");
		exit(1);
	}

	setup_sigio(pid->pid, pid->perf_fd);

	if (ioctl(pid->perf_fd, PERF_EVENT_IOC_RESET, 0) == -1) {
		perror("ioctl(PERF_EVENT_IOC_RESET)");
		exit(1);
	}

	/* Counters will pause on first overflow */
	if (ioctl(pid->perf_fd, PERF_EVENT_IOC_REFRESH, 1) == -1) {
		perror("ioctl(PERF_EVENT_IOC_REFRESH)");
		exit(1);
	}
}

static void destroy_insn_counter(struct pid *pid)
{
	if ((ioctl(pid->perf_fd, PERF_EVENT_IOC_DISABLE)) == -1) {
		perror("ioctl(PERF_EVENT_IOC_DISABLE)");
		exit(1);
	}

	close(pid->perf_fd);
}

/*
 * The PMU won't stop exactly on the instruction we want, so stop a little
 * early. The main loop will single step the rest for us.
 */
#define SLACK 100

/*
 * We count instructions across all threads and choose the first one that
 * hits the instruction count.
 */
unsigned long fast_forward(unsigned long *nr_insns)
{
	unsigned long i;
	pid_t pid;
	unsigned long res;
	unsigned long long count;

	/* Set up a counter on all threads */
	for (i = 0; i < nr_pids; i++)
		setup_insn_counter(&pids[i], *nr_insns - SLACK);

	/* We enter with all threads stopped, so start all threads. */
	for (i = 0; i < nr_pids; i++) {
		if (ptrace(PTRACE_CONT, pids[i].pid, 0, 0) == -1) {
			perror("fast_forward: ptrace(PTRACE_CONT)");
			exit(1);
		}
	}

	while (1) {
		int status;
		unsigned int sig = 0;
		unsigned long data;

		while ((pid = waitpid(-1, &status, __WALL)) == -1) {
			if (errno != EINTR) {
				perror("fast_forward: waitpid");
				exit(1);
			}
		}

		if (!WIFSTOPPED(status)) {
			perror("fast_forward: waitpid");
			exit(1);
		}

		if (((status >> 16) == PTRACE_EVENT_CLONE) ||
			((status >> 16) == PTRACE_EVENT_VFORK) ||
			((status >> 16) == PTRACE_EVENT_FORK)) {

			if (ptrace(PTRACE_GETEVENTMSG, pid, NULL,
				   &data) == 1) {
				perror("fast_forward: ptrace(PTRACE_GETEVENTMSG");
				exit(1);
			}

			setup_insn_counter(add_pid(data), *nr_insns - SLACK);

			if (ptrace(PTRACE_CONT, pid, 0, 0) == -1) {
				perror("fast_forward: ptrace(PTRACE_CONT)");
				exit(1);
			}

			continue;
		}

		if (((status >> 16) == PTRACE_EVENT_EXIT)) {
			destroy_insn_counter(find_pid(pid));
			remove_pid(pid);

			if (ptrace(PTRACE_DETACH, pid, 0, 0) == -1) {
				perror("main: ptrace(PTRACE_CONT)");
				exit(1);
			}

			continue;
		}

		/* One of the children stopping on clone/vfork/fork entry */
		if ((status >> 16) == PTRACE_EVENT_STOP &&
		    (WSTOPSIG(status == 0))) {
			if (ptrace(PTRACE_CONT, pid, 0, 0) == -1) {
				perror("fast_forward: ptrace(PTRACE_CONT)");
				exit(1);
			}

			continue;
		}

		if (WSTOPSIG(status) == SIGSTKFLT)
			break;

		if (WSTOPSIG(status) != SIGTRAP)
			sig = WSTOPSIG(status);

		if (ptrace(PTRACE_CONT, pid, 0, sig) == -1) {
			perror("fast_forward: ptrace(PTRACE_CONT)");
			exit(1);
		}
	}

	res = read(find_pid(pid)->perf_fd, &count, sizeof(count));
	if (res != sizeof(count)) {
		fprintf(stderr, "fast_forward: perf read returned %ld, expected %ld\n", res,
			sizeof(count));
	}
	*nr_insns -= count;

	for (i = 0; i < nr_pids; i++)
		destroy_insn_counter(&pids[i]);

	/* We return with the tracing thread stopped */

	return pid;
}
