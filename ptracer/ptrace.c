/*
 * Copyright (C) 2017 Anton Blanchard <anton@au.ibm.com>, IBM
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <limits.h>
#include <dirent.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>

#include "pids.h"
#include "ptrace.h"

#if 1
#define DBG(A...)
#else
#define DBG(A...) printf(A)
#endif

uint32_t *read_pc(pid_t pid)
{
#ifdef __powerpc64__
	unsigned long pc;

	pc = ptrace(PTRACE_PEEKUSER, pid, sizeof(unsigned long) * PT_NIP);

	if (pc == -1) {
		perror("read_pc: ptrace(PTRACE_PEEKUSER)");
		exit(1);
	}

	return (uint32_t *)pc;
#else
#error Implement read_pc
#endif
}

uint32_t read_insn(pid_t pid, uint32_t *pc)
{
#ifdef __powerpc64__
	uint32_t insn;
	unsigned long data;

	data = ptrace(PTRACE_PEEKDATA, pid, pc, NULL);
	if (data == -1) {
		perror("read_insn: ptrace(PTRACE_PEEKDATA)");
		exit(1);
	}

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	insn = data & 0xffffffffUL;
#else
	insn = data >> 32;
#endif

	DBG("read addr %p val %x\n", pc, insn);

	return insn;
#else
#error Implement read_insn
#endif
}

void write_insn(pid_t pid, uint32_t *pc, uint32_t insn)
{
	DBG("write_insn pc %p insn %x\n", pc, insn);
#ifdef __powerpc64__
	unsigned long data;

	data = ptrace(PTRACE_PEEKDATA, pid, pc, NULL);
	if (data == -1) {
		perror("write_insn: ptrace(PTRACE_PEEKDATA)");
		exit(1);
	}

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	data = (data & 0xffffffff00000000UL) | insn;
#else
	data = (data & 0xffffffffUL) | (unsigned long)insn << 32;
#endif

	if (ptrace(PTRACE_POKEDATA, pid, pc, data) == -1) {
		perror("write_insn: ptrace(PTRACE_POKEDATA)");
		exit(1);
	}
#else
#error Implement write_insn
#endif
}

static void wait_for_group_stop(int pid)
{
	int status;

	/*
	 * Wait for pid to stop. We need to reinject any signals until we see
	 * it enter group-stop state.
	 */
	while (1) {
		while (waitpid(pid, &status, __WALL) == -1) {
			if (errno != EINTR) {
				perror("wait_for_group_stop: waitpid");
				exit(1);
			}
		}

		if (!WIFSTOPPED(status))
			continue;

		if ((status >> 16) == PTRACE_EVENT_STOP)
			return;

		if (WIFSTOPPED(status)) {
			int sig = WSTOPSIG(status);

			if (ptrace(PTRACE_CONT, pid, 0, sig)) {
				perror("ptrace(PTRACE_CONT)");
				exit(1);
			}
		}
	}
}

void capture_all_threads(pid_t pid)
{
	char path[PATH_MAX];
	DIR *dir;
	struct dirent *d;
	unsigned long i;

	/* Seize the thread we are tracing */
	if (ptrace(PTRACE_SEIZE, pid, 0, PTRACE_SEIZE_OPTIONS) == -1) {
		perror("ptrace(PTRACE_SIZE)");
		exit(1);
	}

	/* Stop process */
	if (kill(pid, SIGSTOP) == -1) {
		perror("kill(SIGSTOP)\n");
		exit(1);
	}

	wait_for_group_stop(pid);

	/*
	 * Now the process is stopped, we can safely get a list of all the
	 * threads in the process.
	 */
	snprintf(path, PATH_MAX-1, "/proc/%d/task/", pid);

	dir = opendir(path);
	if (!dir) {
		perror("opendir");
		goto err;
	}

	while ((d = readdir(dir)) != NULL) {
		unsigned long p;
		char *end;

		if (!isdigit(d->d_name[0]))
			continue;

		errno = 0;
		p = strtoul(d->d_name, &end, 10);
		if (errno || (d->d_name == end) || (end && *end)) {
			fprintf(stderr, "strtoul(%s) failed\n", d->d_name);
			goto err;
		}

		pids[nr_pids++].pid = p;
		if (nr_pids >= MAX_PIDS) {
			fprintf(stderr, "Too many threads, bump MAX_PIDS\n");
			goto err;
		}
	}

	closedir(dir);

	/* Seize all other threads */
	for (i = 0; i < nr_pids; i++) {
		if (pids[i].pid == pid)
			continue;
		printf("%lu\n", pids[i].pid);
		if (ptrace(PTRACE_SEIZE, pids[i].pid, 0,
			   PTRACE_SEIZE_OPTIONS) == -1) {
			perror("ptrace(PTRACE_SEIZE)");
			goto err;
		}
	}

	/* Wait for all other threads to signal they have entered group-stop */
	for (i = 0; i < nr_pids; i++) {
		if (pids[i].pid == pid)
			continue;

		wait_for_group_stop(pids[i].pid);
	}

	/* Interrupt all threads */
	for (i = 0; i < nr_pids; i++) {
		if (ptrace(PTRACE_INTERRUPT, pids[i].pid, 0, 0) == -1) {
			perror("ptrace(PTRACE_INTERRUPT)");
			goto err;
		}
	}

	/*
	 * Restart the process. Since we interrupted all threads, they will
	 * move from group stop to ptrace stop.
	 */
	if (kill(pid, SIGCONT) == -1) {
		perror("kill(SIGCONT)\n");
		exit(1);
	}

	return;

err:
	/* FIXME: do something useful */
	exit(1);
}

void release_all_non_tracing_threads(pid_t tracing_pid)
{
	unsigned long i;

	for (i = 0; i < nr_pids; i++) {
		if (pids[i].pid == tracing_pid)
			continue;

		if (ptrace(PTRACE_CONT, pids[i].pid, 0, 0)) {
			perror("release_all_non_tracing_threads: ptrace(PTRACE_CONT)");
			exit(1);
		}
	}
}

void detach_all_threads(void)
{
	unsigned long i;

	/*
	 * XXX FIXME: We need to ensure none of the threads have hit an
	 * atomic stepping software breakpoint. We should force all threads
	 * into ptrace via PTRACE_INTERRUPT to be sure.
	 */
	for (i = 0; i < nr_pids; i++)
		ptrace(PTRACE_DETACH, pids[i].pid, NULL, NULL);
}

pid_t do_exec(char *argv[])
{
	pid_t child_pid;

	child_pid = fork();
	if (child_pid == -1) {
		perror("do_exec: fork");
		exit(1);
	}

	/*
	 * The child stops itself. The parent waits for that with waitpid()
	 * and then issues a PTRACE_SEIZE on the child. It uses waitpid()
	 * to be told that the child is stopped with the PTRACE_EVENT_STOP
	 * event. It then restarts the child and waits for the
	 * PTRACE_EVENT_EXEC event.
	 */
	if (!child_pid) {
		kill(getpid(), SIGSTOP);
		execvp(argv[0], argv);
		perror("do_exec: execv");
		exit(1);
	} else {
		int status;

		while (waitpid(child_pid, &status, WSTOPPED) == -1) {
			if (errno != EINTR) {
				perror("do_exec: waitpid");
				goto err_parent;
			}
		}

		if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP) {
			perror("do_exec: waitpid");
			goto err_parent;
		}

		if (ptrace(PTRACE_SEIZE, child_pid, 0,
			   PTRACE_SEIZE_OPTIONS) == -1) {
			perror("do_exec: ptrace(PTRACE_SEIZE)");
			goto err_parent;
		}

		/* Handle the event that tells us the child is stopped */
		while (waitpid(child_pid, &status, __WALL) == -1) {
			if (errno != EINTR) {
				perror("do_exec: waitpid");
				goto err_parent;
			}
		}

		if ((!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP) ||
		    (status >> 16) != PTRACE_EVENT_STOP) {
			perror("do_exec: waitpid");
			goto err_parent;
		}

		/* Restart the child */
		ptrace(PTRACE_CONT, child_pid, 0, 0);

		/* Wait for the PTRACE_EVENT_EXEC event */
		while (waitpid(child_pid, &status, __WALL) == -1) {
			if (errno != EINTR) {
				perror("do_exec: waitpid");
				goto err_parent;
			}
		}

		if ((!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) ||
		    (status >> 16) != PTRACE_EVENT_EXEC) {
			perror("do_exec: waitpid");
			goto err_parent;
		}
	}

	pids[nr_pids++].pid = child_pid;

	return child_pid;

err_parent:
	kill(child_pid, SIGKILL);
	exit(1);
}
