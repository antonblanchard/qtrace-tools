/*
 * Copyright (C) 2017 Anton Blanchard <anton@au.ibm.com>, IBM
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>

#include "ptrace.h"
#include "single_step.h"

/*
 * TODO:
 * If only one breakpoint, use a hardware breakpoint
 */

#define LWARX_MASK 0xfc0007fe
#define LBARX_INSTRUCTION 0x7c000068
#define LHARX_INSTRUCTION 0x7c0000e8
#define LWARX_INSTRUCTION 0x7c000028
#define LDARX_INSTRUCTION 0x7c0000A8
#define LQARX_INSTRUCTION 0x7c000228

#define STWCX_MASK 0xfc0007ff
#define STBCX_INSTRUCTION 0x7c00056d
#define STHCX_INSTRUCTION 0x7c0005ad
#define STWCX_INSTRUCTION 0x7c00012d
#define STDCX_INSTRUCTION 0x7c0001ad
#define STQCX_INSTRUCTION 0x7c00016d

#define BRANCH_MASK 0xfc000000
#define BC_INSN 0x40000000

#define BREAKPOINT_INSN 0x00b00b00UL

bool is_larx(uint32_t insn)
{
	uint32_t insn_base = insn & LWARX_MASK;

	if ((insn_base == LBARX_INSTRUCTION) ||
	    (insn_base == LHARX_INSTRUCTION) ||
	    (insn_base == LWARX_INSTRUCTION) ||
	    (insn_base == LDARX_INSTRUCTION) ||
	    (insn_base == LQARX_INSTRUCTION))
		return true;

	return false;
}

static inline bool is_stcx(uint32_t insn)
{
	uint32_t insn_base = insn & STWCX_MASK;

	if ((insn_base == STBCX_INSTRUCTION) ||
	    (insn_base == STHCX_INSTRUCTION) ||
	    (insn_base == STWCX_INSTRUCTION) ||
	    (insn_base == STDCX_INSTRUCTION) ||
	    (insn_base == STQCX_INSTRUCTION))
		return true;

	return false;
}

static inline bool is_branch(uint32_t insn)
{
	uint32_t insn_base = insn & BRANCH_MASK;

	if (insn_base == BC_INSN)
		return true;

	return false;
}

static inline uint32_t *branch_target(uint32_t insn, uint32_t *addr)
{
	unsigned long target;
	int immediate = ((insn & 0xfffc) ^ 0x8000) - 0x8000;
	int absolute = insn & 2;

	if (absolute)
		target = immediate;
	else
		target = ((unsigned long)addr) + immediate;

	return (uint32_t *)target;
}

/* This includes the breakpoint at the termination of the larx/stcx sequence */
#define MAX_BREAKPOINTS		8
#define MAX_LARX_STCX_GAP	32

struct breakpoint {
	uint32_t *addr;
	uint32_t insn;
};

static bool insert_one_breakpoint(pid_t pid, struct breakpoint *breakpoint)
{
	uint32_t val;

	val = read_insn(pid, breakpoint->addr);
	breakpoint->insn = val;
	write_insn(pid, breakpoint->addr, BREAKPOINT_INSN);

	return true;
}

static bool remove_one_breakpoint(pid_t pid, struct breakpoint *breakpoint)
{
	uint32_t val;

	val = read_insn(pid, breakpoint->addr);

	if (val != BREAKPOINT_INSN)
		return false;

	write_insn(pid, breakpoint->addr, breakpoint->insn);

	return true;
}

static bool insert_breakpoints(pid_t pid, struct breakpoint *breakpoints,
			       unsigned long nr)
{
	struct breakpoint *b = breakpoints;
	unsigned long i, j;

	for (i = 0; i < nr; i++) {
		if ((b->addr != (uint32_t *)-1) &&
		    (insert_one_breakpoint(pid, b) == false)) {
			b = breakpoints;
			for (j = 0; j < i; j++)
				remove_one_breakpoint(pid, b++);
			return false;
		}
		b++;
	}

	return true;
}

static bool remove_breakpoints(pid_t pid, struct breakpoint *breakpoints,
			       unsigned long nr)
{
	struct breakpoint *b = breakpoints;
	unsigned long i;
	bool ret = true;

	for (i = 0; i < nr; i++) {
		if ((b->addr != (uint32_t *)-1) &&
		    (remove_one_breakpoint(pid, b) == false))
			ret = false;
		b++;
	}

	return ret;
}

typedef void (*callback)(pid_t pid, uint32_t *pc);

static struct sigaction old_sigaction[NSIG];

static void ignore_signals(void)
{
	struct sigaction action;

	memset(&action, 0, sizeof(action));
	action.sa_handler = SIG_IGN;

	for (unsigned long i = 0; i < NSIG; i++) {
		if (i != SIGTRAP)
			sigaction(i, &action, &old_sigaction[i]);
	}
}

static void dont_ignore_signals(void)
{
	for (unsigned long i = 0; i < NSIG; i++) {
		if (i != SIGTRAP)
			sigaction(i, &old_sigaction[i], NULL);
	}
}

unsigned long step_over_atomic(pid_t pid, uint32_t *p, callback fn)
{
	struct breakpoint breakpoints[MAX_BREAKPOINTS];
	unsigned long b = 0, i = 0, j = 0;
	uint32_t *start, *end;
	uint32_t *pc;
	uint32_t insn;
	int status;

	insn = read_insn(pid, p);
	if (!is_larx(insn))
		return 0;

	start = p;

	for (i = 0; i < MAX_LARX_STCX_GAP; i++) {
		insn = read_insn(pid, p);
		if (is_stcx(insn))
			break;

		if (is_branch(insn)) {
			/* Too many branches? */
			if (b == (MAX_BREAKPOINTS-1)) {
				fprintf(stderr, "step_over_atomic: too many breakpoints at %p\n", p);
				exit(1);
			}

			breakpoints[b++].addr = branch_target(insn, p);
		}

		p++;
	}

	/* We didn't find the stcx */
	if (!is_stcx(insn)) {
		fprintf(stderr, "step_over_atomic: stcx not found at %p\n", p);
		exit(1);
	}

	/* Add breakpoint after stcx */
	p++;
	breakpoints[b++].addr = p;

	end = p;

	/*
	 * check for breakpoints within the larx/stcx region, or
	 * duplicated breakpoints.
	 */
	for (i = 0; i < b; i++) {
		if ((breakpoints[i].addr >= start) &&
		    (breakpoints[i].addr < end)) {
			breakpoints[i].addr = (uint32_t *)-1;
			continue;
		}

		for (j = i+1; j < b; j++) {
			if (breakpoints[i].addr == breakpoints[j].addr)
				breakpoints[i].addr = (uint32_t *)-1;
		}
	}

	ignore_signals();
	insert_breakpoints(pid, breakpoints, b);

	if (ptrace(PTRACE_CONT, pid, 0, 0) == -1) {
		perror("step_over_atomic: ptrace(PTRACE_CONT)");
		goto error;
	}

	if (waitpid(pid, &status, __WALL) == -1) {
		perror("step_over_atomic: waitpid");
		goto error;
	}

	if (!WIFSTOPPED(status)) {
		fprintf(stderr, "%s: waitpid status 0x%x\n", __func__, status);
		goto error;
	}

	/* XXX FIXME: We got a signal inside a larx/stcx sequence */
	if (WSTOPSIG(status) != SIGILL) {
		fprintf(stderr, "%s: received %d signal\n", __func__, WSTOPSIG(status));
		goto error;
	}

	remove_breakpoints(pid, breakpoints, b);
	dont_ignore_signals();

	pc = read_pc(pid);

	if (fn) {
		/* XXX FIXME This assumes the larx/stcx passed */
		while (start <= pc) {
			fn(pid, start);
			start++;
		}
	}

	if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) == -1) {
		perror("ptrace");
		exit(1);
	}

	/* We return with the tracing thread running */

	return start - pc;

error:
	remove_breakpoints(pid, breakpoints, b);
	dont_ignore_signals();
	exit(1);
}
