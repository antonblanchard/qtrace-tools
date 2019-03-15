/*
 * Copyright (C) 2018 Michael Neuling <mikey@neuling.org>, IBM
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <assert.h>

#include "ppcstats_private.c"

#define NR_HCALLS (sizeof(hcalls) / sizeof(struct hcall))

struct stats {
	uint64_t total;
	uint64_t system;
	uint64_t opal;
	uint64_t user;
	uint64_t userlib;
	uint64_t userbin;
	uint64_t r3;
	uint64_t r0;
	uint64_t idle;
	uint64_t mftb_last;
	uint64_t ctxswitch;
	uint64_t ctxswitch_ea;
	uint64_t ctxswitch_ea_multiple;
	struct exception *exceptions;
	struct call *syscalls;
	struct call *opalcalls;
	struct hcall *hcalls;
	uint64_t exceptionnum;
	uint64_t syscallnum;
	uint64_t opalcallnum;
	uint64_t hcallnum;
	bool opallast;
};
struct stats s = {
	.syscalls = syscalls,
	.exceptions = exceptions,
	.opalcalls = opalcalls,
	.hcalls = hcalls,
};

static bool is_exception_entry(unsigned long ea)
{
	unsigned long exception;
	int i;

	if (((ea & 0xfffffffffffff01f) != 0xc000000000004000) &&
	    ((ea & 0xfffffffffffff01f) != 0x0000000000000000))
		return false;

	exception = (ea & 0xfff);
	for (i = 0; i < NR_EXCEPTIONS; i++) {
		if (exception == s.exceptions[i].addr) {
			s.exceptionnum++;
			s.exceptions[i].count++;
			return true;
		}
	}

	return false;
}

static struct hcall *hcall_find(uint32_t token)
{
	int i;

	for (i = 0; i < NR_HCALLS; i++) { /* Linear search .. barf */
		if (s.hcalls[i].token == token)
			return &s.hcalls[i];
	}
	return &s.hcalls[NR_HCALLS -1]; /* return unknown */
}

static void hcall_increment(uint32_t token)
{
	struct hcall *h = hcall_find(token);

	h->count++;
}

void ppcstats_log_inst(unsigned long ea, uint32_t insn)
{
	uint64_t c;
	uint32_t i;
	bool system = false;
	bool opal = false;

	s.total++;
	if (ea >= 0xc000000000000000) {
		system = true;
		s.system++;
	} else if ((ea & 0xFFFFFFFFFF000000) == 0x0000000030000000) {
		opal = true;
		s.opal++;
	} else {
		s.user++;
		if (ea >= 0x700000000000)
			s.userlib++;
		else
			s.userbin++;
	}

	is_exception_entry(ea);

	/* Find syscalls: syscall() case. ie.
	 *   li r3, ?? ; mr r0, r3
	 */
	if ((insn & 0xffff0000) == 0x38600000) /* li r3, ?? */
		s.r3 = insn & 0x0000ffff;
	if (insn == 0x7c601b78) /* mr r0, r3 */
		s.r0 = s.r3;

	/* Find syscalls:  Most common case li r0, ?? */
	if ((insn & 0xffff0000) == 0x38000000) /* li r0, ?? */
		s.r0 = insn & 0x0000ffff;
	if (insn == 0x44000002) { /* sc */
		c = s.r0;
		if (c >= NR_SYSCALLS)
			c = NR_SYSCALLS - 1;
		s.syscallnum++;
		s.syscalls[c].count++;
	}

	/* Find HCALLS:  Most common case li r3, ?? */
	if (insn == 0x44000022) { /* sc 1 */
		s.hcallnum++;
		c = s.r3;
		hcall_increment(c);
	}

	/*
	 * Find start of OPAL call.  If this instruction is OPAL and
	 * the last wasn't, then this is the start of an OPAL call.
	 */
	if (opal && !s.opallast) {
		s.opalcallnum++;
		c = s.r3;
		if (c >= NR_OPALCALLS)
			c = NR_OPALCALLS - 1;
		s.opalcalls[c].count++;
	}

	/* Context switch */
	/* mfspr r??, SPRN_EBBRR in kernel == context switch */
	if (system && ((insn & 0xfe1fffff) == 0x7c0042a6)) {
		s.ctxswitch++;
		if (!s.ctxswitch_ea)
			s.ctxswitch_ea = ea;
		/* double check we aren't doing tm, signals or kvm */
		if (ea != s.ctxswitch_ea)
			s.ctxswitch_ea_multiple++;
	}

	/* look for mftb r??  within 10 cycles */
	if (system && ((insn & 0xfc1fffff) == 0x7c0c42a6)) {
		i = s.total - s.mftb_last;
		if (i < 10)
			/* We are in the snoop loop */
			s.idle += i;
		s.mftb_last = s.total;
	}
	s.opallast = opal;

}

static int exceptions_compare(const void *a, const void *b)
{
	return ((struct exception *)b)->count - ((struct exception *)a)->count;
}

static int call_compare(const void *a, const void *b)
{
	return ((struct call *)b)->count - ((struct call *)a)->count;
}

static int hcall_compare(const void *a, const void *b)
{
	return ((struct hcall *)b)->count - ((struct hcall *)a)->count;
}

void ppcstats_print(void)
{
	int i;
	float f;

	fprintf(stdout,"\n");
	fprintf(stdout,"Instructions:\n");
	fprintf(stdout,"  %-16s%li\n", "Total", s.total);
	fprintf(stdout,"    %-14s%8li\t%6.2f%% of Total\n", "System",
		s.system, 100.0*s.system/s.total);
	fprintf(stdout,"      %-12s%8li\t%6.2f%% of System\n", "Idle",
		s.idle, s.system?100.0*s.idle/s.system:0);

	fprintf(stdout,"    %-14s%8li\t%6.2f%% of Total\n", "OPAL",
		s.opal, 100.0*s.opal/s.total);
	fprintf(stdout,"    %-14s%8li\t%6.2f%% of Total\n", "User",
		s.user, 100.0*s.user/s.total);

	fprintf(stdout,"      %-12s%8li\t%6.2f%% of User\n", "Bin",
		s.userbin, s.user?100.0*s.userbin/s.user:0);
	fprintf(stdout,"      %-12s%8li\t%6.2f%% of User\n", "Lib",
		s.userlib, s.user?100.0*s.userlib/s.user:0);


	fprintf(stdout,"\nContext Switches: %8li\n", s.ctxswitch);
	f = 100.0 * s.ctxswitch_ea_multiple/s.ctxswitch;
	if (f > 10.0)
		fprintf(stdout,"WARNING: Context Switches fuzzy by %0.2f%%)\n", f);

	fprintf(stdout,"\nExceptions:       %8li\n", s.exceptionnum);
	qsort(s.exceptions, NR_EXCEPTIONS, sizeof(struct exception), exceptions_compare);
	for (i = 0; i < NR_EXCEPTIONS; i++) {
		if (s.exceptions[i].count) {
			fprintf(stdout,"\t%16s\t%li\n",
			       s.exceptions[i].name,
			       s.exceptions[i].count);
		}
	}

	fprintf(stdout,"\nSyscalls:         %8li\n", s.syscallnum);
	qsort(s.syscalls, NR_SYSCALLS, sizeof(struct call), call_compare);
	for (i = 0; i < NR_SYSCALLS; i++) {
		if (!syscalls[i].count)
			break;
		fprintf(stdout,"\t%16s\t%li\n",
		       syscalls[i].name, syscalls[i].count);
	}

	fprintf(stdout,"\nOPAL Calls:       %8li\n", s.opalcallnum);
	qsort(s.opalcalls, NR_OPALCALLS, sizeof(struct call), call_compare);
	for (i = 0; i < NR_OPALCALLS; i++) {
		if (!opalcalls[i].count)
			continue;
		fprintf(stdout,"\t%16s\t%li\n",
		       opalcalls[i].name, opalcalls[i].count);
	}

	fprintf(stdout,"\nHCALLS Calls:     %8li\n", s.hcallnum);
	qsort(s.hcalls, NR_HCALLS, sizeof(struct hcall), hcall_compare);
	for (i = 0; i < NR_HCALLS; i++) {
		if (!hcalls[i].count)
			continue;
		fprintf(stdout,"\t%16s\t%li\n",
		       hcalls[i].name, hcalls[i].count);
	}
}
