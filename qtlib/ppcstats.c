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

#include "ccan/hash/hash.h"
#include "ccan/htable/htable_type.h"

#include "ppc-opc.c"
#include "ppcstats.h"
#include "ppcstats_private.c"

#define NR_OPCODES (sizeof(powerpc_opcodes) / sizeof(struct powerpc_opcode))

/* setup hash table for instruction mix counts */
struct cache_obj {
	uint32_t opcode;
	int index;
};

static const uint32_t *cache_obj_opcode(const struct cache_obj *obj)
{
	return &obj->opcode;
}

static size_t cache_obj_hash(const uint32_t *opcode)
{
	return hash(opcode, 1, 0);
}

static bool cache_obj_cmp(const struct cache_obj *obj, const uint32_t *opcode)
{
	return obj->opcode == *opcode;
}

HTABLE_DEFINE_TYPE(struct cache_obj, cache_obj_opcode, cache_obj_hash, cache_obj_cmp, htable_cache);

struct opcode_major {
	int start;
	int end;
};

/* power9 dialect from binutils-gdb opcodes/ppc-dis.c ppc_opts:"power9" */
#define DIALECT ( PPC_OPCODE_PPC | PPC_OPCODE_ISEL | PPC_OPCODE_64 \
		  | PPC_OPCODE_POWER4 | PPC_OPCODE_POWER5 | PPC_OPCODE_POWER6 \
		  | PPC_OPCODE_POWER7 | PPC_OPCODE_POWER8 | PPC_OPCODE_POWER9 \
		  | PPC_OPCODE_ALTIVEC | PPC_OPCODE_VSX )

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
	bool stats;
	bool imix;

	struct opcode_major major[64]; 	// 6 bits of major opcode
	uint64_t insn_count[NR_OPCODES];
	uint64_t unknown;
	struct htable_cache cache;
	uint64_t cache_hits;
	uint64_t cache_misses;
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

void ppcstats_init(uint64_t flags)
{
	int i;

	assert(flags);

	if (flags & PPCSTATS_STATS)
		s.stats = true;
	if (flags & PPCSTATS_IMIX)
		s.imix = true;

	if (!(flags & PPCSTATS_IMIX))
		return;

	/* init hash table for imix cache */
	assert(htable_cache_init_sized(&s.cache, 1024 * 1024));

	/* Setup table for where major opcodes are in full opcodes table
	 * This is so we don't have to search has much.
	 */
	for (i = 0; i < 64; i++)
		s.major[i].start = -1;
	for (i = 0; i < NR_OPCODES - 1; i++) {
		struct opcode_major *op;
		unsigned int prefix;

		prefix = 0x3f & (powerpc_opcodes[i].opcode >> 26);

		op = &s.major[prefix];
		if (op->start == -1)
			op->start = i;

		op->end = i;
	}
}

static void ppcstats_log_inst_stats(unsigned long ea, uint32_t insn)
{
	uint64_t c;
	uint32_t i;
	bool system = false;
	bool opal = false;

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

static void ppcstats_log_inst_imix(unsigned long ea, uint32_t insn)
{
	struct cache_obj *obj;
	struct opcode_major *op;
	unsigned int prefix;
	uint32_t i;

	/* Check cache for opcode */
	obj = htable_cache_get(&s.cache, &insn);
	if (obj) {
		s.insn_count[obj->index]++;
		s.cache_hits++;
		return;
	}

	/* Doh! Not in cache. Go find it and put in cache.
	 *
	 * We linearly look though the full opcode table starting at
	 * major opcode we currently have. When we find it, add to the
	 * cache.
	 */
	prefix = insn >> 26;
	op = &s.major[prefix];
	s.cache_misses++;

	for (i = op->start; i <= op->end; i++) {
		const struct powerpc_opcode *po = &powerpc_opcodes[i];

		if (((insn & (uint32_t)po->mask) == (uint32_t)po->opcode) &&
		    (po->flags & DIALECT)) {
			s.insn_count[i]++;

			obj = malloc(sizeof(*obj));
			assert(obj);

			*obj = (struct cache_obj) {
				.opcode = insn,
				.index = i,
			};

			htable_cache_add(&s.cache, obj);
			return;
		}
	}

	s.unknown++;
}

void ppcstats_log_inst(unsigned long ea, uint32_t insn)
{
	s.total++;

	if (s.stats)
		ppcstats_log_inst_stats(ea, insn);
	if (s.imix)
		ppcstats_log_inst_imix(ea, insn);
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

static int insn_compare(const void *a, const void *b)
{
	int id1 = *(const int *)a;
	int id2 = *(const int *)b;

	return s.insn_count[id2] - s.insn_count[id1];
}

static void ppcstats_print_stats(void)
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

static void ppcstats_print_imix(void)
{
	int i;
	int index[NR_OPCODES];

	/* Create indexes and then sort based on count */
	for (i = 0 ; i < NR_OPCODES; i++)
		index[i] = i;
	qsort(index, NR_OPCODES, sizeof(int), insn_compare);

	/* Now print in order */
	fprintf(stdout,"\nInstruction mix:\n");
	for (i = 0; i < NR_OPCODES; i++) {
		const struct powerpc_opcode *po = &powerpc_opcodes[index[i]];
		uint64_t count = s.insn_count[index[i]];

		if (!count)
			break;

		fprintf(stdout,"\t%16s\t% 9li %6.2f%%\n",
			po->name, count,
			100.0 * (double)count/(double)s.total);
	}

	fprintf(stdout,"\nUNKNOWN instruction:   %16li\n", s.unknown);
#if 0
	fprintf(stdout,"\nCache Hits:   %16li %6.2f%%\n", s.cache_hits,
		100.0 * (double)(s.cache_hits)/(double)(s.cache_hits + s.cache_misses));
	fprintf(stdout,"Cache Misses: %16li %6.2f%%\n", s.cache_misses,
		100.0 * (double)(s.cache_misses)/(double)(s.cache_hits + s.cache_misses));
#endif
}

void ppcstats_print(void)
{

	if (s.stats)
		ppcstats_print_stats();
	if (s.imix)
		ppcstats_print_imix();
}
