#define f0	0
#define f1	1
#define f2	2
#define f3	3
#define f4	4
#define f5	5
#define f6	6
#define f7	7
#define f8	8
#define f9	9
#define f10	10
#define f11	11
#define f12	12
#define f13	13
#define f14	14
#define f15	15
#define f16	16
#define f17	17
#define f18	18
#define f19	19
#define f20	20
#define f21	21
#define f22	22
#define f23	23
#define f24	24
#define f25	25
#define f26	26
#define f27	27
#define f28	28
#define f29	29
#define f30	30
#define f31	31

#define vs0	0
#define vs1	1
#define vs2	2
#define vs3	3
#define vs4	4
#define vs5	5
#define vs6	6
#define vs7	7
#define vs8	8
#define vs9	9
#define vs10	10
#define vs11	11
#define vs12	12
#define vs13	13
#define vs14	14
#define vs15	15
#define vs16	16
#define vs17	17
#define vs18	18
#define vs19	19
#define vs20	20
#define vs21	21
#define vs22	22
#define vs23	23
#define vs24	24
#define vs25	25
#define vs26	26
#define vs27	27
#define vs28	28
#define vs29	29
#define vs30	30
#define vs31	31

#define v0	0
#define v1	1
#define v2	2
#define v3	3
#define v4	4
#define v5	5
#define v6	6
#define v7	7
#define v8	8
#define v9	9
#define v10	10
#define v11	11
#define v12	12
#define v13	13
#define v14	14
#define v15	15
#define v16	16
#define v17	17
#define v18	18
#define v19	19
#define v20	20
#define v21	21
#define v22	22
#define v23	23
#define v24	24
#define v25	25
#define v26	26
#define v27	27
#define v28	28
#define v29	29
#define v30	30
#define v31	31

#define r0	0
#define r1	1
#define r2	2
#define r3	3
#define r4	4
#define r5	5
#define r6	6
#define r7	7
#define r8	8
#define r9	9
#define r10	10
#define r11	11
#define r12	12
#define r13	13
#define r14	14
#define r15	15
#define r16	16
#define r17	17
#define r18	18
#define r19	19
#define r20	20
#define r21	21
#define r22	22
#define r23	23
#define r24	24
#define r25	25
#define r26	26
#define r27	27
#define r28	28
#define r29	29
#define r30	30
#define r31	31

.section ".data.insnmap"
.previous
.section ".data.ldstmap"
.previous

.macro start_trace pc
	qtb_start:
	branch_to_abs \pc
.endm

.macro branch_to_abs pc
	10010:
	.section ".data.insnmap"
	.llong	(10010b - qtb_start)
	.long	0
	.llong	\pc
	.previous
.endm

.macro branch_to_rel rel
	10010:
	.section ".data.insnmap"
	.llong	(10010b - qtb_start)
	long	1
	.llong	\rel
	.previous
.endm

.macro branch_taken
	10010:
	.section ".data.insnmap"
	.llong (10010b - qtb_start)
	.long	2
	.llong	0
	.previous
.endm

.macro ldst addr
	10010:
	.section ".data.ldstmap"
	.llong	10010b - qtb_start
	.llong	\addr
	.previous
.endm

