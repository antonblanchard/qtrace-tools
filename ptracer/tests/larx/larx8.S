#include <syscall.h>

#include <ppc-asm.h>
#define r2 2

FUNC_START(_start)
	addis	r3,r2,scratch@toc@ha
	addi	r3,r3,scratch@toc@l

	lwarx	r4,0,r3
	/* Force a SEGV signal inside a larx/stcx sequence */
	li	r6,0
	ld	r5,0(r6)
	stwcx.	r4,0,r3

	li	r0,SYS_exit
	li	r3,0
	sc
FUNC_END(_start)

	.section .data
	.balign 16
scratch:
	.space 16
