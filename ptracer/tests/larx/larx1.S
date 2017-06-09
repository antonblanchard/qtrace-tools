#include <syscall.h>

#include <ppc-asm.h>
#define r2 2

FUNC_START(_start)
	addis	r3,r2,scratch@toc@ha
	addi	r3,r3,scratch@toc@l

	lbarx	r4,0,r3
	stbcx.	r4,0,r3

	lharx	r4,0,r3
	sthcx.	r4,0,r3

	lwarx	r4,0,r3
	stwcx.	r4,0,r3

	ldarx	r4,0,r3
	stdcx.	r4,0,r3

	lqarx	r4,0,r3
	stqcx.	r4,0,r3

	li	r0,SYS_exit
	li	r3,0
	sc
FUNC_END(_start)

	.section .data
	.balign 16
scratch:
	.space 16
