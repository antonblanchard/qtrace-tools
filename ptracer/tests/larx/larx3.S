#include <syscall.h>

#include <ppc-asm.h>
#define r2 2

FUNC_START(_start)
	addis	r3,r2,scratch@toc@ha
	addi	r3,r3,scratch@toc@l

	stdx	r4,0,r3

1:	lbarx	r4,0,r3
	cmpdi	r4,1
	beq	2f
	stbcx.	r4,0,r3
	bne	1b
2:

	li	r0,SYS_exit
	li	r3,0
	sc
FUNC_END(_start)

	.section .data
	.balign 16
scratch:
	.space 16
