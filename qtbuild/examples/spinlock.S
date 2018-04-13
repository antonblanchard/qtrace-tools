#
# spinlock.S - qtbuild example.
# This is a little bit like an execution trace of Linux's powerpc
# spinlock, failing to take the lock at first and then succeeding.
#
# Turn this into a .qt with:
#     cc -c spinlock.S
#     qtbuild spinlock.o spinlock.qt
#
#
# Every qtbuild trace includes this file:
#
#include "qtb.h"

# begin executing instructions at this address
start_trace 0xc000000000000300

# call spin_lock
bl	0x4200			; branch_to_abs 0xc000000000004500

mflr	r0
nop				# mcount patched out
li	r10,0
stb	r10,4(r13)		; ldst 0xc000000000100004
lwz	r10,0(r13)		; ldst 0xc000000000100000
lwarx	r9,0,r3,1		; ldst 0xc000000000200120
cmpwi	r9,0
bne-	0x10			; branch_taken
cmpdi	cr7,r9,0
bne	cr7,0x10		; branch_taken
mr	r1,r1
lwz	r9,0(r3)		; ldst 0xc000000000200120
cmpdi	cr7,r9,0
bne	cr7,0xc
mr	r2,r2
lwz	r10,0(r13)		; ldst 0xc000000000100000
lwarx	r9,0,r3,1		; ldst 0xc000000000200120
cmpwi	r9,0
bne-	0x10
stwcx.	r10,0,r3		; ldst 0xc000000000200120
bne-	-0x10
lwsync				# isync patch
cmpdi	cr7,r9,0
bne	cr7,-0x34
blr				; branch_to_abs 0xc000000000000304

#back to caller
nop
nop
