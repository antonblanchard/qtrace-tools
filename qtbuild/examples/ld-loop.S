#
# ld-loop.S - qtbuild example.
# A loop of 128 dependent loads, using some asm macro magic to provide
# an incrementing address.
#
# Turn this into a .qt with:
#     cc -c -o ld-loop.o ld-loop.S
#     qtbuild ld-loop.o ld-loop.qt
#
#
# Every qtbuild trace includes this file:
#
#include "qtb.h"

# begin executing instructions at this address
start_trace 0xc000000000300c20


li	r9,1024
mtctr	r9
address=0xc000000100000000
.rept 1024
1:
ld      r3,0(r8)			; ldst address
ld      r4,8(r8)			; ldst address+8
ld      r5,16(r8)			; ldst address+16
ld      r6,24(r8)			; ldst address+24
ld      r3,32(r8)			; ldst address+32
ld      r4,40(r8)			; ldst address+40
ld      r5,48(r8)			; ldst address+48
ld      r6,56(r8)			; ldst address+56
bdnz	1b				; branch_taken
address=address+0
.endr
