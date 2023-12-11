.section .text
.global _start
_start:
	call load_gp
	mv a0, sp
	la a1, main
	call __mlibc_entry@plt
	unimp

load_gp:
.option push
.option norelax
	lla   gp, __global_pointer$
.option pop
	ret

.section .preinit_array,"aw"
.dc.a load_gp

.section .note.GNU-stack,"",%progbits
