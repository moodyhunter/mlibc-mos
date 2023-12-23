.section .text
.global __mlibc_start_thread

__mlibc_start_thread:
	add $8, %rsp # skip a return address pushed by the kernel
	pop %rdi
	pop %rsi
	pop %rdx
	call __mlibc_enter_thread

.section .note.GNU-stack,"",%progbits

