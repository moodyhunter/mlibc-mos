.global __mlibc_start_thread
__mlibc_start_thread:
    // there are 3 arguments on the stack, we need to pop them
    ld a0, 0(sp)
    ld a1, 8(sp)
    ld a2, 16(sp)
    call __mlibc_enter_thread
