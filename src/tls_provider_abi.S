/* Fixed Win64 -> SysV adapters for integer/pointer prototypes only.
 * The first SysV argument is the guest LastErrorValue pointer. The remaining
 * five fit in registers; arguments 6–12 occupy the outgoing SysV stack.
 * Incoming Win64 arguments 5–12 are above its return slot and home space.
 * Rust owns the exact-width ABI and never runs under guest GS. */
.macro bridge entry, adapter, argc, return_pc
    .if \argc > 12
        .error "static TLS bridge supports at most twelve scalar arguments"
    .endif
    .set TLS_BRIDGE_EXTRA, 0
    .if \argc > 8
        .set TLS_BRIDGE_EXTRA, 32
    .endif
    .set TLS_BRIDGE_FRAME, 248+TLS_BRIDGE_EXTRA
    .globl \entry
\entry:
    subq $TLS_BRIDGE_FRAME, %rsp       /* 16-byte aligned before calls */
    .irp n,6,7,8,9,10,11,12,13,14,15
        movaps %xmm\n, TLS_BRIDGE_EXTRA+32+16*(\n-6)(%rsp)
    .endr
    movq %rdi, TLS_BRIDGE_EXTRA+192(%rsp)
    movq %rsi, TLS_BRIDGE_EXTRA+200(%rsp)
    movq %r12, TLS_BRIDGE_EXTRA+208(%rsp)
    .if \argc >= 1
        movq %rcx, TLS_BRIDGE_EXTRA+216(%rsp)
    .endif
    .if \argc >= 2
        movq %rdx, TLS_BRIDGE_EXTRA+224(%rsp)
    .endif
    .if \argc >= 3
        movq %r8, TLS_BRIDGE_EXTRA+232(%rsp)
    .endif
    .if \argc >= 4
        movq %r9, TLS_BRIDGE_EXTRA+240(%rsp)
    .endif

    movq %gs:{context_slot}, %r12
    check_guest %r12
    switch_to {host_base}, %r12
    check_host %r12
    cmpb $0, {trace_startup}(%r12)
    je 1f
    /* Log only under checked host GS, before setting adapter arguments. */
    leaq \entry(%rip), %rdi
    movq TLS_BRIDGE_FRAME(%rsp), %rsi  /* guest return PC, not fault RIP */
    callq {trace_bridge}
1:
    movq {guest_base}(%r12), %rdi
    addq ${last_error}, %rdi
    .if \argc >= 1
        movq TLS_BRIDGE_EXTRA+216(%rsp), %rsi
    .endif
    .if \argc >= 2
        movq TLS_BRIDGE_EXTRA+224(%rsp), %rdx
    .endif
    .if \argc >= 3
        movq TLS_BRIDGE_EXTRA+232(%rsp), %rcx
    .endif
    .if \argc >= 4
        movq TLS_BRIDGE_EXTRA+240(%rsp), %r8
    .endif
    .if \argc >= 5
        movq TLS_BRIDGE_FRAME+40(%rsp), %r9
    .endif
    .irp n,6,7,8,9,10,11,12
        .if \argc >= \n
            movq TLS_BRIDGE_FRAME+8*\n(%rsp), %rax
            movq %rax, 8*(\n-6)(%rsp)
        .endif
    .endr
    .if \return_pc
        .if \argc != 3
            .error "saved return PC supported only after three guest arguments"
        .endif
        movq TLS_BRIDGE_FRAME(%rsp), %r8
    .endif
    callq \adapter
    movq %rax, TLS_BRIDGE_EXTRA+216(%rsp)
    check_host %r12
    switch_to {guest_base}, %r12
    check_guest %r12
    movq TLS_BRIDGE_EXTRA+216(%rsp), %rax

    .irp n,6,7,8,9,10,11,12,13,14,15
        movaps TLS_BRIDGE_EXTRA+32+16*(\n-6)(%rsp), %xmm\n
    .endr
    movq TLS_BRIDGE_EXTRA+192(%rsp), %rdi
    movq TLS_BRIDGE_EXTRA+200(%rsp), %rsi
    movq TLS_BRIDGE_EXTRA+208(%rsp), %r12
    addq $TLS_BRIDGE_FRAME, %rsp
    retq
.endm
