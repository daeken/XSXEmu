/* Fixed Win64 -> SysV adapters for integer/pointer prototypes only.
 * The first SysV argument is the guest LastErrorValue pointer. The remaining
 * five fit in registers; arguments 6–8 occupy the outgoing SysV stack.
 * Incoming Win64 arguments 5–8 are above its return slot and home space.
 * Rust owns the exact-width ABI and never runs under guest GS. */
.set TLS_BRIDGE_FRAME, 248
.macro bridge entry, adapter, argc
    .if \argc > 8
        .error "static TLS bridge supports at most eight scalar arguments"
    .endif
    .globl \entry
\entry:
    subq $TLS_BRIDGE_FRAME, %rsp       /* 16-byte aligned before calls */
    .irp n,6,7,8,9,10,11,12,13,14,15
        movaps %xmm\n, 32+16*(\n-6)(%rsp)
    .endr
    movq %rdi, 192(%rsp)
    movq %rsi, 200(%rsp)
    movq %r12, 208(%rsp)
    .if \argc >= 1
        movq %rcx, 216(%rsp)
    .endif
    .if \argc >= 2
        movq %rdx, 224(%rsp)
    .endif
    .if \argc >= 3
        movq %r8, 232(%rsp)
    .endif
    .if \argc >= 4
        movq %r9, 240(%rsp)
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
        movq 216(%rsp), %rsi
    .endif
    .if \argc >= 2
        movq 224(%rsp), %rdx
    .endif
    .if \argc >= 3
        movq 232(%rsp), %rcx
    .endif
    .if \argc >= 4
        movq 240(%rsp), %r8
    .endif
    .if \argc >= 5
        movq TLS_BRIDGE_FRAME+40(%rsp), %r9
    .endif
    .if \argc >= 6
        movq TLS_BRIDGE_FRAME+48(%rsp), %rax
        movq %rax, 0(%rsp)
    .endif
    .if \argc >= 7
        movq TLS_BRIDGE_FRAME+56(%rsp), %rax
        movq %rax, 8(%rsp)
    .endif
    .if \argc >= 8
        movq TLS_BRIDGE_FRAME+64(%rsp), %rax
        movq %rax, 16(%rsp)
    .endif
    callq \adapter
    movq %rax, 216(%rsp)
    check_host %r12
    switch_to {guest_base}, %r12
    check_guest %r12
    movq 216(%rsp), %rax

    .irp n,6,7,8,9,10,11,12,13,14,15
        movaps 32+16*(\n-6)(%rsp), %xmm\n
    .endr
    movq 192(%rsp), %rdi
    movq 200(%rsp), %rsi
    movq 208(%rsp), %r12
    addq $TLS_BRIDGE_FRAME, %rsp
    retq
.endm
