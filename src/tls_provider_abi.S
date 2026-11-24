/* Fixed Win64 -> SysV adapters for integer/pointer prototypes only.
 * The first SysV argument is the guest LastErrorValue pointer. The remaining
 * five fit in registers; Win64's fifth argument is above its home space.
 * Rust owns the exact-width ABI and never runs under guest GS. */
.set TLS_BRIDGE_FRAME, 216
.macro bridge entry, adapter, argc
    .if \argc > 5
        .error "static TLS bridge supports at most five scalar arguments"
    .endif
    .globl \entry
\entry:
    subq $TLS_BRIDGE_FRAME, %rsp       /* 16-byte aligned before calls */
    .irp n,6,7,8,9,10,11,12,13,14,15
        movaps %xmm\n, 16*(\n-6)(%rsp)
    .endr
    movq %rdi, 160(%rsp)
    movq %rsi, 168(%rsp)
    movq %r12, 176(%rsp)
    .if \argc >= 1
        movq %rcx, 184(%rsp)
    .endif
    .if \argc >= 2
        movq %rdx, 192(%rsp)
    .endif
    .if \argc >= 3
        movq %r8, 200(%rsp)
    .endif
    .if \argc >= 4
        movq %r9, 208(%rsp)
    .endif

    movq %gs:{context_slot}, %r12
    check_guest %r12
    switch_to {host_base}, %r12
    check_host %r12
    movq {guest_base}(%r12), %rdi
    addq ${last_error}, %rdi
    .if \argc >= 1
        movq 184(%rsp), %rsi
    .endif
    .if \argc >= 2
        movq 192(%rsp), %rdx
    .endif
    .if \argc >= 3
        movq 200(%rsp), %rcx
    .endif
    .if \argc >= 4
        movq 208(%rsp), %r8
    .endif
    .if \argc >= 5
        movq TLS_BRIDGE_FRAME+40(%rsp), %r9
    .endif
    callq \adapter
    movq %rax, 184(%rsp)
    check_host %r12
    switch_to {guest_base}, %r12
    check_guest %r12
    movq 184(%rsp), %rax

    .irp n,6,7,8,9,10,11,12,13,14,15
        movaps 16*(\n-6)(%rsp), %xmm\n
    .endr
    movq 160(%rsp), %rdi
    movq 168(%rsp), %rsi
    movq 176(%rsp), %r12
    addq $TLS_BRIDGE_FRAME, %rsp
    retq
.endm
