/* Fixed SysV -> Win64 boundary (EXE entry, TLS callback or DllMain).
 * From the first switch to the checked restore, only this assembly, trusted
 * PE code, the GS-neutral GuardCF leaf checks/dispatch and the pre-resolved
 * Rosetta TSD setter may execute. Never call a dyld stub, Rust function, or
 * signal-mask operation with guest GS. */
.text
.macro check_guest ctx
    movq %gs:0x30, %r10
    cmpq {guest_base}(\ctx), %r10
    jne Lbad_tls_boundary
    movq %gs:0x58, %r10
    cmpq {vector}(\ctx), %r10
    jne Lbad_tls_boundary
    cmpq %gs:{context_slot}, \ctx
    jne Lbad_tls_boundary
.endm
.macro check_host ctx
    movq %gs:0, %r10
    cmpq {host0}(\ctx), %r10
    jne Lbad_tls_boundary
    movq %gs:0x30, %r10
    cmpq {host30}(\ctx), %r10
    jne Lbad_tls_boundary
.endm
.macro switch_to field, ctx
    movq \field(\ctx), %rdi
    callq *{setter}(\ctx)
.endm

.globl _xsxemu_tls_call
_xsxemu_tls_call:
    pushq %r12
    pushq %r13
    pushq %r14
    subq $48, %rsp          /* Win64 home space + locals; align before calls */
    movq %rdi, %r12         /* context (callee-saved in both ABIs) */
    movq %rsi, %r13         /* target */
    movq %rdx, %r14         /* image, or 0 for EXE */
    movl %ecx, 36(%rsp)     /* reason */

    switch_to {guest_base}, %r12
    check_guest %r12
    movq %r14, %rcx
    movl 36(%rsp), %edx
    xorl %r8d, %r8d         /* null reserved */
    callq *%r13
    movl %eax, 32(%rsp)
    check_guest %r12

    switch_to {host_base}, %r12
    check_host %r12
    movl 32(%rsp), %eax
    addq $48, %rsp
    popq %r14
    popq %r13
    popq %r12
    retq

Lbad_tls_boundary:
    ud2                     /* default SIGILL, no recovery */

/* Win64 -> SysV bridges specialized from the c800404 proof. Only these
 * shapes are supported: DWORD(void) and void(DWORD). SysV calls below need
 * no home space or extra argument slots. Save Win64 nonvolatiles that SysV
 * may clobber, plus R12 for our context and ECX/EAX across the setter. */
.set TLS_BRIDGE_FRAME, 200
.set TLS_BRIDGE_LAST_ERROR, {last_error}
.macro save_bridge
    subq $TLS_BRIDGE_FRAME, %rsp         /* RSP % 16 == 0 before SysV calls */
    .irp n,6,7,8,9,10,11,12,13,14,15
        movaps %xmm\n, 16*(\n-6)(%rsp)
    .endr
    movq %rdi, 160(%rsp)
    movq %rsi, 168(%rsp)
    movq %r12, 176(%rsp)
    movl %ecx, 184(%rsp)

    movq %gs:{context_slot}, %r12
    check_guest %r12
    switch_to {host_base}, %r12
    check_host %r12
    movq {guest_base}(%r12), %rdi
    addq $TLS_BRIDGE_LAST_ERROR, %rdi /* explicit DWORD pointer for the Rust adapter */
.endm

.macro restore_bridge
    .irp n,6,7,8,9,10,11,12,13,14,15
        movaps 16*(\n-6)(%rsp), %xmm\n
    .endr
    movq 160(%rsp), %rdi
    movq 168(%rsp), %rsi
    movq 176(%rsp), %r12
    addq $TLS_BRIDGE_FRAME, %rsp
    retq
.endm

.globl _xsxemu_tls_get_last_error
_xsxemu_tls_get_last_error:
    save_bridge
    callq {get_error}
    movl %eax, 184(%rsp)
    check_host %r12
    switch_to {guest_base}, %r12
    check_guest %r12
    movl 184(%rsp), %eax
    restore_bridge

.globl _xsxemu_tls_set_last_error
_xsxemu_tls_set_last_error:
    save_bridge
    movl 184(%rsp), %esi
    callq {set_error}
    check_host %r12
    switch_to {guest_base}, %r12
    check_guest %r12
    restore_bridge
