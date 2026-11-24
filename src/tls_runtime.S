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

    movq {guest_base}(%r12), %rdi
    callq *{setter}(%r12)
    check_guest %r12
    movq %r14, %rcx
    movl 36(%rsp), %edx
    xorl %r8d, %r8d         /* null reserved */
    callq *%r13
    movl %eax, 32(%rsp)
    check_guest %r12

    movq {host_base}(%r12), %rdi
    callq *{setter}(%r12)
    movq %gs:0, %r10
    cmpq {host0}(%r12), %r10
    jne Lbad_tls_boundary
    movq %gs:0x30, %r10
    cmpq {host30}(%r12), %r10
    jne Lbad_tls_boundary
    movl 32(%rsp), %eax
    addq $48, %rsp
    popq %r14
    popq %r13
    popq %r12
    retq

Lbad_tls_boundary:
    ud2                     /* default SIGILL, no recovery */
