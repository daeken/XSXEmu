/* Fixed SysV -> Win64 boundary (EXE entry, TLS callback or DllMain).
 * From the first switch to the checked restore, only this assembly, trusted
 * PE code, the GS-neutral GuardCF leaf checks/dispatch and the pre-resolved
 * Rosetta TSD setter may execute, along with the sealed terminal trap entries
 * below. Never call a dyld stub, Rust function, or signal-mask operation
 * with guest GS. */
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

/* Thread start takes a single LPVOID in RCX and returns a DWORD in EAX.
 * Share the fixed frame and checked return path with notifications. Zero
 * the unused EDX/R8D arguments; this does not emulate Windows SEH or ExitThread. */
.globl _xsxemu_tls_thread_call
_xsxemu_tls_thread_call:
    xorl %ecx, %ecx
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
/* Entered from an exact bound Win64 trap thunk with MissingImport in RCX and
 * normal function-entry stack alignment. This path never returns, so guest
 * callee-saved registers need not be restored. */
.globl _xsxemu_tls_missing_import
_xsxemu_tls_missing_import:
    movq %rcx, %r13
    movq %gs:{context_slot}, %r12
    testq %r12, %r12
    jz Lbad_tls_boundary
    check_guest %r12
    subq $8, %rsp          /* align stack before the SysV setter call */
    switch_to {host_base}, %r12
    check_host %r12
    movq %r13, %rdi
    addq $8, %rsp          /* SysV function-entry alignment for the tail jump */
    jmp {missing_import}

/* These terminal entries ignore every guest argument and candidate target.
 * They cannot return to the original call or jump to the candidate. */
.macro dormant_guard_entry name, id
.globl \name
\name:
    movl $\id, %r13d
    jmp Ldormant_guard
.endm

dormant_guard_entry _xsxemu_tls_dormant_cfg_check, 0
dormant_guard_entry _xsxemu_tls_dormant_cfg_dispatch, 1
dormant_guard_entry _xsxemu_tls_dormant_xfg_check, 2
dormant_guard_entry _xsxemu_tls_dormant_xfg_dispatch, 3
dormant_guard_entry _xsxemu_tls_dormant_xfg_table_dispatch, 4
dormant_guard_entry _xsxemu_tls_guard_memcpy, 5

Ldormant_guard:
    movq %gs:{context_slot}, %r12
    testq %r12, %r12
    jz Lbad_tls_boundary
    check_guest %r12
    andq $-16, %rsp
    switch_to {host_base}, %r12
    check_host %r12
    movq %r13, %rdi
    callq {dormant_guard}
    ud2
