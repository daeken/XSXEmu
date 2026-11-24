/* SysV -> Win64 boundary, only for these three fixed calls. Keep the original
 * frame, 32 bytes of home space and 16-byte pre-call alignment. R12 survives
 * both ABIs; save the entry result across detach and the private setter. */
.text
.globl _run_owned_pe
_run_owned_pe:
    pushq %r12
    subq $48, %rsp
    movq %rdi, %r12
    movq {guest_base}(%r12), %rdi
    callq __thread_set_tsd_base
    movq %gs:0x30, %rax
    cmpq {guest_base}(%r12), %rax
    jne Lbad_boundary
    movq %gs:0x58, %rax
    cmpq {vector}(%r12), %rax
    jne Lbad_boundary

    movq {image}(%r12), %rcx
    movl $1, %edx               /* DLL_PROCESS_ATTACH */
    xorl %r8d, %r8d             /* reserved = null in this fixture */
    callq *{callback}(%r12)
    callq *{entry}(%r12)
    movl %eax, 32(%rsp)
    movq {image}(%r12), %rcx
    xorl %edx, %edx             /* DLL_PROCESS_DETACH */
    xorl %r8d, %r8d
    callq *{callback}(%r12)

    movq {host_base}(%r12), %rdi
    callq __thread_set_tsd_base
    movq %gs:0, %rax
    cmpq {host0}(%r12), %rax
    jne Lbad_boundary
    movq %gs:0x30, %rax
    cmpq {host30}(%r12), %rax
    jne Lbad_boundary
    movl 32(%rsp), %eax
    addq $48, %rsp
    popq %r12
    retq
Lbad_boundary:
    ud2                         /* never return to Rust if GS is unknown */

/* This range is data in the Mach-O. Only its copied PE .text executes.
 * All label references in the range are local PC-relative branches/LEAs;
 * no Mach-O symbol address or fixup travels into the PE. */
.section __TEXT,__const
.p2align 2
.globl _owned_code
_owned_code:
    .long Lcode_end - Lcode_start
    .long Lcallback - Lcode_start
    .long Lentry - Lcode_start
Lcode_start:

/* At Win64 callee entry RSP % 16 == 8. R11 = mapped .text, R10 = TLS block.
 * Check the planned DWORD index before following it. Check the relocated
 * template pointer before dereferencing it. Use only volatile registers. */
.macro load_tls cookie_value
    movl %esp, %r9d
    andl $15, %r9d
    cmpl $8, %r9d
    jne Lbad_pe
    leaq Lcode_start(%rip), %r11
    movl {index_from_text}(%r11), %eax
    testl %eax, %eax
    jne Lbad_pe
    movq %gs:0x58, %r10
    movq (%r10,%rax,8), %r10
    leaq {cookie_from_text}(%r11), %r9
    cmpq %r9, (%r10)
    jne Lbad_pe
    cmpq $\cookie_value, (%r9)
    jne Lbad_pe
.endm

.macro transition before, scratch, after, next_scratch
    cmpq $\before, 8(%r10)
    jne Lbad_pe
    cmpq $\scratch, 16(%r10)
    jne Lbad_pe
    movq $\after, 8(%r10)
    movq $\next_scratch, 16(%r10)
.endm

Lcallback:
    load_tls {cookie}
    leaq -{text_rva}(%r11), %rax
    cmpq %rax, %rcx
    jne Lbad_pe
    testq %r8, %r8
    jne Lbad_pe
    cmpl $1, %edx
    je Lattach
    testl %edx, %edx
    jne Lbad_pe
    transition {entered}, {entry_scratch}, {detached}, {detach_scratch}
    retq
Lattach:
    transition {seed}, 0, {attached}, {attach_scratch}
    retq

Lentry:
    load_tls {cookie}
    transition {attached}, {attach_scratch}, {entered}, {entry_scratch}
    movl ${return_code}, %eax
    retq
Lbad_pe:
    ud2                         /* bad phase, args or TLS: default SIGILL */
Lcode_end:
    .org Lcode_start + {code_capacity}, 0xcc
