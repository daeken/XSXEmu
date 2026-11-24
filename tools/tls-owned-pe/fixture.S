/* SysV -> Win64 boundary, only for these three fixed calls. Keep the original
 * frame, 32 bytes of home space and 16-byte pre-call alignment. R12 survives
 * both ABIs; save the entry result across detach and the private setter. */
.text
.macro check_host ctx
    movq %gs:0, %r10
    cmpq {host0}(\ctx), %r10
    jne Lbad_boundary
    movq %gs:0x30, %r10
    cmpq {host30}(\ctx), %r10
    jne Lbad_boundary
.endm

.macro check_guest ctx
    movq %gs:0x30, %r10
    cmpq {guest_base}(\ctx), %r10
    jne Lbad_boundary
    movq %gs:0x58, %r10
    cmpq {vector}(\ctx), %r10
    jne Lbad_boundary
    cmpq %gs:{context_slot}, \ctx
    jne Lbad_boundary
.endm

.globl _run_owned_pe
_run_owned_pe:
    pushq %r12
    subq $48, %rsp
    movq %rdi, %r12
    movq {guest_base}(%r12), %rdi
    callq __thread_set_tsd_base
    check_guest %r12

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
    check_guest %r12

    movq {host_base}(%r12), %rdi
    callq __thread_set_tsd_base
    check_host %r12
    movl 32(%rsp), %eax
    addq $48, %rsp
    popq %r12
    retq
Lbad_boundary:
    ud2                         /* never return to Rust if GS is unknown */

/* Same fixed Win64 frame pattern as teb-boundary. Keep 32-byte home
 * space, stack slots #5..7 and 16-byte pre-call alignment. The SysV
 * setter may clobber positional argument registers and Win64's extra
 * nonvolatiles (RDI/RSI and the low 128 bits of XMM6..15). */
.set FRAME, 376
.macro save_win64
    subq $FRAME, %rsp
    .irp n,0,1,2,3
        movaps %xmm\n, 64+16*\n(%rsp)
    .endr
    movq %rcx, 128(%rsp)
    movq %rdx, 136(%rsp)
    movq %r8, 144(%rsp)
    movq %r9, 152(%rsp)
    .irp n,6,7,8,9,10,11,12,13,14,15
        movaps %xmm\n, 160+16*(\n-6)(%rsp)
    .endr
    movq %rdi, 320(%rsp)
    movq %rsi, 328(%rsp)
.endm

.macro switch_to field
    movq 336(%rsp), %rax
    movq \field(%rax), %rdi
    callq __thread_set_tsd_base
    movq 336(%rsp), %rax
.endm

.macro forward_args
    movq FRAME+40(%rsp), %r10
    movq %r10, 32(%rsp)
    movq FRAME+48(%rsp), %r10
    movq %r10, 40(%rsp)
    movq 128(%rsp), %rcx
    movq 136(%rsp), %rdx
    movq 144(%rsp), %r8
    movq 152(%rsp), %r9
    .irp n,0,1,2,3
        movaps 64+16*\n(%rsp), %xmm\n
    .endr
.endm

.macro restore_win64
    .irp n,6,7,8,9,10,11,12,13,14,15
        movaps 160+16*(\n-6)(%rsp), %xmm\n
    .endr
    movq 320(%rsp), %rdi
    movq 328(%rsp), %rsi
    addq $FRAME, %rsp
    retq
.endm

/* Win64 import: six guest arguments. Context comes from the test TEB. */
.globl _import_thunk
_import_thunk:
    save_win64
    movq %gs:{context_slot}, %rax
    movq %rax, 336(%rsp)
    check_guest %rax
    switch_to {host_base}
    check_host %rax
    forward_args
    movq %rax, 48(%rsp)      /* trusted ctx as #7 for the Rust provider */
    callq _owned_provider
    movq %rax, 344(%rsp)
    switch_to {guest_base}
    check_guest %rax
    movq 344(%rsp), %rax
    restore_win64

/* Rust requests only the nested target already validated in this fixture. */
.globl _enter_nested
_enter_nested:
    save_win64
    movq FRAME+56(%rsp), %rax
    movq %rax, 336(%rsp)
    check_host %rax
    switch_to {guest_base}
    check_guest %rax
    forward_args
    callq *{nested}(%rax)
    movaps %xmm0, 352(%rsp)
    movq 336(%rsp), %rax
    check_guest %rax
    switch_to {host_base}
    check_host %rax
    movaps 352(%rsp), %xmm0
    restore_win64

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
    .long Lnested - Lcode_start
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
    cmpq ${attached}, 8(%r10)
    jne Lbad_pe
    cmpq ${attach_scratch}, 16(%r10)
    jne Lbad_pe

    /* Home space + two stack args + guest nonvolatile saves. */
    pushq %rdi
    pushq %rsi
    subq $88, %rsp
    movaps %xmm6, 48(%rsp)
    movaps %xmm15, 64(%rsp)
    movl $0x21212121, %edi
    movl $0x42424242, %esi
    pcmpeqd %xmm6, %xmm6
    movl $0x13579bdf, %eax
    movd %eax, %xmm15
    pshufd $0, %xmm15, %xmm15
    movabsq ${p_int}, %rcx
    movabsq ${p_double}, %rax
    movq %rax, %xmm1
    movabsq ${p_int3}, %r8
    movl ${p_float}, %eax
    movd %eax, %xmm3
    movabsq ${p_stack_int}, %rax
    movq %rax, 32(%rsp)
    movabsq ${p_stack_double}, %rax
    movq %rax, 40(%rsp)
    callq *{iat_from_text}(%r11)
    movabsq ${p_ok}, %r10
    cmpq %r10, %rax
    jne Lbad_pe
    cmpq $0x21212121, %rdi
    jne Lbad_pe
    cmpq $0x42424242, %rsi
    jne Lbad_pe
    pcmpeqd %xmm0, %xmm0
    pcmpeqb %xmm6, %xmm0
    pmovmskb %xmm0, %ecx
    cmpl $0xffff, %ecx
    jne Lbad_pe
    movl $0x13579bdf, %ecx
    movd %ecx, %xmm0
    pshufd $0, %xmm0, %xmm0
    pcmpeqb %xmm15, %xmm0
    pmovmskb %xmm0, %ecx
    cmpl $0xffff, %ecx
    jne Lbad_pe
    movaps 48(%rsp), %xmm6
    movaps 64(%rsp), %xmm15
    addq $88, %rsp
    popq %rsi
    popq %rdi

    load_tls {cookie}
    transition {nested_phase}, {nested_scratch}, {entered}, {entry_scratch}
    movl ${return_code}, %eax
    retq

Lnested:
    /* Consume the Win64 register/stack arguments and exercise home space. */
    movq %rdx, 8(%rsp)
    movq %xmm0, %rax
    movabsq ${c_double}, %r11
    cmpq %r11, %rax
    jne Lbad_pe
    movd %xmm2, %eax
    cmpl ${c_float}, %eax
    jne Lbad_pe
    movabsq ${c_int4}, %r11
    cmpq %r11, %r9
    jne Lbad_pe
    movabsq ${c_stack_double}, %r11
    cmpq %r11, 40(%rsp)
    jne Lbad_pe
    movabsq ${c_stack_int}, %r11
    cmpq %r11, 48(%rsp)
    jne Lbad_pe
    load_tls {cookie}
    leaq -{text_rva}(%r11), %rax
    cmpq %rax, 8(%rsp)
    jne Lbad_pe
    transition {attached}, {attach_scratch}, {nested_phase}, {nested_scratch}
    movabsq ${c_ok}, %rax
    movq %rax, %xmm0
    retq
Lbad_pe:
    ud2                         /* bad phase, args or TLS: default SIGILL */
Lcode_end:
    .org Lcode_start + {code_capacity}, 0xcc
