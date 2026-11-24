/* Original Win64 fixture; copied verbatim into the test-generated PEs. */
.const
.globl _static_tls_fixture
.p2align 4
_static_tls_fixture:
    .long Lend-Ltext, Lroot_cb-Ltext, Lroot_entry-Ltext
    .long Ldll_cb-Ltext, Ldll_main-Ltext, Lstep-Ltext
    .long Lsolo_cb-Ltext, Lsolo_entry-Ltext
    .long Lcfg_entry-Ltext, Lcfg_target-Ltext
    .long Lbridge_cb-Ltext, Lbridge_entry-Ltext
Ltext:
.macro tls index
    leaq Ltext(%rip), %r11
    movl {index_delta}(%r11), %eax
    cmpl $\index, %eax
    jne Lbad
    movq %gs:0x58, %r10
    movq (%r10,%rax,8), %r10
    testq $31, %r10
    jnz Lbad
    leaq {cookie_delta}(%r11), %rax
    cmpq %rax, (%r10)       /* relocated pointer in template */
    jne Lbad
    movq (%rax), %rax
    testq %rax, %rax
    jz Lbad
    cmpq $0x12131415, %rax  /* loader must seed security cookie */
    je Lbad
.endm
.macro args
    leaq -{text_rva}(%r11), %rax
    cmpq %rcx, %rax
    jne Lbad
    testq %r8, %r8
    jnz Lbad
    movq %rcx, 8(%rsp)     /* exercise Win64 home space */
    movq %rdx, 32(%rsp)
.endm
.macro phase from, to
    cmpq $\from, 8(%r10)
    jne Lbad
    movq $\to, 8(%r10)
.endm
.macro step expected
    subq $40, %rsp
    movl $\expected, %ecx
    callq *{iat_delta}(%r11)
    addq $40, %rsp
.endm
Lroot_cb:
    tls 0
    args
    testl %edx, %edx
    je Lroot_detach
    cmpl $1, %edx
    jne Lbad
    phase 0, 1
    step 2
    retq
Lroot_detach:
    phase 2, 3
    step 4
    retq
Lroot_entry:
    tls 0
    phase 1, 2
    step 3
    movl $42, %eax
    retq
Ldll_cb:
    tls 1
    args
    testl %edx, %edx
    je Ldll_cb_detach
    cmpl $1, %edx
    jne Lbad
    phase 0, 1
    retq
Ldll_cb_detach:
    phase 5, 6
    retq
Ldll_main:
    tls 1
    args
    testl %edx, %edx
    je Ldll_main_detach
    cmpl $1, %edx
    jne Lbad
    phase 1, 2
    movl $1, %eax
    retq
Ldll_main_detach:
    phase 6, 7
    movl $1, %eax
    retq
Lstep:
    tls 1
    movl %ecx, %eax
    cmpq %rax, 8(%r10)
    jne Lbad
    incq 8(%r10)
    retq
Lsolo_cb:
    tls 0
    args
    testl %edx, %edx
    je Lsolo_detach
    cmpl $1, %edx
    jne Lbad
    phase 0, 1
    retq
Lsolo_detach:
    phase 2, 3
    retq
Lsolo_entry:
    tls 0
    phase 1, 2
    movl $43, %eax
    retq
Lcfg_entry:
    tls 0
    leaq Lcfg_target(%rip), %rcx
    cmpl $1, {mode_delta}(%r11)
    jne Lcfg_check
    decq %rcx
Lcfg_check:
    subq $40, %rsp
    callq *{check_delta}(%r11)
    movq %rcx, %rax
    cmpl $2, {mode_delta}(%r11)
    jne Lcfg_dispatch
    decq %rax
Lcfg_dispatch:
    cmpl $3, {mode_delta}(%r11)
    jne Lcfg_do_call
    movq $0, {dispatch_delta}(%r11) /* write must fault on a sealed slot */
Lcfg_do_call:
    callq *{dispatch_delta}(%r11)
    addq $40, %rsp
    retq
    nop                      /* callable, but not listed in the GFID table */
Lcfg_target:
    tls 0
    phase 1, 2
    movl $44, %eax
    retq
/* The TLS callback uses direct IAT calls; entry uses both CFG thunks. */
Lbridge_cb:
    tls 0
    args
    testl %edx, %edx
    je Lbridge_detach
    cmpl $1, %edx
    jne Lbad
    phase 0, 1
    subq $40, %rsp
    callq *{iat_delta}(%r11)
    testl %eax, %eax             /* new guest TEB is zero-initialized */
    jne Lbad
    movl $0x89345678, %gs:0x68   /* direct guest store, observed at entry */
    addq $40, %rsp
    retq
Lbridge_detach:
    phase 2, 3
    cmpl $0xfedcba98, %gs:0x68
    jne Lbad
    subq $40, %rsp
    callq *{iat_delta}(%r11)
    cmpl $0xfedcba98, %eax
    jne Lbad
    addq $40, %rsp
    retq

.set BRIDGE_REJECT_CHECK, 1
.set BRIDGE_REJECT_DISPATCH, 2
.set BRIDGE_SET_VALUE, 0xfedcba98
.macro bridge_cfg slot
    leaq Ltext(%rip), %r11
    movq {iat_delta}+\slot(%r11), %rcx
    cmpl $BRIDGE_REJECT_CHECK, {mode_delta}(%r11)
    jne 1f
    incq %rcx
1:
    callq *{check_delta}(%r11)   /* RCX is exact target, checked and preserved */
    movq %rcx, %rax
    cmpl $BRIDGE_REJECT_DISPATCH, {mode_delta}(%r11)
    jne 2f
    incq %rax
2:
    movl $BRIDGE_SET_VALUE, %ecx  /* first Win64 argument for SetLastError */
    callq *{dispatch_delta}(%r11)
.endm

Lbridge_entry:
    tls 0
    phase 1, 2
    pushq %rdi
    pushq %rsi
    pushq %r12
    subq $192, %rsp             /* home space and Win64 XMM saves */
    .irp n,6,7,8,9,10,11,12,13,14,15
        movaps %xmm\n, 32+16*(\n-6)(%rsp)
        pcmpeqb %xmm\n, %xmm\n
    .endr
    movl $0x11111111, %edi
    movl $0x22222222, %esi
    movl $0x33333333, %r12d
    bridge_cfg 0                /* GetLastError reads the callback's store */
    cmpl $0x89345678, %eax
    jne Lbad
    bridge_cfg 8                /* SetLastError writes the guest TEB DWORD */
    cmpl $0xfedcba98, %gs:0x68
    jne Lbad
    cmpq $0x11111111, %rdi
    jne Lbad
    cmpq $0x22222222, %rsi
    jne Lbad
    cmpq $0x33333333, %r12
    jne Lbad
    .irp n,6,7,8,9,10,11,12,13,14,15
        pcmpeqb %xmm0, %xmm0
        pcmpeqb %xmm\n, %xmm0
        pmovmskb %xmm0, %eax
        cmpl $0xffff, %eax
        jne Lbad
        movaps 32+16*(\n-6)(%rsp), %xmm\n
    .endr
    addq $192, %rsp
    popq %r12
    popq %rsi
    popq %rdi
    movl $45, %eax
    retq
Lbad:
    ud2
Lend:
    .org Ltext + {capacity}, 0xcc
