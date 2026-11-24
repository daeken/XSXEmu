/* Original Win64 fixture; copied verbatim into the test-generated PEs. */
.const
.globl _static_tls_fixture
.p2align 4
_static_tls_fixture:
    .long Lend-Ltext, Lroot_cb-Ltext, Lroot_entry-Ltext
    .long Ldll_cb-Ltext, Ldll_main-Ltext, Lstep-Ltext
    .long Lsolo_cb-Ltext, Lsolo_entry-Ltext
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
Lbad:
    ud2
Lend:
    .org Ltext + {capacity}, 0xcc
