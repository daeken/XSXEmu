.const
.globl _static_tls_thread_controls_fixture
.p2align 2
_static_tls_thread_controls_fixture:
    .long Ltc_entry-Ltc_text
Ltc_text:
    xorl %eax, %eax
    retq                             /* no-op TLS callback and worker */
Ltc_entry:
    subq $680, %rsp
    movq %rbx, 48(%rsp)
    leaq Ltc_text(%rip), %rbx
    xorl %ecx, %ecx
    xorl %edx, %edx
    movq %rbx, %r8
    xorl %r9d, %r9d
    movl $4, 32(%rsp)               /* CREATE_SUSPENDED */
    movq $0, 40(%rsp)
    callq *{iat}(%rbx)
    testq %rax, %rax
    jz Ltc_bad
    movq %rax, 56(%rsp)
    movq %rax, %rcx
    xorl %edx, %edx
    callq *{iat}+8(%rbx)            /* SetThreadPriority(NORMAL) */
    testl %eax, %eax
    jne Ltc_bad
    cmpl $50, %gs:0x68
    jne Ltc_bad
    movq $-1, 64(%rsp)
    movq $-1, 72(%rsp)
    movq $-1, 80(%rsp)
    movq $-1, 88(%rsp)
    movq 56(%rsp), %rcx
    leaq 64(%rsp), %rdx
    callq *{iat}+32(%rbx)
    cmpl $1, %eax
    jne Ltc_bad
    cmpq $0, 72(%rsp)               /* group and reserved all initialized */
    jne Ltc_bad
    cmpl $50, %gs:0x68
    jne Ltc_bad
    movl $512, 96(%rsp)
    leaq 112(%rsp), %rcx
    leaq 96(%rsp), %rdx
    callq *{iat}+56(%rbx)           /* GetLogicalProcessorInformation */
    cmpl $1, %eax
    jne Ltc_bad
    cmpl $512, 96(%rsp)
    jne Ltc_bad
    xorl %ecx, %ecx
    movl $1, %eax
    leaq 112(%rsp), %rdx
Ltc_records:
    cmpq %rax, (%rdx)
    jne Ltc_bad
    orq %rax, %rcx
    shlq $1, %rax
    addq $32, %rdx
    cmpq $0x10000, %rax
    jb Ltc_records
    cmpq $0xffff, %rcx
    jne Ltc_bad
    cmpq %rcx, 64(%rsp)
    jne Ltc_bad
    movq $0x1f00, 64(%rsp)
    movq 56(%rsp), %rcx
    leaq 64(%rsp), %rdx
    leaq 80(%rsp), %r8
    callq *{iat}+40(%rbx)
    testl %eax, %eax
    jne Ltc_bad
    cmpl $50, %gs:0x68
    jne Ltc_bad
    cmpq $-1, 80(%rsp)
    jne Ltc_bad
    cmpq $-1, 88(%rsp)
    jne Ltc_bad
    movq 56(%rsp), %rcx
    leaq 64(%rsp), %rdx
    callq *{iat}+32(%rbx)
    cmpl $1, %eax
    jne Ltc_bad
    cmpq $0xffff, 64(%rsp)
    jne Ltc_bad
    movq 56(%rsp), %rcx
    callq *{iat}+16(%rbx)           /* ResumeThread */
    cmpl $1, %eax
    jne Ltc_bad
    movq 48(%rsp), %rbx
    addq $680, %rsp
    movl $58, %eax
    retq
Ltc_bad:
    ud2
    .org Ltc_text + {capacity}, 0xcc
