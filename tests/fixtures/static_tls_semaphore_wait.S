/* Original Win64 PE entry and no-op TLS callback. */
.const
.globl _static_tls_semaphore_wait_fixture
.p2align 2
_static_tls_semaphore_wait_fixture:
    .long Lsw_entry-Lsw_text
Lsw_text:
    retq
.macro sw_wait ms, expected
    movq 56(%rsp), %rcx
    movl $\ms, %edx
    callq *{iat_delta}+8(%rbx)
    cmpl $\expected, %eax
    jne Lsw_bad
.endm
.macro sw_post count, expected
    movq 56(%rsp), %rcx
    movl $\count, %edx
    leaq 64(%rsp), %r8
    callq *{iat_delta}+16(%rbx)
    cmpl $\expected, %eax
    jne Lsw_bad
.endm
Lsw_entry:
    subq $72, %rsp
    movq %rbx, 48(%rsp)
    leaq Lsw_text(%rip), %rbx
    movl $0x12348765, %gs:0x68
    xorl %ecx, %ecx
    xorl %edx, %edx
    movl $1, %r8d
    xorl %r9d, %r9d
    movl $0, 32(%rsp)
    movl $0x00100002, 40(%rsp)
    callq *{iat_delta}(%rbx)
    testq %rax, %rax
    jz Lsw_bad
    movq %rax, 56(%rsp)
    sw_wait 0, 258
    sw_post 1, 1
    cmpl $0, 64(%rsp)
    jne Lsw_bad
    cmpl $0x12348765, %gs:0x68
    jne Lsw_bad
    movl $-1, 64(%rsp)
    sw_post 1, 0
    cmpl $298, %gs:0x68
    jne Lsw_bad
    cmpl $-1, 64(%rsp)
    jne Lsw_bad
    sw_wait 0, 0
    sw_wait 1, 258
    cmpl $298, %gs:0x68
    jne Lsw_bad
    sw_post 0, 0
    cmpl $87, %gs:0x68
    jne Lsw_bad
    cmpl $-1, 64(%rsp)
    jne Lsw_bad
    xorq %rcx, %rcx
    xorl %edx, %edx
    callq *{iat_delta}+8(%rbx)
    cmpl $-1, %eax
    jne Lsw_bad
    cmpl $6, %gs:0x68
    jne Lsw_bad
    movq 48(%rsp), %rbx
    addq $72, %rsp
    movl $56, %eax
    retq
Lsw_bad:
    ud2
    .org Lsw_text + {capacity}, 0xcc
