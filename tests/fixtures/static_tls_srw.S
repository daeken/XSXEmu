/* Original Win64 PE entry and no-op TLS callback. */
.const
.globl _static_tls_srw_fixture
.p2align 2
_static_tls_srw_fixture:
    .long Lsrw_entry-Lsrw_text
Lsrw_text:
    retq
Lsrw_entry:
    subq $40, %rsp
    movq %rbx, 32(%rsp)
    leaq Lsrw_text(%rip), %rbx
    cmpl $1, {mode_delta}(%rbx)
    je Lsrw_recursive
    cmpl $2, {mode_delta}(%rbx)
    je Lsrw_contended
    cmpl $3, {mode_delta}(%rbx)
    je Lsrw_not_owner
    movq $0x12345678, {lock_delta}-8(%rbx)
    movq $0x23456789, {lock_delta}+8(%rbx)
    movl $0xa3b4c5d6, %gs:0x68
    .rept 2
    leaq {lock_delta}(%rbx), %rcx
    callq *{iat_delta}(%rbx)
    movq %gs:0x48, %rax               /* modeled owner, ClientId.UniqueThread */
    testq %rax, %rax
    jz Lsrw_bad
    cmpq %rax, {lock_delta}(%rbx)
    jne Lsrw_bad
    cmpl $(0xa3b4c5d6), %gs:0x68
    jne Lsrw_bad
    leaq {lock_delta}(%rbx), %rcx
    callq *{iat_delta}+8(%rbx)
    cmpq $(0), {lock_delta}(%rbx)
    jne Lsrw_bad
    cmpl $(0xa3b4c5d6), %gs:0x68
    jne Lsrw_bad
    .endr
    cmpq $0x12345678, {lock_delta}-8(%rbx)
    jne Lsrw_bad
    cmpq $0x23456789, {lock_delta}+8(%rbx)
    jne Lsrw_bad
    movq 32(%rsp), %rbx
    addq $40, %rsp
    movl $53, %eax
    retq
Lsrw_recursive:
    leaq {lock_delta}(%rbx), %rcx
    callq *{iat_delta}(%rbx)
    jmp Lsrw_acquire_again
Lsrw_contended:
    movq $-1, {lock_delta}(%rbx)       /* impossible owner ID */
Lsrw_acquire_again:
    leaq {lock_delta}(%rbx), %rcx
    callq *{iat_delta}(%rbx)
    jmp Lsrw_bad
Lsrw_not_owner:
    movq $-1, {lock_delta}(%rbx)
    leaq {lock_delta}(%rbx), %rcx
    callq *{iat_delta}+8(%rbx)
Lsrw_bad:
    ud2
    .org Lsrw_text + {capacity}, 0xcc
