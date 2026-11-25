/* Original Win64 fixture. Its alternate return site and the wrong but fully
 * writable destination precede the only accepted call. */
.const
.globl _static_tls_xmem_physical_fixture
.p2align 2
_static_tls_xmem_physical_fixture:
    .long Lphysical_callback_return-Lphysical_code
    .long Lphysical_end-Lphysical_code
Lphysical_code:
    subq $56, %rsp
    leaq Lphysical_code(%rip), %r10
    leaq {output_rva}(%r10), %r8
    movq %r8, 40(%rsp)
    movq $-1, -8(%r8)
    movq $-1, {token_bytes}(%r8)
    movq $0x2c60, 32(%rsp)
    leaq 32(%rsp), %rdx
    movl $0x280, %ecx
    callq *{iat_rva}(%r10)       /* deliberately wrong saved return PC */
    testl %eax, %eax
    jne Lphysical_bad
    movq 40(%rsp), %r8
    cmpq $0, (%r8)
    jne Lphysical_bad

    leaq Lphysical_code(%rip), %r10
    leaq {wrong_rva}(%r10), %r8  /* wrong address in same writable root */
    callq Lphysical_call
    testl %eax, %eax
    jne Lphysical_bad
    leaq Lphysical_code(%rip), %r10
    cmpq $0, {wrong_rva}(%r10)
    jne Lphysical_bad

    movabsq $0x100002c60, %rax
    movq %rax, 32(%rsp)
    movq 40(%rsp), %r8
    callq Lphysical_call
    testl %eax, %eax
    jne Lphysical_bad
    movabsq $0x100002c60, %rax
    cmpq %rax, 32(%rsp)
    jne Lphysical_bad
    movq 40(%rsp), %r8
    cmpq $0, (%r8)
    jne Lphysical_bad

    movq $0x2c60, 32(%rsp)
    callq Lphysical_call
    cmpl $1, %eax
    jne Lphysical_bad
    cmpq $0x2c60, 32(%rsp)
    jne Lphysical_bad
    movq 40(%rsp), %r8
    movq (%r8), %rax
    testq %rax, %rax
    je Lphysical_bad
    xorl %ecx, %ecx
Lphysical_loop:
    cmpq %rax, (%r8,%rcx,8)
    jne Lphysical_bad
    incq %rax
    incl %ecx
    cmpl $0x2c60, %ecx
    jne Lphysical_loop
    cmpq $-1, -8(%r8)
    jne Lphysical_bad
    cmpq $-1, {token_bytes}(%r8)
    jne Lphysical_bad
    movq $-2, (%r8)
    callq Lphysical_call
    testl %eax, %eax
    jne Lphysical_bad
    movq 40(%rsp), %r8
    cmpq $-2, (%r8)
    jne Lphysical_bad
    cmpq $0x2c60, 32(%rsp)
    jne Lphysical_bad
    movl $46, %eax
    jmp Lphysical_done
Lphysical_bad:
    movl $2, %eax
Lphysical_done:
    addq $56, %rsp
    retq
Lphysical_call:
    leaq 40(%rsp), %rdx         /* caller's count qword, past return slot */
    subq $40, %rsp
    movl $0x280, %ecx
    leaq Lphysical_code(%rip), %r10
    callq *{iat_rva}(%r10)
Lphysical_callback_return:
    addq $40, %rsp
    retq
Lphysical_end:
    .fill {capacity}-(.-Lphysical_code), 1, 0xcc
