/* Owned Win64 fixture for confined title-data file operations. */
.macro title_read offset, overlapped
    leaq Lcreate_text(%rip), %r11
    movq 48(%rsp), %rcx
    leaq {buffer_delta}+\offset(%r11), %rdx
    movl $4096, %r8d
    leaq 40(%rsp), %r9
    movq $\overlapped, 32(%rsp)
    movq $-1, 40(%rsp)
    callq *{iat_delta}+16(%r11)
    cmpl $-1, 44(%rsp)
    jne Lcreate_bad
.endm
.const
.globl _static_tls_title_create_file_fixture
.p2align 2
_static_tls_title_create_file_fixture:
    .long Lcreate_entry-Lcreate_text
Lcreate_text:
    retq
Lcreate_entry:
    subq $56, %rsp
    movl $0x87654321, %gs:0x68
    leaq Lcreate_text(%rip), %r11
    leaq {path_delta}(%r11), %rcx
    movl {args_delta}+24(%r11), %edx
    movl $1, %r8d
    xorl %r9d, %r9d
    movq {args_delta}(%r11), %rax
    movq %rax, 32(%rsp)
    movq {args_delta}+8(%r11), %rax
    movq %rax, 40(%rsp)
    movq {args_delta}+16(%r11), %rax
    movq %rax, 48(%rsp)
    callq *{iat_delta}(%r11)
    cmpq $-1, %rax
    je Lcreate_failed
    cmpl $0x87654321, %gs:0x68
    jne Lcreate_bad
    movq %rax, 48(%rsp)
    movq %rax, %rcx
    xorl %edx, %edx
    xorl %r8d, %r8d
    leaq 33(%rsp), %r9
    movb $0x5a, 41(%rsp)
    leaq Lcreate_text(%rip), %r11
    callq *{iat_delta}+8(%r11)
    cmpl $1, %eax
    jne Lcreate_bad
    cmpl $0x87654321, %gs:0x68
    jne Lcreate_bad
    movabsq $116444736012340000, %rax
    cmpq %rax, 33(%rsp)
    jne Lcreate_bad
    cmpb $0x5a, 41(%rsp)
    jne Lcreate_bad
    movq 48(%rsp), %rcx
    leaq 33(%rsp), %rdx
    xorl %r8d, %r8d
    movq %rdx, %r9
    leaq Lcreate_text(%rip), %r11
    callq *{iat_delta}+8(%r11)
    testl %eax, %eax
    jne Lcreate_bad
    cmpl $50, %gs:0x68
    jne Lcreate_bad

    // A non-null fifth argument must not read or move the cursor.
    title_read 0, 1
    testl %eax, %eax
    jne Lcreate_bad
    cmpl $50, %gs:0x68
    jne Lcreate_bad
    cmpl $0, 40(%rsp)
    jne Lcreate_bad
    movl $0x87654321, %gs:0x68
    title_read 0, 0
    cmpl $1, %eax
    jne Lcreate_bad
    cmpl $4096, 40(%rsp)
    jne Lcreate_bad
    leaq Lcreate_text(%rip), %r11
    cmpl $0x41414141, {buffer_delta}(%r11)
    jne Lcreate_bad
    cmpl $0x41414141, {buffer_delta}+4092(%r11)
    jne Lcreate_bad
    movb $0x5a, {buffer_delta}+4101(%r11)
    title_read 4096, 0
    cmpl $1, %eax
    jne Lcreate_bad
    cmpl $5, 40(%rsp)
    jne Lcreate_bad
    leaq Lcreate_text(%rip), %r11
    cmpl $0x6c696174, {buffer_delta}+4096(%r11) // 'tail'
    jne Lcreate_bad
    cmpw $0x5a21, {buffer_delta}+4100(%r11) // '!' and untouched sentinel
    jne Lcreate_bad
    title_read 0, 0
    cmpl $1, %eax
    jne Lcreate_bad
    cmpl $0, 40(%rsp)
    jne Lcreate_bad
    cmpl $0x87654321, %gs:0x68
    jne Lcreate_bad

    movq 48(%rsp), %rcx
    leaq Lcreate_text(%rip), %r11
    callq *{iat_delta}+32(%r11)
    cmpl $1, %eax
    jne Lcreate_bad
    title_read 0, 0
    testl %eax, %eax
    jne Lcreate_bad
    cmpl $0, 40(%rsp)
    jne Lcreate_bad
    cmpl $6, %gs:0x68
    jne Lcreate_bad
    movabsq $116444736012340000, %rax
    movq %rax, 33(%rsp)
    movq 48(%rsp), %rcx
    xorl %edx, %edx
    xorl %r8d, %r8d
    leaq 33(%rsp), %r9
    leaq Lcreate_text(%rip), %r11
    callq *{iat_delta}+8(%r11)
    testl %eax, %eax
    jne Lcreate_bad
    cmpl $6, %gs:0x68
    jne Lcreate_bad
    movabsq $116444736012340000, %rax
    cmpq %rax, 33(%rsp)
    jne Lcreate_bad
    movq 48(%rsp), %rcx
    leaq Lcreate_text(%rip), %r11
    callq *{iat_delta}+32(%r11)
    testl %eax, %eax
    jne Lcreate_bad
    cmpl $6, %gs:0x68
    jne Lcreate_bad
    movl $60, %eax
    jmp Lcreate_return
Lcreate_failed:
    movl %gs:0x68, %eax
Lcreate_return:
    addq $56, %rsp
    retq
Lcreate_bad:
    ud2
    .org Lcreate_text + {capacity}, 0xcc
