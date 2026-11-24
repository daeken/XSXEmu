/* Owned Win64 fixture for the confined title-data CreateFileW bridge. */
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
    movl $0x80000000, %edx
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
    leaq Lcreate_text(%rip), %r11
    callq *{iat_delta}+16(%r11)
    cmpl $1, %eax
    jne Lcreate_bad
    movq 48(%rsp), %rcx
    leaq Lcreate_text(%rip), %r11
    callq *{iat_delta}+16(%r11)
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
