/* Original Win64 PE entry and no-op TLS callback. */
.const
.globl _static_tls_semaphore_w_fixture
.p2align 2
_static_tls_semaphore_w_fixture:
    .long Lsemw_entry-Lsemw_text
Lsemw_text:
    retq
.macro semw_call security, initial, maximum, name
    movl $(0x67458321), %gs:0x68
    movabsq $\security, %rcx
    movl $\initial, %edx
    movl $\maximum, %r8d
    movabsq $\name, %r9
    callq *{iat_delta}(%rbx)
.endm
.macro semw_success
    testq %rax, %rax
    jz Lsemw_bad
    cmpq $(-1), %rax
    je Lsemw_bad
    cmpl $(0x67458321), %gs:0x68
    jne Lsemw_bad
.endm
.macro semw_failure error
    testq %rax, %rax
    jnz Lsemw_bad
    cmpl $\error, %gs:0x68
    jne Lsemw_bad
.endm
Lsemw_entry:
    subq $56, %rsp
    movq %rbx, 32(%rsp)
    leaq Lsemw_text(%rip), %rbx
    semw_call 0, 0, 1, 0
    semw_success
    movq %rax, 40(%rsp)
    semw_call 0, 0, 1, 0
    semw_success
    cmpq 40(%rsp), %rax
    je Lsemw_bad
    semw_call 0, -1, 1, 0
    semw_failure 87
    semw_call 0, 0, 0, 0
    semw_failure 87
    semw_call 0, 2, 1, 0
    semw_failure 87
    semw_call 0x100000000, 0, 1, 0
    semw_failure 50
    semw_call 0, 0, 1, 0x100000000
    semw_failure 50
    movq 32(%rsp), %rbx
    addq $56, %rsp
    movl $55, %eax
    retq
Lsemw_bad:
    ud2
    .org Lsemw_text + {capacity}, 0xcc
