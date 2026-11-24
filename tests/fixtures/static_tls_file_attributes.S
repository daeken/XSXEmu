/* Original Win64 PE entry and no-op TLS callback. */
.const
.globl _static_tls_file_attributes_fixture
.p2align 2
_static_tls_file_attributes_fixture:
    .long Lattrs_entry-Lattrs_text
Lattrs_text:
    retq
Lattrs_entry:
    pushq %rbx
    pushq %rsi
    pushq %rdi
    subq $32, %rsp
    leaq Lattrs_text(%rip), %rbx
    leaq {cases_delta}(%rbx), %rsi
    movl $1, %edi
Lattrs_case:
    xorl %ecx, %ecx
    cmpw $0, 8(%rsi)
    je Lattrs_call
    leaq 8(%rsi), %rcx
Lattrs_call:
    movl $0x12345678, %gs:0x68
    callq *{iat_delta}(%rbx)
    cmpl (%rsi), %eax
    jne Lattrs_fail
    movl %gs:0x68, %eax
    cmpl 4(%rsi), %eax
    jne Lattrs_fail
    addq ${case_size}, %rsi
    incl %edi
    cmpl ${case_count}, %edi
    jbe Lattrs_case
    movl $54, %eax
    jmp Lattrs_return
Lattrs_fail:
    movl %edi, %eax
Lattrs_return:
    addq $32, %rsp
    popq %rdi
    popq %rsi
    popq %rbx
    retq
    .org Lattrs_text + {capacity}, 0xcc
