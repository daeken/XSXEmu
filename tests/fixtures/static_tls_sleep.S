/* Original Win64 PE entry and no-op TLS callback. */
.const
.globl _static_tls_sleep_fixture
.p2align 2
_static_tls_sleep_fixture:
    .long Lsleep_entry-Lsleep_text
Lsleep_text:
    retq
Lsleep_entry:
    subq $56, %rsp
    movq %rbx, 32(%rsp)
    leaq Lsleep_text(%rip), %rbx
    movl $0x12348765, %gs:0x68
    movabsq $0xabcdef9800000000, %rcx  /* Sleep(0): DWORD, not QWORD */
    callq *{iat_delta}(%rbx)
    cmpl $0x12348765, %gs:0x68
    jne Lsleep_bad
    callq *{iat_delta}+16(%rbx)        /* GetTickCount64 */
    movq %rax, 40(%rsp)
    movl $40, %ecx
    callq *{iat_delta}(%rbx)
    cmpl $0x12348765, %gs:0x68
    jne Lsleep_bad
    callq *{iat_delta}+16(%rbx)
    subq 40(%rsp), %rax
    cmpq $39, %rax                     /* allow one ms of clock quantization */
    jb Lsleep_bad
    movq 32(%rsp), %rbx
    addq $56, %rsp
    movl $57, %eax
    retq
Lsleep_bad:
    ud2
    .org Lsleep_text + {capacity}, 0xcc
