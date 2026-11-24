/* Original Win64 PE entry and no-op TLS callback. */
.const
.globl _static_tls_mutex_fixture
.p2align 2
_static_tls_mutex_fixture:
    .long Lmutex_entry-Lmutex_text
Lmutex_text:
    retq
.macro mutex_create security, owner, name
    movl $(0xa2468bce), %gs:0x68
    movabsq $\security, %rcx
    movabsq $\owner, %rdx
    movabsq $\name, %r8
    leaq Lmutex_text(%rip), %r11
    callq *{iat_delta}(%r11)
.endm
.macro mutex_success
    testq %rax, %rax
    jz Lmutex_bad
    cmpq $-1, %rax
    je Lmutex_bad
    cmpl $(0xa2468bce), %gs:0x68
    jne Lmutex_bad
.endm
.macro mutex_unsupported
    testq %rax, %rax
    jnz Lmutex_bad
    cmpl $(50), %gs:0x68
    jne Lmutex_bad
.endm
Lmutex_entry:
    subq $40, %rsp                   /* Win64 home space + saved handle */
    mutex_create 0, 0, 0
    mutex_success
    movq %rax, 32(%rsp)
    mutex_create 0, 0x12345678ffffffff, 0
    mutex_success
    cmpq 32(%rsp), %rax
    je Lmutex_bad
    mutex_create 0x100000000, 0, 0
    mutex_unsupported
    mutex_create 0, 0, 0x100000000
    mutex_unsupported
    movl $52, %eax
    addq $40, %rsp
    retq
Lmutex_bad:
    ud2
    .org Lmutex_text + {capacity}, 0xcc
