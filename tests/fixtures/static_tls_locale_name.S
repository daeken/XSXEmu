/* Owned Win64 locale name probe in the shared TLS fixture image. */
.const
.globl _static_tls_locale_fixture
.p2align 2
_static_tls_locale_fixture:
    .long Llocale_entry-Llocale_text
Llocale_text:
    retq
Llocale_entry:
    subq $56, %rsp
    leaq Llocale_text(%rip), %r11
    xorl %ecx, %ecx
    xorl %edx, %edx
    callq *{iat_delta}(%r11)
    testl %eax, %eax
    jne Llocale_bad
    cmpl $266, %gs:0x68
    jne Llocale_bad
    leaq Llocale_text(%rip), %r11
    leaq 32(%rsp), %rcx
    movl $-1, %edx
    callq *{iat_delta}(%r11)
    testl %eax, %eax
    jne Llocale_bad
    cmpl $87, %gs:0x68
    jne Llocale_bad
    movq $-1, 32(%rsp)
    movq $-1, 40(%rsp)
    leaq Llocale_text(%rip), %r11
    leaq 32(%rsp), %rcx
    movl $3, %edx
    callq *{iat_delta}(%r11)
    testl %eax, %eax
    jne Llocale_bad
    cmpl $266, %gs:0x68
    jne Llocale_bad
    movabsq $0xffff0000006e0065, %rax
    cmpq %rax, 32(%rsp)
    jne Llocale_bad
    leaq Llocale_text(%rip), %r11
    leaq 32(%rsp), %rcx
    movl $6, %edx
    callq *{iat_delta}(%r11)
    cmpl $6, %eax
    jne Llocale_bad
    cmpl $266, %gs:0x68
    jne Llocale_bad
    movabsq $0x0055002d006e0065, %rax
    cmpq %rax, 32(%rsp)
    jne Llocale_bad
    cmpl $0x0053, 40(%rsp)
    jne Llocale_bad
    cmpl $-1, 44(%rsp)
    jne Llocale_bad
    addq $56, %rsp
    movl $51, %eax
    retq
Llocale_bad:
    ud2
    .org Llocale_text + {capacity}, 0xcc
