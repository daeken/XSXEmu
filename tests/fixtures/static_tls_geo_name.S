/* Owned Win64 geo name fixture using the shared TLS image layout. */
.const
.globl _static_tls_geo_fixture
.p2align 2
_static_tls_geo_fixture:
    .long Lgeo_name_entry-Lgeo_text
Lgeo_text:
    retq
Lgeo_name_entry:
    subq $40, %rsp
    movl $0x87654321, %gs:0x68
    xorl %ecx, %ecx
    xorl %edx, %edx
    leaq Lgeo_text(%rip), %r11
    callq *{iat_delta}(%r11)
    cmpl $3, %eax
    jne Lgeo_bad
    cmpl $0x87654321, %gs:0x68
    jne Lgeo_bad
    movq $-1, 32(%rsp)
    leaq Lgeo_text(%rip), %r11
    leaq 32(%rsp), %rcx
    movl $2, %edx
    callq *{iat_delta}(%r11)
    testl %eax, %eax
    jne Lgeo_bad
    cmpl $122, %gs:0x68
    jne Lgeo_bad
    cmpq $-1, 32(%rsp)
    jne Lgeo_bad
    leaq Lgeo_text(%rip), %r11
    xorl %ecx, %ecx
    movl $3, %edx
    callq *{iat_delta}(%r11)
    testl %eax, %eax
    jne Lgeo_bad
    cmpl $87, %gs:0x68
    jne Lgeo_bad
    leaq Lgeo_text(%rip), %r11
    leaq 32(%rsp), %rcx
    movl $3, %edx
    callq *{iat_delta}(%r11)
    cmpl $3, %eax
    jne Lgeo_bad
    cmpl $87, %gs:0x68
    jne Lgeo_bad
    movabsq $0xffff000000530055, %rax
    cmpq %rax, 32(%rsp)
    jne Lgeo_bad
    addq $40, %rsp
    movl $50, %eax
    retq
Lgeo_bad:
    ud2
    .org Lgeo_text + {capacity}, 0xcc
