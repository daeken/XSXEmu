/* Original Win64 PE entry and no-op TLS callback. */
.const
.globl _static_tls_init_cs_fixture
.p2align 2
_static_tls_init_cs_fixture:
    .long Lics_entry-Lics_text
Lics_text:
    retq
.macro ics_call slot
    leaq {cs_delta}(%rbx), %rcx
    callq *{iat_delta}+\slot(%rbx)
    cmpl $(0x76543210), %gs:0x68
    jne Lics_bad
.endm
Lics_entry:
    subq $40, %rsp
    movq %rbx, 32(%rsp)
    leaq Lics_text(%rip), %rbx
    movl $0x76543210, %gs:0x68
    movq $0x12345678, {cs_delta}-8(%rbx)
    movq $0x23456789, {cs_delta}+40(%rbx)
    movq $-1, {cs_delta}+32(%rbx)
    ics_call 0                       /* initialize opaque storage */
    cmpq $0, {cs_delta}+32(%rbx)     /* default spin count */
    jne Lics_bad
    ics_call 8                       /* recursive enter */
    ics_call 8
    ics_call 16
    ics_call 16
    ics_call 24                      /* delete and reuse the address */
    ics_call 0
    ics_call 24
    cmpq $0x12345678, {cs_delta}-8(%rbx)
    jne Lics_bad
    cmpq $0x23456789, {cs_delta}+40(%rbx)
    jne Lics_bad
    movq 32(%rsp), %rbx
    addq $40, %rsp
    movl $54, %eax
    retq
Lics_bad:
    ud2
    .org Lics_text + {capacity}, 0xcc
