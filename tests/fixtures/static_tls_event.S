/* Original Win64 PE entry and no-op TLS callback. */
.const
.globl _static_tls_event_fixture
.p2align 2
_static_tls_event_fixture:
    .long Levent_entry-Levent_text
Levent_text:
    retq
.macro event_create security, manual, initial, name
    movl $(0xa1234bcd), %gs:0x68
    movabsq $\security, %rcx
    movabsq $\manual, %rdx
    movabsq $\initial, %r8
    movabsq $\name, %r9
    leaq Levent_text(%rip), %r11
    callq *{iat_delta}(%r11)
.endm
.macro event_success
    testq %rax, %rax
    jz Levent_bad
    cmpq $-1, %rax
    je Levent_bad
    cmpl $(0xa1234bcd), %gs:0x68
    jne Levent_bad
.endm
.macro event_unsupported
    testq %rax, %rax
    jnz Levent_bad
    cmpl $(50), %gs:0x68
    jne Levent_bad
.endm
.macro event_op slot, handle, milliseconds, result, error=0xa1234bcd
    movl $(0xa1234bcd), %gs:0x68
    movq \handle, %rcx
    movl $\milliseconds, %edx
    leaq Levent_text(%rip), %r11
    callq *({iat_delta}+8*\slot)(%r11)
    cmpl $\result, %eax
    jne Levent_bad
    cmpl $\error, %gs:0x68
    jne Levent_bad
.endm
Levent_entry:
    subq $56, %rsp                    /* Win64 home space + saved handles */
    /* BOOLs are 32 bits; deliberately poison the upper halves. */
    event_create 0, 0x1234567800000000, 0xfedcba9800000000, 0
    event_success
    movq %rax, 32(%rsp)
    event_create 0, 0x2345678900000001, 0xabcdef9800000000, 0
    event_success
    cmpq 32(%rsp), %rax
    je Levent_bad
    movq %rax, 40(%rsp)
    event_op 1, 32(%rsp), 0, 258         /* Initially clear. */
    event_op 1, 32(%rsp), 2, 258         /* Finite wait on clear state. */
    event_op 2, 32(%rsp), 0, 1
    event_op 2, 32(%rsp), 0, 1           /* A second SetEvent does not accumulate. */
    event_op 1, 32(%rsp), -1, 0          /* Persistent signal, consumed by the wait. */
    event_op 1, 32(%rsp), 0, 258
    event_op 1, $0, 0, -1, 6
    event_op 2, $0, 0, 0, 6
    event_op 1, 40(%rsp), 0, -1, 50      /* Manual-reset waits/signals fail closed. */
    event_op 2, 40(%rsp), 0, 0, 50
    /* Reject both non-null pointer forms without dereferencing them. */
    event_create 0x100000000, 0, 0, 0
    event_unsupported
    event_create 0, 0, 0, 0x100000000
    event_unsupported
    movl $51, %eax
    addq $56, %rsp
    retq
Levent_bad:
    ud2
    .org Levent_text + {capacity}, 0xcc
