/* Original Win64 code for a standalone PE using the shared TLS image layout. */
.const
.globl _static_tls_exception_filter_fixture
.p2align 2
_static_tls_exception_filter_fixture:
    .long Lfilter_entry-Lfilter_text
Lfilter_text:
    retq                              /* no-op TLS attach/detach callback */
.macro check_swap next, previous, sentinel
    movl $\sentinel, %gs:0x68
    movabsq $\next, %rcx
    leaq Lfilter_text(%rip), %r11
    callq *{iat_delta}(%r11)
    movabsq $\previous, %rdx
    cmpq %rdx, %rax
    jne Lfilter_bad
    cmpl $\sentinel, %gs:0x68
    jne Lfilter_bad
.endm
Lfilter_entry:
    subq $40, %rsp                    /* Win64 shadow space and alignment */
    /* Deliberately unmapped tokens: the bridge must not touch or invoke them. */
    check_swap 0x0000123487654321, 0, 0xdeadbeef
    check_swap 0x0000432112345678, 0x0000123487654321, 0x1234abcd
    check_swap 0, 0x0000432112345678, 0xfedcba98
    check_swap 0, 0, 0x5aa5a55a
    movl $50, %eax
    addq $40, %rsp
    retq
Lfilter_bad:
    ud2
    .org Lfilter_text + {capacity}, 0xcc
