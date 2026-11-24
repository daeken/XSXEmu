/* Owned Win64 WSAStartup probe: no socket calls. */
.const
.globl _static_tls_winsock_init_fixture
.p2align 2
_static_tls_winsock_init_fixture:
    .long Lwsa_entry-Lwsa_text
Lwsa_text:
    retq
.macro wsa_call version
    /* Nonzero upper bits check that the ABI takes a WORD, not a DWORD. */
    movl $(0xa55a0000 + \version),%ecx
    leaq Lwsa_text(%rip),%r11
    callq *{iat_delta}(%r11)
    cmpl $0x8e77aacc,%gs:0x68
    jne Lwsa_bad
.endm
Lwsa_entry:
    subq $456,%rsp
    movl $0x8e77aacc,%gs:0x68
    movabsq $0xaaaaaaaaaaaaaaaa,%rax
    xorl %r10d,%r10d
Lwsa_fill:
    movq %rax,32(%rsp,%r10,8)
    incq %r10
    cmpq $53,%r10
    jne Lwsa_fill
    leaq 40(%rsp),%rdx
    wsa_call 0x0200
    cmpl $10092,%eax
    jne Lwsa_bad
    movabsq $0xaaaaaaaaaaaaaaaa,%rax
    xorl %r10d,%r10d
Lwsa_check_failure:
    cmpq %rax,40(%rsp,%r10,8)
    jne Lwsa_bad
    incq %r10
    cmpq $51,%r10
    jne Lwsa_check_failure
    xorl %edx,%edx
    wsa_call 0x0202
    cmpl $10014,%eax
    jne Lwsa_bad
    leaq 40(%rsp),%rdx
    wsa_call 0x0202
    testl %eax,%eax
    jne Lwsa_bad
    leaq Lwsa_expected(%rip),%r11
    xorl %r10d,%r10d
Lwsa_check_data:
    movb (%r11,%r10),%al
    cmpb %al,40(%rsp,%r10)
    jne Lwsa_bad
    incq %r10
    cmpq $408,%r10
    jne Lwsa_check_data
    leaq 40(%rsp),%rdx
    wsa_call 0x0002
    testl %eax,%eax
    jne Lwsa_bad
    cmpl $0x02020002,40(%rsp)
    jne Lwsa_bad
    leaq 40(%rsp),%rdx
    wsa_call 0xff01
    testl %eax,%eax
    jne Lwsa_bad
    cmpl $0x02020101,40(%rsp)
    jne Lwsa_bad
    cmpl $0xffbb7fff,44(%rsp)
    jne Lwsa_bad
    movabsq $0xaaaaaaaaaaaaaaaa,%rax
    cmpq %rax,32(%rsp)
    jne Lwsa_bad
    cmpq %rax,448(%rsp)
    jne Lwsa_bad
    movl $52,%eax
    addq $456,%rsp
    retq
Lwsa_bad:
    ud2
Lwsa_expected:
    .short 0x0202, 0x0202, 0, 0
    .quad 0
    .asciz "XSXEmu Winsock 2.2"
    .org Lwsa_expected + 0x111, 0
    .asciz "Offline (initialization only)"
    .org Lwsa_expected + 0x198, 0
    .org Lwsa_text + {capacity}, 0xcc
