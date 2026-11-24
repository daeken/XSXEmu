/* Original Win64 code for a standalone PE using the shared TLS image layout. */
.const
.globl _static_tls_semaphore_fixture
.p2align 2
_static_tls_semaphore_fixture:
    .long Lsem_entry-Lsem_text
Lsem_text:
    retq                              /* no-op TLS attach/detach callback */
.macro create initial, maximum, flags, access
    movl $(0x1234abcd), %gs:0x68
    xorl %ecx, %ecx
    movl $\initial, %edx
    movl $\maximum, %r8d
    xorl %r9d, %r9d
    movl $\flags, 32(%rsp)
    movl $(0xbaadf00d), 36(%rsp)         /* upper half is not part of DWORD */
    movl $\access, 40(%rsp)
    movl $(0xdeadbeef), 44(%rsp)
    leaq Lsem_text(%rip), %r11
    callq *{iat_delta}(%r11)
.endm
.macro success
    testq %rax, %rax
    jz Lsem_bad
    cmpq $-1, %rax
    je Lsem_bad
    cmpl $(0x1234abcd), %gs:0x68
    jne Lsem_bad
.endm
.macro failure error
    testq %rax, %rax
    jnz Lsem_bad
    cmpl $\error, %gs:0x68
    jne Lsem_bad
.endm
Lsem_entry:
    subq $56, %rsp                     /* Win64 home space, args 5/6, saved handle */
    create 0, 0x7fff, 0, 0x00100002
    success
    movq %rax, 48(%rsp)
    create 7, 7, 0, 0x00100002
    success
    cmpq 48(%rsp), %rax
    je Lsem_bad
    create 0, 2, 1, 0x00100002         /* reject flags (arg 5) */
    failure 87
    create 0, 2, 0, 0x80000000         /* reject generic access (arg 6) */
    failure 50
    create -1, 2, 0, 0x00100002        /* reject signed initial count */
    failure 87
    movl $49, %eax
    addq $56, %rsp
    retq
Lsem_bad:
    ud2
    .org Lsem_text + {capacity}, 0xcc
