/* Original Win64 code for a standalone PE using the shared TLS image layout. */
.const
.globl _static_tls_thread_id_fixture
.p2align 2
_static_tls_thread_id_fixture:
    .long Lthread_id_entry-Lthread_id_text, Lcurrent_process_entry-Lthread_id_text
Lthread_id_text:
    retq                              /* no-op TLS attach/detach callback */
.macro check_thread_id sentinel
    movl $\sentinel, %gs:0x68
    leaq Lthread_id_text(%rip), %r11
    callq *{iat_delta}(%r11)
    movl %eax, %eax                    /* DWORD return, compare as a qword */
    cmpq 32(%rsp), %rax
    jne Lthread_id_bad
    cmpq %rax, %gs:0x48                /* ClientId.UniqueThread unchanged */
    jne Lthread_id_bad
    cmpl $\sentinel, %gs:0x68
    jne Lthread_id_bad
.endm
Lthread_id_entry:
    subq $40, %rsp                     /* Win64 home space + saved ID */
    movq %gs:0x48, %rax                /* modeled TEB ID before any call */
    testq %rax, %rax
    jz Lthread_id_bad
    movq %rax, 32(%rsp)
    check_thread_id 0xdeadbeef
    check_thread_id 0x1234abcd
    movl $48, %eax
    addq $40, %rsp
    retq
Lcurrent_process_entry:
    subq $40, %rsp
    movl $0xdeadbeef, %gs:0x68
    leaq Lthread_id_text(%rip), %r11
    callq *{iat_delta}(%r11)
    cmpq $-1, %rax                   /* Full-width guest pseudo-handle. */
    jne Lthread_id_bad
    cmpl $0xdeadbeef, %gs:0x68
    jne Lthread_id_bad
    movl $48, %eax
    addq $40, %rsp
    retq
Lthread_id_bad:
    ud2
    .org Lthread_id_text + {capacity}, 0xcc
