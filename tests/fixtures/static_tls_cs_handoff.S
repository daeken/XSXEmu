/* Owned two-worker handoff through the normal Win64 IAT and guest GS. */
.const
.p2align 4
.globl _cs_handoff_fixture
_cs_handoff_fixture:
    .long Lcs_main-Lcs_text
Lcs_text:
    retq                              /* TLS callback: no notifications needed */
.set CS, {data}
.set OWNER_READY, {data}+40
.set PEER_READY, {data}+48
.set PEER_ENTERED, {data}+56
.set THREAD_A, {data}+64
.set THREAD_B, {data}+72
.set PAYLOAD, {data}+80
.macro cs_api slot
    callq *Lcs_text+{iat}+8*\slot(%rip)
.endm
.macro cs_expect condition
    j\condition 1f
    ud2
1:
.endm
.macro cs_lock slot
    leaq Lcs_text+CS(%rip), %rcx
    cs_api \slot
.endm
.macro cs_make_sem dest
    xorl %ecx, %ecx
    xorl %edx, %edx
    movl $1, %r8d
    xorl %r9d, %r9d
    cs_api 4                         /* CreateSemaphoreW */
    testq %rax, %rax
    cs_expect ne
    movq %rax, Lcs_text+\dest(%rip)
.endm
.macro cs_wait handle, timeout=5000, expected=0
    movq Lcs_text+\handle(%rip), %rcx
    movl $\timeout, %edx
    cs_api 5                         /* WaitForSingleObject */
    cmpl $\expected, %eax
    cs_expect e
.endm
.macro cs_signal handle
    movq Lcs_text+\handle(%rip), %rcx
    movl $1, %edx
    xorl %r8d, %r8d
    cs_api 6                         /* ReleaseSemaphore */
    testl %eax, %eax
    cs_expect ne
.endm
.macro cs_spawn start, dest
    xorl %ecx, %ecx
    xorl %edx, %edx
    leaq \start(%rip), %r8
    xorl %r9d, %r9d
    movq $0, 32(%rsp)
    movq $0, 40(%rsp)
    cs_api 7                         /* CreateThread */
    testq %rax, %rax
    cs_expect ne
    movq %rax, Lcs_text+\dest(%rip)
.endm
.macro cs_close handle
    movq Lcs_text+\handle(%rip), %rcx
    cs_api 8                         /* CloseHandle */
    testl %eax, %eax
    cs_expect ne
.endm
.macro cs_error expected
    cmpl $\expected, %gs:0x68
    cs_expect e
.endm
Lcs_main:
    subq $56, %rsp
    movl $0x1357, %gs:0x68
    xorl %edx, %edx                   /* no spins: blocking implementation */
    cs_lock 0                        /* InitializeCriticalSectionAndSpinCount */
    testl %eax, %eax
    cs_expect ne
    cs_make_sem OWNER_READY
    cs_make_sem PEER_READY
    cs_make_sem PEER_ENTERED
    cs_spawn Lcs_owner, THREAD_A
    cs_spawn Lcs_peer, THREAD_B
    cs_wait THREAD_A
    cs_wait THREAD_B
    cmpl $3, Lcs_text+PAYLOAD(%rip)
    cs_expect e
    cs_lock 3                        /* DeleteCriticalSection, after both joins */
    cs_close THREAD_A
    cs_close THREAD_B
    cs_close OWNER_READY
    cs_close PEER_READY
    cs_close PEER_ENTERED
    cs_error 0x1357
    movl $59, %eax
    addq $56, %rsp
    retq
Lcs_owner:
    subq $40, %rsp
    movl $0x2468, %gs:0x68
    cs_lock 1                        /* EnterCriticalSection */
    cs_lock 1                        /* recursive acquisition */
    cs_error 0x2468
    movl $1, Lcs_text+PAYLOAD(%rip)
    cs_signal OWNER_READY
    cs_wait PEER_READY
    cs_lock 2                        /* LeaveCriticalSection, still owner */
    cs_wait PEER_ENTERED, 500, 258    /* A partial release must not let B enter. */
    cs_error 0x2468
    movl $2, Lcs_text+PAYLOAD(%rip)
    cs_lock 2                        /* final release enables handoff */
    cs_error 0x2468
    xorl %eax, %eax
    addq $40, %rsp
    retq
Lcs_peer:
    subq $40, %rsp
    movl $0x369c, %gs:0x68
    cs_wait OWNER_READY
    cs_signal PEER_READY
    cs_lock 1                        /* blocks until the owner's final leave */
    cmpl $2, Lcs_text+PAYLOAD(%rip)
    cs_expect e
    movl $3, Lcs_text+PAYLOAD(%rip)
    cs_error 0x369c
    cs_lock 2
    cs_signal PEER_ENTERED
    cs_error 0x369c
    xorl %eax, %eax
    addq $40, %rsp
    retq
    .space {capacity}-(.-Lcs_text), 0xcc
