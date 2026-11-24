/* Original fixture bytes, copied at the same RVA into owned EXE and DLL. */
.const
.p2align 4
.globl _thread_fixture
_thread_fixture:
    .long Lthread_entry-Lthread_text, Lthread_callback-Lthread_text, Lthread_dll-Lthread_text, Lthread_probe-Lthread_text
Lthread_text:
.macro th_ref
    leaq Lthread_text(%rip), %r11
.endm
.macro th_api idx
    th_ref
    callq *{iat}+8*\idx(%r11)
.endm
.macro th_tls
    th_ref
    movl {index}(%r11), %eax
    movq %gs:0x58, %r10
    movq (%r10,%rax,8), %r10
.endm
.macro th_ensure condition
    j\condition 1f
    ud2
1:
.endm
Lthread_callback:
    th_tls
    cmpl $2, %edx
    je Lthread_attach
    cmpl $3, %edx
    je Lthread_detach
    testl %edx, %edx
    jnz Lthread_cb_done
    /* Process detach must never precede the worker's detach. */
    cmpq $0, {data}+0x08(%r11)
    je Lthread_cb_done
    cmpl $1, {data}+0x28(%r11)
    th_ensure e
Lthread_cb_done:
    retq
Lthread_attach:
    cmpl $6, {mode}(%r11)
    jne 1f
    cmpq $0, {data}+0x08(%r11) /* Creator published handle before resume. */
    th_ensure ne
1:
    movl $1, {data}+0x3c(%r11)
    leaq {cookie}(%r11), %rax
    cmpq %rax, (%r10)      /* relocated initialized template */
    th_ensure e
    cmpq $0, 8(%r10)       /* brand-new zero-fill, not parent's TLS */
    th_ensure e
    movq $2, 8(%r10)
    retq
Lthread_detach:
    cmpl $0x8765, %gs:0x68
    th_ensure e
    movq $3, 8(%r10)
    movl $1, {data}+0x28(%r11)
    retq
Lthread_dll:
    th_tls
    cmpl $2, %edx
    je Lthread_dll_attach
    cmpl $3, %edx
    jne Lthread_dll_ok
    cmpq $3, 8(%r10)       /* TLS callback ran before DllMain */
    th_ensure e
    movl $2, {data}+0x28(%r11)
    jmp Lthread_dll_ok
Lthread_dll_attach:
    cmpq $2, 8(%r10)
    th_ensure e
    movq $7, 8(%r10)
    movl $7, {data}+0x40(%r11)
Lthread_dll_ok:
    movl $1, %eax
    retq
Lthread_probe:
    th_tls
    movq 8(%r10), %rax
    testq %rax, %rax
    jnz 1f
    movl {data}+0x28(%r11), %eax
    testl %eax, %eax
    jnz 1f
    movl {data}+0x40(%r11), %eax
1:
    retq
/* Two independent zero-count binary semaphores. */
.macro th_make_semaphore offset
    xorq %rcx, %rcx
    xorl %edx, %edx
    movl $1, %r8d
    xorq %r9, %r9
    movq $0, 32(%rsp)
    movq $0x100002, 40(%rsp)
    th_api 4
    testq %rax, %rax
    th_ensure ne
    th_ref
    movq %rax, {data}+\offset(%r11)
.endm
Lthread_entry:
    subq $56, %rsp
    th_tls
    movq $0x1144, (%r10)   /* must not become the worker template */
    movq $0x2525, 8(%r10)
    movq %r10, {data}+0x20(%r11)
    movq %gs:0x30, %rax
    movq %rax, {data}+0x10(%r11)
    movq %gs:0x08, %rax
    movq %rax, {data}+0x18(%r11)
    th_make_semaphore 0
    th_make_semaphore 0x30
    xorl %ecx, %ecx
    cmpl $3, {mode}(%r11)
    jb 1f
    cmpl $4, {mode}(%r11)
    ja 1f
    leaq Lthread_unexpected_fls(%rip), %rcx
1:
    th_api 12                /* FlsAlloc, process-wide index */
    cmpl $-1, %eax
    th_ensure ne
    th_ref
    movl %eax, {data}+0x38(%r11)
    movl %eax, %ecx
    movl $0xdead, %edx
    th_api 14                /* Creator stores its own value. */
    cmpl $1, %eax
    th_ensure e
    th_ref
    cmpl $4, {mode}(%r11)
    jne 1f
    movl {data}+0x38(%r11), %ecx
    xorl %edx, %edx
    th_api 14                /* Leave only the worker callback value live. */
    cmpl $1, %eax
    th_ensure e
1:
    th_ref
    movl $0x1234, %gs:0x68
    xorq %rcx, %rcx
    movl $65536, %edx
    leaq Lthread_worker(%rip), %r8
    leaq {data}(%r11), %r9
    movq $0, 32(%rsp)
    cmpl $6, {mode}(%r11)
    jb 1f
    movl $4, 32(%rsp)
1:
    leaq {data}+0x2c(%r11), %rax
    movq %rax, 40(%rsp)
    th_api 0
    testq %rax, %rax
    th_ensure ne
    th_ref
    movq %rax, {data}+0x08(%r11)
    movl {data}+0x2c(%r11), %edx
    testl %edx, %edx
    th_ensure ne
    cmpl %gs:0x48, %edx
    th_ensure ne
    cmpl $0x1234, %gs:0x68
    th_ensure e
    movq %rax, %rcx
    xorl %edx, %edx
    th_api 5                  /* Worker must still be waiting on semaphore. */
    cmpl $258, %eax
    th_ensure e
    th_ref
    cmpl $6, {mode}(%r11)
    jb Lthread_check_close
    movq {data}+0x08(%r11), %rcx
    movl $20, %edx
    th_api 5                 /* Remains unsignaled while actually parked. */
    cmpl $258, %eax
    th_ensure e
    th_ref
    cmpl $0, {data}+0x3c(%r11) /* Root THREAD_ATTACH has not run. */
    th_ensure e
    th_api 10
    testq %rax, %rax          /* DLL THREAD_ATTACH has not run. */
    th_ensure e
    th_ref
    cmpl $7, {mode}(%r11)
    je Lthread_close
    movq {data}+0x08(%r11), %rcx
    th_api 2
    cmpl $1, %eax
    th_ensure e
    cmpl $0x1234, %gs:0x68
    th_ensure e
    th_ref
    movq {data}+0x08(%r11), %rcx
    th_api 2                 /* Worker can run, but hasn't received work yet. */
    testl %eax, %eax
    th_ensure e
    cmpl $0x1234, %gs:0x68
    th_ensure e
    jmp Lthread_release
Lthread_check_close:
    cmpl $1, {mode}(%r11)
    je Lthread_close              /* close running worker then return without release */
    cmpl $2, {mode}(%r11)
    jne Lthread_release
Lthread_close:
    movq {data}+0x08(%r11), %rcx
    th_api 8
    cmpl $1, %eax
    th_ensure e
    th_ref
    movq {data}+0x08(%r11), %rcx
    xorl %edx, %edx
    th_api 5
    cmpl $-1, %eax
    th_ensure e
    cmpl $6, %gs:0x68
    th_ensure e
    th_ref
    movq {data}+0x08(%r11), %rcx
    th_api 2
    cmpl $-1, %eax           /* Closed handles can't resume workers. */
    th_ensure e
    cmpl $6, %gs:0x68
    th_ensure e
    th_ref
    cmpl $7, {mode}(%r11)
    je Lthread_done
    cmpl $1, {mode}(%r11)
    je Lthread_done
Lthread_release:
    th_ref
    movq {data}(%r11), %rcx
    movl $1, %edx
    leaq 48(%rsp), %r8
    th_api 6
    cmpl $1, %eax
    th_ensure e
    cmpl $0, 48(%rsp)
    th_ensure e
    th_ref
    cmpl $2, {mode}(%r11)
    je Lthread_done               /* exercise join without a live guest handle */
    movq {data}+0x30(%r11), %rcx
    movl $-1, %edx
    th_api 5                 /* Worker acknowledges on the second semaphore. */
    testl %eax, %eax
    th_ensure e
    th_ref
    cmpl $4, {mode}(%r11)
    jne 1f
    movl {data}+0x38(%r11), %ecx
    th_api 15                /* Must detect another lane's callback value. */
    ud2
1:
    cmpl $5, {mode}(%r11)
    jne Lthread_join
    movl {data}+0x38(%r11), %ecx
    th_api 15                /* Free while worker is live with a non-null value. */
    cmpl $1, %eax
    th_ensure e
    xorl %ecx, %ecx
    th_api 12
    th_ref
    cmpl {data}+0x38(%r11), %eax
    th_ensure e
    movl %eax, %ecx
    th_api 13
    testq %rax, %rax
    th_ensure e
    cmpl $0, %gs:0x68
    th_ensure e
    th_ref
    movl {data}+0x38(%r11), %ecx
    movl $0xdead, %edx
    th_api 14
    cmpl $1, %eax
    th_ensure e
    th_ref
    movq {data}(%r11), %rcx
    movl $1, %edx
    xorl %r8d, %r8d
    th_api 6
    cmpl $1, %eax
    th_ensure e
    movl $0x1234, %gs:0x68
    th_ref
Lthread_join:
    movq {data}+0x08(%r11), %rcx
    movl $-1, %edx
    th_api 5
    testl %eax, %eax
    th_ensure e
    th_ref
    movl {data}+0x2c(%r11), %r8d
    movl $0x1fffff, %ecx
    xorl %edx, %edx
    th_api 17                /* Completed ID no longer admits new handles. */
    testq %rax, %rax
    th_ensure e
    cmpl $87, %gs:0x68
    th_ensure e
    movl $0x1234, %gs:0x68
    th_tls
    cmpq $0x1144, (%r10)
    th_ensure e
    cmpq $0x2525, 8(%r10)
    th_ensure e
    cmpq %r10, {data}+0x20(%r11)
    th_ensure e
    cmpl $0x1234, %gs:0x68
    th_ensure e
    cmpl $1, {data}+0x28(%r11)
    th_ensure e
    th_ref
    movl {data}+0x38(%r11), %ecx
    th_api 13
    cmpq $0xdead, %rax        /* Worker SetValue did not change creator. */
    th_ensure e
    cmpl $0, %gs:0x68
    th_ensure e
    th_ref
    movl {data}+0x38(%r11), %ecx
    th_api 15
    cmpl $1, %eax
    th_ensure e
    th_api 10                  /* DLL detach completed before thread signaled. */
    cmpq $2, %rax
    th_ensure e
    th_ref
    movq {data}+0x08(%r11), %rcx
    th_api 8
    cmpl $1, %eax
    th_ensure e
    th_ref
    movq {data}(%r11), %rcx
    th_api 8
    cmpl $1, %eax
    th_ensure e
    th_ref
    movq {data}+0x30(%r11), %rcx
    th_api 8
    cmpl $1, %eax
    th_ensure e
Lthread_done:
    addq $56, %rsp
    movl $55, %eax
    retq
Lthread_worker:
    th_ref
    leaq {data}(%r11), %rax
    cmpq %rax, %rcx
    th_ensure e
    movq %rcx, 8(%rsp)
    movq %rcx, 32(%rsp)     /* Win64 home-space can be written. */
    movq %rsp, %rax
    andl $15, %eax
    cmpl $8, %eax
    th_ensure e
    cmpq %gs:0x08, %rsp
    th_ensure b
    cmpq %gs:0x10, %rsp
    th_ensure a
    movq %gs:0x30, %rax
    cmpq {data}+0x10(%r11), %rax
    th_ensure ne
    movq %gs:0x08, %rax
    cmpq {data}+0x18(%r11), %rax
    th_ensure ne
    cmpl $0, %gs:0x68
    th_ensure e
    th_tls
    cmpq $2, 8(%r10)
    th_ensure e
    cmpq %r10, {data}+0x20(%r11)
    th_ensure ne
    pushq %rbx
    subq $32, %rsp
    movq %gs:0x30, %rbx
    movl $0x8765, %gs:0x68
    movq {data}(%r11), %rcx
    movl $-1, %edx
    th_api 5
    testl %eax, %eax
    th_ensure e
    cmpq %gs:0x30, %rbx
    th_ensure e
    cmpl $0x8765, %gs:0x68
    th_ensure e
    th_api 1                  /* GetCurrentThreadId agrees with both TEB and parent. */
    th_ref
    cmpl {data}+0x2c(%r11), %eax
    th_ensure e
    cmpl %gs:0x48, %eax
    th_ensure e
    th_ref
    movl {data}+0x38(%r11), %ecx
    th_api 13                /* First read in a worker: NULL, ERROR_SUCCESS. */
    testq %rax, %rax
    th_ensure e
    cmpl $0, %gs:0x68
    th_ensure e
    cmpq %gs:0x30, %rbx
    th_ensure e
    movl $0x8765, %gs:0x68
    th_ref
    movl {data}+0x38(%r11), %ecx
    movl $0xbeef, %edx
    th_api 14
    cmpl $1, %eax
    th_ensure e
    cmpl $0x8765, %gs:0x68
    th_ensure e
    th_ref
    movl {data}+0x38(%r11), %ecx
    th_api 13
    cmpq $0xbeef, %rax
    th_ensure e
    cmpl $0, %gs:0x68
    th_ensure e
    movl $0x8765, %gs:0x68
    /* Reopen the current guest worker by ID using the observed full mask. */
    movl %gs:0x48, %r8d
    movl $0x1fffff, %ecx
    xorl %edx, %edx
    th_api 17
    testq %rax, %rax
    th_ensure ne
    th_ref
    cmpq {data}+0x08(%r11), %rax
    th_ensure ne
    movq %rax, %rcx
    th_api 8                 /* Closing this handle cannot close the creator's. */
    cmpl $1, %eax
    th_ensure e
    cmpl $0x8765, %gs:0x68
    th_ensure e
    th_api 10                  /* DLL thread attach followed its TLS callback. */
    cmpq $7, %rax
    th_ensure e
    th_ref
    movq {data}+0x30(%r11), %rcx
    movl $1, %edx
    xorl %r8d, %r8d
    th_api 6
    cmpl $1, %eax
    th_ensure e
    cmpq %gs:0x30, %rbx
    th_ensure e
    cmpl $0x8765, %gs:0x68
    th_ensure e
    th_ref
    cmpl $4, {mode}(%r11)
    jb Lthread_worker_return
    cmpl $5, {mode}(%r11)
    ja Lthread_worker_return
    movq {data}(%r11), %rcx
    movl $-1, %edx
    th_api 5
    testl %eax, %eax
    th_ensure e
    th_ref
    cmpl $5, {mode}(%r11)
    th_ensure e
    movl {data}+0x38(%r11), %ecx
    th_api 13                /* Reused index, live worker's old value is gone. */
    testq %rax, %rax
    th_ensure e
    cmpl $0, %gs:0x68
    th_ensure e
    movl $0x8765, %gs:0x68
Lthread_worker_return:
    movl $0xeda7babe, %eax
    addq $32, %rsp
    popq %rbx
    retq
Lthread_unexpected_fls:
    ud2
    .fill {capacity}-(.-Lthread_text), 1, 0xcc
