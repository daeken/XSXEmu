/* Original Win64 fixture; copied verbatim into the test-generated PEs. */
.const
.globl _static_tls_fixture
.p2align 4
_static_tls_fixture:
    .long Lend-Ltext, Lroot_cb-Ltext, Lroot_entry-Ltext
    .long Ldll_cb-Ltext, Ldll_main-Ltext, Lstep-Ltext
    .long Lsolo_cb-Ltext, Lsolo_entry-Ltext
    .long Lcfg_entry-Ltext, Lcfg_target-Ltext
    .long Lbridge_cb-Ltext, Lbridge_entry-Ltext
    .long Ltrace_entry-Ltext
Ltext:
.macro tls index
    leaq Ltext(%rip), %r11
    movl {index_delta}(%r11), %eax
    cmpl $\index, %eax
    jne Lbad
    movq %gs:0x58, %r10
    movq (%r10,%rax,8), %r10
    testq $31, %r10
    jnz Lbad
    leaq {cookie_delta}(%r11), %rax
    cmpq %rax, (%r10)       /* relocated pointer in template */
    jne Lbad
    movq (%rax), %rax
    testq %rax, %rax
    jz Lbad
    cmpq $0x12131415, %rax  /* loader must seed security cookie */
    je Lbad
.endm
.macro args
    leaq -{text_rva}(%r11), %rax
    cmpq %rcx, %rax
    jne Lbad
    testq %r8, %r8
    jnz Lbad
    movq %rcx, 8(%rsp)     /* exercise Win64 home space */
    movq %rdx, 32(%rsp)
.endm
.macro phase from, to
    cmpq $\from, 8(%r10)
    jne Lbad
    movq $\to, 8(%r10)
.endm
.macro step expected
    subq $40, %rsp
    movl $\expected, %ecx
    callq *{iat_delta}(%r11)
    addq $40, %rsp
.endm
Lroot_cb:
    tls 0
    args
    testl %edx, %edx
    je Lroot_detach
    cmpl $1, %edx
    jne Lbad
    phase 0, 1
    step 2
    retq
Lroot_detach:
    phase 2, 3
    step 4
    retq
Lroot_entry:
    tls 0
    phase 1, 2
    step 3
    movl $42, %eax
    retq
Ldll_cb:
    tls 1
    args
    testl %edx, %edx
    je Ldll_cb_detach
    cmpl $1, %edx
    jne Lbad
    phase 0, 1
    retq
Ldll_cb_detach:
    phase 5, 6
    retq
Ldll_main:
    tls 1
    args
    testl %edx, %edx
    je Ldll_main_detach
    cmpl $1, %edx
    jne Lbad
    phase 1, 2
    movl $1, %eax
    retq
Ldll_main_detach:
    phase 6, 7
    movl $1, %eax
    retq
Lstep:
    tls 1
    movl %ecx, %eax
    cmpq %rax, 8(%r10)
    jne Lbad
    incq 8(%r10)
    retq
Lsolo_cb:
    tls 0
    args
    testl %edx, %edx
    je Lsolo_detach
    cmpl $1, %edx
    jne Lbad
    phase 0, 1
    retq
Lsolo_detach:
    phase 2, 3
    retq
Lsolo_entry:
    tls 0
    phase 1, 2
    movl $43, %eax
    retq
Lcfg_entry:
    tls 0
    leaq Lcfg_target(%rip), %rcx
    cmpl $1, {mode_delta}(%r11)
    jne Lcfg_check
    decq %rcx
Lcfg_check:
    subq $40, %rsp
    callq *{check_delta}(%r11)
    movq %rcx, %rax
    cmpl $2, {mode_delta}(%r11)
    jne Lcfg_dispatch
    decq %rax
Lcfg_dispatch:
    cmpl $3, {mode_delta}(%r11)
    jne Lcfg_do_call
    movq $0, {dispatch_delta}(%r11) /* write must fault on a sealed slot */
Lcfg_do_call:
    callq *{dispatch_delta}(%r11)
    addq $40, %rsp
    retq
    nop                      /* callable, but not listed in the GFID table */
Lcfg_target:
    tls 0
    phase 1, 2
    movl $44, %eax
    retq
/* The TLS callback uses direct IAT calls; entry uses both CFG thunks. */
Lbridge_cb:
    tls 0
    args
    testl %edx, %edx
    je Lbridge_detach
    cmpl $1, %edx
    jne Lbad
    phase 0, 1
    subq $40, %rsp
    callq *{iat_delta}(%r11)
    testl %eax, %eax             /* new guest TEB is zero-initialized */
    jne Lbad
    movl $0x89345678, %gs:0x68   /* direct guest store, observed at entry */
    addq $40, %rsp
    retq
Lbridge_detach:
    phase 2, 3
    cmpl $0xfedcba98, %gs:0x68
    jne Lbad
    subq $40, %rsp
    callq *{iat_delta}(%r11)
    cmpl $0xfedcba98, %eax
    jne Lbad
    addq $40, %rsp
    retq

.set BRIDGE_REJECT_CHECK, 1
.set BRIDGE_REJECT_DISPATCH, 2
.set BRIDGE_SET_VALUE, 0xfedcba98
.macro bridge_cfg slot
    leaq Ltext(%rip), %r11
    movq {iat_delta}+\slot(%r11), %rcx
    cmpl $BRIDGE_REJECT_CHECK, {mode_delta}(%r11)
    jne 1f
    incq %rcx
1:
    callq *{check_delta}(%r11)   /* RCX is exact target, checked and preserved */
    movq %rcx, %rax
    cmpl $BRIDGE_REJECT_DISPATCH, {mode_delta}(%r11)
    jne 2f
    incq %rax
2:
    movl $BRIDGE_SET_VALUE, %ecx  /* first Win64 argument for SetLastError */
    callq *{dispatch_delta}(%r11)
.endm

Lbridge_entry:
    tls 0
    phase 1, 2
    pushq %rdi
    pushq %rsi
    pushq %r12
    subq $288, %rsp             /* home space, args, locals, Win64 XMM saves */
    .irp n,6,7,8,9,10,11,12,13,14,15
        movaps %xmm\n, 128+16*(\n-6)(%rsp)
        pcmpeqb %xmm\n, %xmm\n
    .endr
    movl $0x11111111, %edi
    movl $0x22222222, %esi
    movl $0x33333333, %r12d
    bridge_cfg 0                /* GetLastError reads the callback's store */
    cmpl $0x89345678, %eax
    jne Lbad
    bridge_cfg 8                /* SetLastError writes the guest TEB DWORD */
    cmpl $0xfedcba98, %gs:0x68
    jne Lbad
    /* Exact scalar results and arguments across the same boundary. */
    leaq Ltext(%rip), %r11
    callq *{iat_delta}+16(%r11)  /* GetProcessHeap */
    testq %rax, %rax
    je Lbad
    movq %rax, 48(%rsp)
    leaq Ltext(%rip), %r11
    movq %rax, %rcx
    movl $8, %edx               /* HEAP_ZERO_MEMORY */
    movq $32, %r8
    callq *{iat_delta}+24(%r11)  /* HeapAlloc */
    testq %rax, %rax
    je Lbad
    cmpq $0, (%rax)
    jne Lbad
    movq $0x12345678, (%rax)
    movq %rax, 56(%rsp)
    cmpl $0xfedcba98, %gs:0x68   /* heap success preserves last error */
    jne Lbad

    xorq %rcx, %rcx             /* wrong heap for HeapFree */
    xorl %edx, %edx
    movq 56(%rsp), %r8
    leaq Ltext(%rip), %r11
    callq *{iat_delta}+32(%r11)
    testl %eax, %eax
    jne Lbad
    cmpl $87, %gs:0x68          /* host provider failure updates guest TEB */
    jne Lbad
    movq 48(%rsp), %rcx
    xorl %edx, %edx
    movq 56(%rsp), %r8
    leaq Ltext(%rip), %r11
    callq *{iat_delta}+32(%r11)
    cmpl $1, %eax
    jne Lbad
    cmpl $87, %gs:0x68
    jne Lbad
    /* Model the observed LoadLibraryExW optional probe. No module handle or
     * dynamic symbol can escape even for a statically bound provider name. */
    leaq Lkernelbase(%rip), %rcx
    xorq %rdx, %rdx
    movl $0x800, %r8d
    leaq Ltext(%rip), %r11
    callq *{iat_delta}+40(%r11)
    testq %rax, %rax
    jne Lbad
    cmpl $126, %gs:0x68
    jne Lbad
    xorl %ecx, %ecx
    xorl %edx, %edx
    xorl %r8d, %r8d
    leaq Ltext(%rip), %r11
    callq *{iat_delta}+40(%r11)
    testq %rax, %rax
    jne Lbad
    cmpl $87, %gs:0x68
    jne Lbad

    leaq 88(%rsp), %rcx
    movl $4000, %edx
    leaq Ltext(%rip), %r11
    callq *{iat_delta}+48(%r11)
    cmpl $1, %eax
    jne Lbad
    cmpq $4000, 120(%rsp)       /* second arg was written to SpinCount */
    jne Lbad
    .irp slot,56,64,72
        leaq 88(%rsp), %rcx
        leaq Ltext(%rip), %r11
        callq *{iat_delta}+\slot(%r11)
    .endr

    /* Exercise the API-set IAT bridge through exact CFG dispatch. Check the
     * third argument is validated before initialization, and LastError
     * survives success after being set on failure. */
    movl $0x1234, %gs:0x68
    movq $-1, 120(%rsp)
    leaq 88(%rsp), %rcx
    movl $17, %edx
    movl $0x01000001, %r8d      /* NO_DEBUG_INFO plus an invalid flag */
    leaq Ltext(%rip), %r11
    movq {iat_delta}+152(%r11), %rax
    callq *{dispatch_delta}(%r11)
    testl %eax, %eax
    jne Lbad
    cmpl $87, %gs:0x68
    jne Lbad
    cmpq $-1, 120(%rsp)
    jne Lbad

    leaq 88(%rsp), %rcx
    movl $17, %edx
    movl $0x01000000, %r8d      /* CRITICAL_SECTION_NO_DEBUG_INFO */
    leaq Ltext(%rip), %r11
    movq {iat_delta}+152(%r11), %rax
    callq *{dispatch_delta}(%r11)
    cmpl $1, %eax
    jne Lbad
    cmpq $17, 120(%rsp)        /* Rosetta runs on multiprocessor hosts */
    jne Lbad
    cmpl $-1, 96(%rsp)         /* lock count in a newly initialized CS */
    jne Lbad
    cmpl $87, %gs:0x68
    jne Lbad
    .irp slot,56,56,64,64,72
        leaq 88(%rsp), %rcx
        leaq Ltext(%rip), %r11
        callq *{iat_delta}+\slot(%r11)
        cmpl $87, %gs:0x68
        jne Lbad
    .endr

    /* Win32 dynamic TLS slots are a provider table, not GS:[0x58]. */
    movq %gs:0x58, %rax
    movq %rax, 64(%rsp)
    movq (%rax), %rax
    movq %rax, 72(%rsp)
    leaq Ltext(%rip), %r11
    callq *{iat_delta}+80(%r11)  /* TlsAlloc */
    cmpl $-1, %eax
    je Lbad
    movl %eax, 80(%rsp)
    movl %eax, %ecx
    movabsq $0x123456789abcdef0, %rdx
    leaq Ltext(%rip), %r11
    callq *{iat_delta}+88(%r11)  /* TlsSetValue */
    cmpl $1, %eax
    jne Lbad
    movl 80(%rsp), %ecx
    leaq Ltext(%rip), %r11
    callq *{iat_delta}+96(%r11)  /* TlsGetValue */
    movabsq $0x123456789abcdef0, %rcx
    cmpq %rcx, %rax
    jne Lbad
    cmpl $0, %gs:0x68
    jne Lbad
    movl 80(%rsp), %ecx
    leaq Ltext(%rip), %r11
    callq *{iat_delta}+104(%r11) /* TlsFree */
    cmpl $1, %eax
    jne Lbad
    movq %gs:0x58, %rax
    cmpq 64(%rsp), %rax
    jne Lbad
    movq (%rax), %rax
    cmpq 72(%rsp), %rax
    jne Lbad
    /* Scalar stack arguments: one register and up to three stack slots
     * after adjusting for the adapter's extra LastError pointer. */
    movl $1252, %ecx
    xorl %edx, %edx
    leaq Lmb_input(%rip), %r8
    movl $-1, %r9d
    leaq 64(%rsp), %rax
    movq %rax, 32(%rsp)
    movq $2, 40(%rsp)
    leaq Ltext(%rip), %r11
    callq *{iat_delta}+112(%r11) /* MultiByteToWideChar */
    cmpl $2, %eax
    jne Lbad
    cmpl $0x20ac, 64(%rsp)       /* Euro + NUL */
    jne Lbad

    movl $1252, %ecx
    xorl %edx, %edx
    leaq Lwc_input(%rip), %r8
    movl $1, %r9d
    leaq 72(%rsp), %rax
    movq %rax, 32(%rsp)
    movq $1, 40(%rsp)
    leaq Lwc_default(%rip), %rax
    movq %rax, 48(%rsp)
    leaq 76(%rsp), %rax
    movl $0, (%rax)
    movq %rax, 56(%rsp)
    leaq Ltext(%rip), %r11
    movq {iat_delta}+120(%r11), %rax
    callq *{dispatch_delta}(%r11) /* WideCharToMultiByte via CFG */
    cmpl $1, %eax
    jne Lbad
    cmpb $33, 72(%rsp)
    jne Lbad
    cmpl $1, 76(%rsp)            /* used supplied default */
    jne Lbad

    leaq Ltext(%rip), %r11
    callq *{iat_delta}+128(%r11) /* GetCommandLineW initialized before entry */
    testq %rax, %rax
    je Lbad
    cmpw $34, (%rax)            /* quoted argv[0] */
    jne Lbad
    leaq Ltext(%rip), %r11
    callq *{iat_delta}+136(%r11) /* GetCommandLineA */
    testq %rax, %rax
    je Lbad
    cmpb $34, (%rax)
    jne Lbad
    bridge_cfg 8                /* restore detach sentinel */
    cmpq $0x11111111, %rdi
    jne Lbad
    cmpq $0x22222222, %rsi
    jne Lbad
    cmpq $0x33333333, %r12
    jne Lbad
    .irp n,6,7,8,9,10,11,12,13,14,15
        pcmpeqb %xmm0, %xmm0
        pcmpeqb %xmm\n, %xmm0
        pmovmskb %xmm0, %eax
        cmpl $0xffff, %eax
        jne Lbad
        movaps 128+16*(\n-6)(%rsp), %xmm\n
    .endr
    addq $288, %rsp
    popq %r12
    popq %rsi
    popq %rdi
    movl $45, %eax
    retq
/* Leave the TLS phase at 1: any erroneous detach runs into Lbad. */
Ltrace_entry:
    tls 0
    subq $40, %rsp
    cmpl $1, {mode_delta}(%r11)
    jne Ltrace_indirect
    callq *{iat_delta}(%r11)
    /* If the first trap returned, a different import would also be called. */
    leaq Ltext(%rip), %r11
    callq *{iat_delta}+8(%r11)
    ud2
Ltrace_indirect:
    movq {iat_delta}+8(%r11), %rcx
    cmpl $2, {mode_delta}(%r11)
    je Ltrace_check
    cmpl $5, {mode_delta}(%r11)
    jne Ltrace_dispatch
    incq %rcx
Ltrace_check:
    callq *{check_delta}(%r11)
    callq *%rcx
    ud2
Ltrace_dispatch:
    movq %rcx, %rax
    cmpl $4, {mode_delta}(%r11)
    jne Ltrace_dispatch_call
    incq %rax
Ltrace_dispatch_call:
    callq *{dispatch_delta}(%r11)
    ud2
Lmb_input:
    .byte 0x80, 0
.p2align 1
Lwc_input:
    .short 0x2603               /* snowman, not expressible in CP1252 */
Lwc_default:
    .byte 33
.p2align 1
Lkernelbase:
    .short 107,101,114,110,101,108,98,97,115,101,46,100,108,108,0
Lbad:
    ud2
Lend:
    .org Ltext + {capacity}, 0xcc
