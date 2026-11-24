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
    .long Ltrace_entry-Ltext, Ldisable_calls_dll_main-Ltext
    .long Lmodule_filename_dll_main-Ltext
    .long Lmodule_handle_dll_main-Ltext, Lmodule_handle_entry-Ltext
    .long Lprocessor_feature_entry-Ltext
    .long Lsync_entry-Ltext, Lsync_sleep-Ltext, Lsync_wake-Ltext
    .long Lregistry_entry-Ltext
    .long Lconfigure_d3d12_vm_entry-Ltext
    .long Lxmem_entry-Ltext
    .long Lprocessor_topology_entry-Ltext
    .long Lsystem_file_time_entry-Ltext
    .long Ltick_count64_entry-Ltext
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
Ldisable_calls_dll_main:
    leaq Ltext(%rip), %r11
    args                         /* RCX is the actual mapped self handle. */
    testl %edx, %edx
    je Ldisable_calls_detach
    cmpl $1, %edx
    jne Lbad
    cmpl $0, {mode_delta}(%r11)
    je 1f
    tls 1
    phase 1, 5                  /* Keep exercising TLS after the refusal. */
1:
    subq $40, %rsp
    movl $0x12345678, %gs:0x68
    callq *{iat_delta}(%r11)     /* DisableThreadLibraryCalls(self) */
    leaq Ltext(%rip), %r11
    cmpl $0, {mode_delta}(%r11)
    jne 2f
    cmpl $1, %eax
    jne Lbad
    cmpl $0x12345678, %gs:0x68
    jne Lbad
    jmp 3f
2:
    testl %eax, %eax
    jne Lbad
    cmpl $87, %gs:0x68           /* ERROR_INVALID_PARAMETER */
    jne Lbad
    tls 1
3:
    leaq 1-{text_rva}(%r11), %rcx
    callq *{iat_delta}(%r11)     /* Interior pointer is not a handle. */
    testl %eax, %eax
    jne Lbad
    cmpl $6, %gs:0x68            /* ERROR_INVALID_HANDLE */
    jne Lbad
    movl $0x12345678, %gs:0x68
    leaq Ltext(%rip), %r11
    xorl %ecx, %ecx
    callq *{iat_delta}(%r11)
    testl %eax, %eax
    jne Lbad
    cmpl $6, %gs:0x68
    jne Lbad
    addq $40, %rsp
    movl $1, %eax
    retq
Ldisable_calls_detach:
    cmpl $0, {mode_delta}(%r11)
    je 1f
    tls 1
    phase 6, 7
1:
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
.set FLS_FREE_WITH_VALUE, 3
.set FLS_LEAVE_PENDING, 4
.set FLS_CLEAR_ON_DETACH, 5
.set FLS_INDEX_DELTA, {mode_delta}+4  /* fixture scratch storage */
.set FLS_TEST_VALUE, 0x123456789abcdef0
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
    /* Resolve this callback's PC on the first process attach. */
    leaq Ltext(%rip), %r11
    leaq Lbridge_cb(%rip), %rcx
    leaq 32(%rsp), %rdx
    movq $-1, (%rdx)
    callq *{iat_delta}+272(%r11) /* RtlPcToFileHeader */
    leaq Ltext(%rip), %r11
    leaq -{text_rva}(%r11), %rcx
    cmpq %rcx, %rax
    jne Lbad
    cmpq %rcx, 32(%rsp)
    jne Lbad
    cmpl $0x89345678, %gs:0x68
    jne Lbad
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
    leaq Ltext(%rip), %r11
    cmpl $FLS_CLEAR_ON_DETACH, {mode_delta}(%r11)
    jne 1f
    /* Entry left a live callback/value pair. Ordinary guest detach must
     * run while the FLS slot and its original value are still live. */
    movl FLS_INDEX_DELTA(%r11), %ecx
    callq *{iat_delta}+184(%r11) /* FlsGetValue */
    movabsq $FLS_TEST_VALUE, %rcx
    cmpq %rcx, %rax
    jne Lbad
    movl $0xfedcba98, %gs:0x68
    leaq Ltext(%rip), %r11
    movl FLS_INDEX_DELTA(%r11), %ecx
    xorl %edx, %edx
    callq *{iat_delta}+176(%r11) /* FlsSetValue(NULL) */
    cmpl $1, %eax
    jne Lbad
    leaq Ltext(%rip), %r11
    movl FLS_INDEX_DELTA(%r11), %ecx
    callq *{iat_delta}+192(%r11) /* FlsFree now needs no callback */
    cmpl $1, %eax
    jne Lbad
    cmpl $0xfedcba98, %gs:0x68
    jne Lbad
1:
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

.macro fls_cfg slot
    leaq Ltext(%rip), %r11
    movq {iat_delta}+\slot(%r11), %rax
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
    /* A host bridge can be dispatched by CFG, but is not a guest image. */
    leaq Ltext(%rip), %r11
    movq {iat_delta}+272(%r11), %rax
    movq %rax, %rcx
    leaq 48(%rsp), %rdx
    movq $-1, (%rdx)
    callq *{dispatch_delta}(%r11) /* RtlPcToFileHeader */
    testq %rax, %rax
    jne Lbad
    cmpq $0, 48(%rsp)
    jne Lbad
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
    movb $0xab, 31(%rax)
    movq %rax, 56(%rsp)
    cmpl $0xfedcba98, %gs:0x68   /* heap success preserves last error */
    jne Lbad

    /* HeapSize returns a full-width SIZE_T, including its failure sentinel.
     * Neither success nor failure changes LastError. */
    movq 48(%rsp), %rcx
    xorl %edx, %edx
    movq 56(%rsp), %r8
    leaq Ltext(%rip), %r11
    callq *{iat_delta}+248(%r11) /* HeapSize via the heap API set */
    cmpq $32, %rax
    jne Lbad
    cmpl $0xfedcba98, %gs:0x68
    jne Lbad

    movl $0x87654321, %gs:0x68
    movq 48(%rsp), %rcx
    movl $8, %edx               /* HEAP_ZERO_MEMORY is invalid for HeapSize */
    movq 56(%rsp), %r8
    leaq Ltext(%rip), %r11
    callq *{iat_delta}+248(%r11)
    cmpq $-1, %rax
    jne Lbad
    cmpl $0x87654321, %gs:0x68
    jne Lbad

    /* Grow via exact CFG dispatch with a Win64 fourth argument (R9).
     * Use the full pointer returned in RAX for subsequent heap operations. */
    movq 48(%rsp), %rcx
    movl $8, %edx               /* HEAP_ZERO_MEMORY */
    movq 56(%rsp), %r8
    movq $64, %r9
    leaq Ltext(%rip), %r11
    movq {iat_delta}+256(%r11), %rax
    callq *{dispatch_delta}(%r11) /* HeapReAlloc via the heap API set */
    testq %rax, %rax
    je Lbad
    cmpq $0x12345678, (%rax)
    jne Lbad
    cmpb $0xab, 31(%rax)
    jne Lbad
    .irp off,32,40,48,56
        cmpq $0, \off(%rax)
        jne Lbad
    .endr
    movq %rax, 56(%rsp)
    cmpl $0x87654321, %gs:0x68
    jne Lbad

    /* A grow with IN_PLACE_ONLY fails deterministically without allocating.
     * The low 32 bits are zero to catch a truncated SIZE_T argument. */
    movq 48(%rsp), %rcx
    movl $0x10, %edx            /* HEAP_REALLOC_IN_PLACE_ONLY */
    movq 56(%rsp), %r8
    movabsq $0x100000000, %r9
    leaq Ltext(%rip), %r11
    movq {iat_delta}+256(%r11), %rax
    callq *{dispatch_delta}(%r11)
    testq %rax, %rax
    jne Lbad
    cmpl $0x87654321, %gs:0x68
    jne Lbad

    /* Failure leaves the original allocation live, sized and intact. */
    movq 48(%rsp), %rcx
    xorl %edx, %edx
    movq 56(%rsp), %r8
    leaq Ltext(%rip), %r11
    callq *{iat_delta}+248(%r11) /* HeapSize */
    cmpq $64, %rax
    jne Lbad
    movq 56(%rsp), %rax
    cmpq $0x12345678, (%rax)
    jne Lbad
    cmpb $0xab, 31(%rax)
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

    /* InitializeSListHead takes one pointer to a 16-byte aligned header.
     * Check a misaligned call leaves storage alone, then initialize the
     * nonzero header via the exact API-set IAT target and CFG dispatch. */
    movq $-1, 88(%rsp)          /* canary before the header */
    movq $-1, 96(%rsp)
    movq $-1, 104(%rsp)
    movq $-1, 112(%rsp)        /* canary after the header */
    movl $0x1234, %gs:0x68
    leaq 104(%rsp), %rcx
    leaq Ltext(%rip), %r11
    movq {iat_delta}+208(%r11), %rax
    callq *{dispatch_delta}(%r11)
    cmpl $87, %gs:0x68
    jne Lbad
    cmpq $-1, 96(%rsp)
    jne Lbad
    cmpq $-1, 104(%rsp)
    jne Lbad
    cmpq $-1, 112(%rsp)
    jne Lbad

    movl $0x1234, %gs:0x68
    leaq 96(%rsp), %rcx
    leaq Ltext(%rip), %r11
    movq {iat_delta}+208(%r11), %rax
    callq *{dispatch_delta}(%r11)
    cmpl $0x1234, %gs:0x68
    jne Lbad
    cmpq $0, 96(%rsp)
    jne Lbad
    cmpq $0, 104(%rsp)
    jne Lbad
    cmpq $-1, 88(%rsp)
    jne Lbad
    cmpq $-1, 112(%rsp)
    jne Lbad

    /* Opaque 64-bit PVOID round trips through the util API-set IAT and
     * exact CFG dispatch. Null is encoded, not passed through unchanged.
     * Neither operation may alter the guest LastError DWORD. */
    .irp value,0,0x123456789abcdef0
        movl $0x87654321, %gs:0x68
        movabsq $\value, %rcx
        leaq Ltext(%rip), %r11
        movq {iat_delta}+224(%r11), %rax
        callq *{dispatch_delta}(%r11) /* EncodePointer */
        cmpl $0x87654321, %gs:0x68
        jne Lbad
        .if \value == 0
            testq %rax, %rax
            je Lbad
        .endif

        movl $0xabcdef01, %gs:0x68
        movq %rax, %rcx
        leaq Ltext(%rip), %r11
        movq {iat_delta}+232(%r11), %rax
        callq *{dispatch_delta}(%r11) /* DecodePointer */
        cmpl $0xabcdef01, %gs:0x68
        jne Lbad
        movabsq $\value, %rcx
        cmpq %rcx, %rax
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
    /* Non-null FLS callback registers but never runs during alloc/get/set.
     * Lbad would fault if the provider accidentally invoked the callback. */
    movl $1234, %gs:0x68
    leaq Lbad(%rip), %rcx
    fls_cfg 168                 /* FlsAlloc */
    cmpl $-1, %eax
    je Lbad
    cmpl $1234, %gs:0x68
    jne Lbad
    movl %eax, 84(%rsp)
    movl %eax, %ecx
    movabsq $FLS_TEST_VALUE, %rdx
    fls_cfg 176                 /* FlsSetValue */
    cmpl $1, %eax
    jne Lbad
    cmpl $1234, %gs:0x68
    jne Lbad
    movl 84(%rsp), %ecx
    fls_cfg 184                 /* FlsGetValue */
    movabsq $FLS_TEST_VALUE, %rcx
    cmpq %rcx, %rax
    jne Lbad
    cmpl $0, %gs:0x68
    jne Lbad
    leaq Ltext(%rip), %r11
    cmpl $FLS_FREE_WITH_VALUE, {mode_delta}(%r11)
    jne 1f
    movl 84(%rsp), %ecx
    fls_cfg 192                 /* Must stop before invoking callback */
    ud2
1:
    cmpl $FLS_LEAVE_PENDING, {mode_delta}(%r11)
    je 2f                       /* Leave callback pending for teardown */
    cmpl $FLS_CLEAR_ON_DETACH, {mode_delta}(%r11)
    jne 3f
    movl 84(%rsp), %eax
    movl %eax, FLS_INDEX_DELTA(%r11)
    jmp 2f                       /* Leave callback live for guest detach */
3:
    movl 84(%rsp), %ecx
    xorl %edx, %edx
    fls_cfg 176                 /* Clearing the value needs no callback */
    cmpl $1, %eax
    jne Lbad
    movl 84(%rsp), %ecx
    fls_cfg 192
    cmpl $1, %eax
    jne Lbad
    movl 84(%rsp), %ecx
    fls_cfg 184                 /* Freed index fails and sets LastError */
    testq %rax, %rax
    jne Lbad
    cmpl $87, %gs:0x68
    jne Lbad
2:
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
/* A path slot contains full length, truncation capacity, then UTF-16 units. */
.macro check_module_path offset, truncated=0
    leaq Ltext(%rip), %r11
    leaq {module_path_buffer_delta}(%r11), %rdx
    .if \truncated
        movl {module_paths_delta}+\offset+4(%r11), %r8d
    .else
        movl {module_paths_delta}+\offset(%r11), %r8d
        incl %r8d
    .endif
    movw $0xffff, -2(%rdx,%r8,2) /* NUL must be written, not already present. */
    movw $0xffff, (%rdx,%r8,2)
    movl $0x12345678, %gs:0x68
    callq *{iat_delta}(%r11)
    leaq Ltext(%rip), %r11
    leaq {module_paths_delta}+\offset(%r11), %r10
    .if \truncated
        movl 4(%r10), %r8d
        cmpl %r8d, %eax
        jne Lbad
        decl %r8d
        cmpl $122, %gs:0x68       /* ERROR_INSUFFICIENT_BUFFER */
    .else
        movl (%r10), %r8d
        cmpl %r8d, %eax
        jne Lbad
        cmpl $0x12345678, %gs:0x68
    .endif
    jne Lbad
    leaq {module_path_buffer_delta}(%r11), %rdx
    cmpw $0, (%rdx,%r8,2)
    jne Lbad
    cmpw $0xffff, 2(%rdx,%r8,2)
    jne Lbad
1:
    decl %r8d
    movw 8(%r10,%r8,2), %ax
    cmpw %ax, (%rdx,%r8,2)
    jne Lbad
    testl %r8d, %r8d
    jnz 1b
.endm
Lmodule_filename_dll_main:
    leaq Ltext(%rip), %r11
    args                          /* RCX is the actual mapped self handle. */
    testl %edx, %edx
    je Lmodule_filename_detach
    cmpl $1, %edx
    jne Lbad
    subq $40, %rsp
    check_module_path {module_path_slot}
    xorl %ecx, %ecx
    check_module_path 0
    xorl %ecx, %ecx
    check_module_path 0, 1
    leaq 1-{text_rva}(%r11), %rcx  /* Interior pointer is not a handle. */
    movl $1, %r8d
    movw $0xffff, (%rdx)
    callq *{iat_delta}(%r11)
    testl %eax, %eax
    jne Lbad
    cmpl $6, %gs:0x68             /* ERROR_INVALID_HANDLE */
    jne Lbad
    leaq Ltext(%rip), %r11
    cmpw $0xffff, {module_path_buffer_delta}(%r11)
    jne Lbad
    addq $40, %rsp
Lmodule_filename_detach:
    movl $1, %eax
    retq
Lmodule_handle_dll_main:
    leaq Ltext(%rip), %r11
    args
    testl %edx, %edx
    je Lmodule_handle_detach
    cmpl $1, %edx
    jne Lbad
    subq $40, %rsp
    movl $0x12345678, %gs:0x68
    leaq {module_paths_delta}(%r11), %rcx
    callq *{iat_delta}(%r11)
    leaq Ltext(%rip), %r11
    leaq -{text_rva}(%r11), %rdx
    cmpq %rdx, %rax
    jne Lbad
    cmpl $0x12345678, %gs:0x68
    jne Lbad
    leaq {module_paths_delta}+64(%r11), %rcx
    callq *{iat_delta}(%r11)
    testq %rax, %rax
    jne Lbad
    cmpl $126, %gs:0x68          /* ERROR_MOD_NOT_FOUND */
    jne Lbad
    addq $40, %rsp
Lmodule_handle_detach:
    movl $1, %eax
    retq
Lmodule_handle_entry:
    tls 0
    phase 1, 2
    subq $40, %rsp
    movl $0x87654321, %gs:0x68
    xorl %ecx, %ecx
    callq *{iat_delta}+16(%r11)
    leaq Ltext(%rip), %r11
    leaq -{text_rva}(%r11), %rdx
    cmpq %rdx, %rax
    jne Lbad
    cmpl $0x87654321, %gs:0x68
    jne Lbad
    addq $40, %rsp
    movl $43, %eax
    retq
Lprocessor_feature_entry:
    tls 0
    phase 1, 2
    subq $40, %rsp
    movl $0x87654321, %gs:0x68
    movabsq $0x876543210000000a, %rcx  /* PF_XMMI64_INSTRUCTIONS_AVAILABLE; high bits ignored. */
    callq *{iat_delta}(%r11)
    cmpl $1, %eax
    jne Lbad
    cmpl $0x87654321, %gs:0x68
    jne Lbad
    leaq Ltext(%rip), %r11
    movl $23, %ecx                    /* PF_FASTFAIL_AVAILABLE; don't advertise INT 29h. */
    callq *{iat_delta}(%r11)
    testl %eax, %eax
    jne Lbad
    cmpl $0x87654321, %gs:0x68
    jne Lbad
    addq $40, %rsp
    movl $43, %eax
    retq
Ltick_count64_entry:
    tls 0
    phase 1, 2
    subq $40, %rsp
    movl $0x87654321, %gs:0x68
    callq *{iat_delta}(%r11)
    cmpl $0x87654321, %gs:0x68
    jne Lbad
    leaq Ltext(%rip), %r11
    movq %rax, %rcx
    subq {mode_delta}(%r11), %rcx     /* Host sample taken before launch. */
    cmpq $60000, %rcx                /* Unsigned: also rejects values below the sample. */
    ja Lbad
    movq %rax, 32(%rsp)
    movl $0x12345678, %gs:0x68
    leaq Ltext(%rip), %r11
    callq *{iat_delta}(%r11)
    cmpl $0x12345678, %gs:0x68
    jne Lbad
    cmpq 32(%rsp), %rax
    jb Lbad
    addq $40, %rsp
    movl $51, %eax
    retq
Lsystem_file_time_entry:
    tls 0
    phase 1, 2
    subq $56, %rsp
    movq $-1, 36(%rsp)                /* FILETIME needs DWORD, not qword, alignment. */
    movl $0x12345678, 32(%rsp)
    movl $0x76543210, 44(%rsp)
    movl $0x87654321, %gs:0x68
    leaq 36(%rsp), %rcx
    callq *{iat_delta}(%r11)
    cmpl $0x87654321, %gs:0x68
    jne Lbad
    cmpl $0x12345678, 32(%rsp)
    jne Lbad
    cmpl $0x76543210, 44(%rsp)
    jne Lbad
    movabsq $116444736000000000, %rdx  /* Unix epoch in FILETIME ticks. */
    movq 36(%rsp), %rax
    cmpq %rdx, %rax
    jb Lbad
    testq %rax, %rax                  /* Reject untouched all-ones and invalid high words. */
    js Lbad
    addq $56, %rsp
    movl $50, %eax
    retq
Lprocessor_topology_entry:
    tls 0
    phase 1, 2
    subq $2088, %rsp                  /* Home space, length, up to 64 records. */
    movq $0, 32(%rsp)
    xorl %ecx, %ecx
    leaq 32(%rsp), %rdx
    callq *{iat_delta}(%r11)
    testl %eax, %eax
    jne Lbad
    cmpl $122, %gs:0x68
    jne Lbad
    movl 32(%rsp), %eax
    testl %eax, %eax
    jz Lbad
    cmpl $2048, %eax
    ja Lbad
    testl $31, %eax
    jne Lbad
    movl %eax, 36(%rsp)              /* Length must be a DWORD, not a size_t. */
    movl $0x87654321, %gs:0x68
    leaq 40(%rsp), %rcx
    leaq 32(%rsp), %rdx
    leaq Ltext(%rip), %r11
    callq *{iat_delta}(%r11)
    cmpl $1, %eax
    jne Lbad
    cmpl $0x87654321, %gs:0x68
    jne Lbad
    movl 32(%rsp), %eax
    cmpl 36(%rsp), %eax
    jne Lbad
    leaq 40(%rsp), %rcx
    leaq (%rcx,%rax), %rdx
    movl $1, %r8d
Lprocessor_topology_next:
    cmpq %r8, (%rcx)                 /* Contiguous, distinct single-bit masks. */
    jne Lbad
    cmpq $0, 8(%rcx)                 /* RelationProcessorCore and padding. */
    jne Lbad
    cmpq $0, 16(%rcx)                /* No SMT flag; fully zeroed union. */
    jne Lbad
    cmpq $0, 24(%rcx)
    jne Lbad
    addq $32, %rcx
    shlq $1, %r8
    cmpq %rdx, %rcx
    jb Lprocessor_topology_next
    addq $2088, %rsp
    movl $49, %eax
    retq
/* Fixture only: the owned caller supplies an initialized condition variable
 * and an exclusively held critical section. There are no possible peers, so
 * releasing and reacquiring on a zero-timeout poll has no observable effect. */
Lsync_sleep:
    testl %r9d, %r9d
    jne Lbad                             /* A blocking wait is unsupported. */
    movl $1460, %gs:0x68                 /* ERROR_TIMEOUT */
    xorl %eax, %eax
    retq
Lsync_wake:
    retq                                 /* No waiter can coexist. */
Lsync_entry:
    tls 0
    phase 1, 2
    pushq %rbx
    subq $80, %rsp
    xorl %ecx, %ecx
    callq *{iat_delta}(%r11)
    leaq Ltext(%rip), %r11
    leaq -{text_rva}(%r11), %rcx
    cmpq %rcx, %rax
    jne Lbad
    cmpw $0x5a4d, (%rax)
    jne Lbad
    movslq 0x3c(%rax), %rcx
    cmpl $0x4550, (%rax,%rcx)
    jne Lbad
    leaq {module_paths_delta}(%r11), %rcx
    callq *{iat_delta}(%r11)
    testq %rax, %rax
    jne 2f
    leaq Ltext(%rip), %r11
    cmpl $3, {mode_delta}(%r11)
    jne Lbad
    cmpl $126, %gs:0x68                  /* ERROR_MOD_NOT_FOUND */
    jne Lbad
    movl $48, %eax
    jmp Lsync_exit
2:
    movq %rax, %rbx
    cmpw $0x5a4d, (%rax)
    jne Lbad
    leaq Ltext(%rip), %r11
    movq $0, 32(%rsp)                    /* CONDITION_VARIABLE_INIT */
    leaq 40(%rsp), %rcx                   /* CRITICAL_SECTION (40 bytes) */
    xorl %edx, %edx
    callq *{iat_delta}+24(%r11)          /* InitializeCriticalSectionAndSpinCount */
    testl %eax, %eax
    je Lbad
    leaq Ltext(%rip), %r11
    leaq 40(%rsp), %rcx
    callq *{iat_delta}+32(%r11)          /* EnterCriticalSection */
    leaq Ltext(%rip), %r11
    movq %rbx, %rcx
    leaq Lsync_wake_name(%rip), %rdx
    movl $0x23456789, %gs:0x68
    callq *{iat_delta}+8(%r11)
    leaq Ltext(%rip), %r11
    movl {module_paths_delta}+0x84(%r11), %ecx
    addq %rbx, %rcx
    cmpq %rcx, %rax
    jne Lbad
    cmpl $0x23456789, %gs:0x68
    jne Lbad
    leaq Ltext(%rip), %r11
    leaq 32(%rsp), %rcx
    callq *{dispatch_delta}(%r11)
    cmpl $0x23456789, %gs:0x68
    jne Lbad
    leaq Ltext(%rip), %r11
    movq %rbx, %rcx
    leaq Lsync_sleep_name(%rip), %rdx
    callq *{iat_delta}+8(%r11)
    leaq Ltext(%rip), %r11
    cmpl $1, {mode_delta}(%r11)
    je Lsync_refused
    movl {module_paths_delta}+0x80(%r11), %ecx
    addq %rbx, %rcx
    cmpq %rcx, %rax
    jne Lbad
    cmpl $0x23456789, %gs:0x68
    jne Lbad
    leaq 32(%rsp), %rcx
    leaq 40(%rsp), %rdx
    xorl %r9d, %r9d                      /* Poll except in mode 2. */
    cmpl $2, {mode_delta}(%r11)
    sete %r9b
    cmpl $4, {mode_delta}(%r11)
    sete %r10b
    orb %r10b, %r9b
    callq *{dispatch_delta}(%r11)
    testl %eax, %eax
    jne Lbad
    cmpl $1460, %gs:0x68
    jne Lbad
    jmp Lsync_return
Lsync_refused:
    testq %rax, %rax
    jne Lbad
    cmpl $127, %gs:0x68                  /* ERROR_PROC_NOT_FOUND */
    jne Lbad
Lsync_return:
    movl %gs:0x68, %ebx
    leaq Ltext(%rip), %r11
    leaq 40(%rsp), %rcx
    callq *{iat_delta}+40(%r11)          /* LeaveCriticalSection */
    leaq Ltext(%rip), %r11
    leaq 40(%rsp), %rcx
    callq *{iat_delta}+48(%r11)          /* DeleteCriticalSection */
    cmpl %ebx, %gs:0x68
    jne Lbad
    xorl %eax, %eax
    leaq Ltext(%rip), %r11
    cmpl $1, {mode_delta}(%r11)
    sete %al
    addl $46, %eax
Lsync_exit:
    addq $80, %rsp
    popq %rbx
    retq
Lsync_sleep_name:
    .asciz "SleepConditionVariableCS"
Lsync_wake_name:
    .asciz "WakeAllConditionVariable"
Lregistry_entry:
    tls 0
    phase 1, 2
    subq $40, %rsp
    movl $0x1234, %gs:0x68
    movq $0, 32(%rsp)
    leaq 32(%rsp), %r8
    leaq Lregistry_subkey(%rip), %rdx
    movq $-2147483646, %rcx             /* sign-extended HKEY_LOCAL_MACHINE */
    callq *{iat_delta}(%r11)            /* RegOpenKeyW */
    testl %eax, %eax
    jz Lbad                            /* must take the optional-key fallback */
    cmpl $2, %eax                      /* ERROR_FILE_NOT_FOUND */
    jne Lbad
    cmpq $0, 32(%rsp)                   /* no handle returned */
    jne Lbad
    cmpl $0x1234, %gs:0x68               /* LSTATUS, not LastError */
    jne Lbad
    movl $41, %eax
    addq $40, %rsp
    retq
Lregistry_subkey:
    .short 'O', 'w', 'n', 'e', 'd', 0
/* Original one-pointer, 32-byte Win64 caller probe. */
.macro configure_d3d12_vm expected
    leaq Ltext(%rip), %r11
    movq $-1, %rdx                    /* not arguments */
    movq $-2, %r8
    movq $-3, %r9
    callq *{iat_delta}(%r11)
    cmpl $\expected, %eax
    jne Lbad
    cmpl $0xbeef, %gs:0x68             /* guest GS restored, LastError unchanged */
    jne Lbad
.endm
Lconfigure_d3d12_vm_entry:
    tls 0
    phase 1, 2
    subq $72, %rsp                    /* 32-byte home + 32-byte input */
    movl $0xbeef, %gs:0x68
    xorps %xmm0, %xmm0
    movups %xmm0, 32(%rsp)
    movups %xmm0, 48(%rsp)
    movl $3, 36(%rsp)
    leaq 32(%rsp), %rcx
    configure_d3d12_vm 0
    cmpl $3, 36(%rsp)
    jne Lbad
    movl $4, 36(%rsp)
    leaq 32(%rsp), %rcx
    configure_d3d12_vm 0
    movb $1, 63(%rsp)                 /* unexpected last byte */
    leaq 32(%rsp), %rcx
    configure_d3d12_vm 0x80004001
    movb $0, 63(%rsp)
    movl $5, 36(%rsp)
    leaq 32(%rsp), %rcx
    configure_d3d12_vm 0x80004001
    xorl %ecx, %ecx
    configure_d3d12_vm 0x80070057
    movl $44, %eax
    addq $72, %rsp
    retq
/* Original ABI exercise: touches only the ends of the RW mappings. */
.macro xmem attr, prot, flags=0x20402000
    xorl %ecx, %ecx
    movq %rbx, %rdx
    movl $\flags, %r8d
    movl $\attr, %r9d
    movl $\prot, 32(%rsp)
    movl $0xfeedface, 36(%rsp)
    leaq Ltext(%rip), %r11
    callq *{iat_delta}(%r11)
.endm
.macro xmem_cpu size, attr, prot, error, flags=0x20003000, mask=0x1fffff
    movl $\size, %ebx
    xmem \attr, \prot, \flags
    testq %rax, %rax
    jz Lbad
    testl $\mask, %eax
    jnz Lbad
    cmpl $\error, %gs:0x68
    jne Lbad
    leaq -1(%rax,%rbx), %rdx
    cmpb $0, (%rax)
    jne Lbad
    cmpb $0, (%rdx)
    jne Lbad
    movb $0x55, (%rax)
    movb $0xaa, (%rdx)
    cmpb $0x55, (%rax)
    jne Lbad
    cmpb $0xaa, (%rdx)
    jne Lbad
    xmem \attr, \prot, \flags
    testq %rax, %rax
    jnz Lbad
    cmpl $8, %gs:0x68
    jne Lbad
.endm
Lxmem_entry:
    tls 0
    phase 1, 2
    pushq %rbx
    subq $48, %rsp
    leaq Ltext(%rip), %r11
    movl {mode_delta}(%r11), %ebx
    shlq $30, %rbx
    movl $0xbeef, %gs:0x68
    xmem 0x21, 4
    testq %rax, %rax
    jz Lbad
    testl $0xffff, %eax
    jnz Lbad
    movq %rax, 40(%rsp)
    xmem 3, 0x801
    testq %rax, %rax
    jz Lbad
    testl $0xffff, %eax
    jnz Lbad
    subq 40(%rsp), %rax
    jns 1f
    negq %rax
1:  cmpq %rbx, %rax
    jb Lbad
    cmpl $0xbeef, %gs:0x68
    jne Lbad
    xmem 0x21, 4
    testq %rax, %rax
    jnz Lbad
    cmpl $8, %gs:0x68
    jne Lbad
    xmem 0x183, 0x22004, 0x20003000
    testq %rax, %rax
    jnz Lbad
    cmpl $50, %gs:0x68
    jne Lbad
    xmem_cpu 0x49400000, 0x183, 0x22004, 50
    xmem_cpu 0x89700000, 0x283, 0x2404, 8
    xmem_cpu 0x23300000, 0x183, 0x22004, 8
    xmem_cpu 0x25400000, 0x183, 0x22004, 8
    xmem_cpu 0x1400000, 0x181, 4, 8, 0x20403000, 0xffff
    /* Unobserved pair swapping size but keeping second flags still fails. */
    movl $0x49400000, %ebx
    xmem 0x283, 0x2404, 0x20003000
    testq %rax, %rax
    jnz Lbad
    cmpl $50, %gs:0x68
    jne Lbad
    movl $45, %eax
    addq $48, %rsp
    popq %rbx
    retq
Lend:
    .org Ltext + {capacity}, 0xcc
