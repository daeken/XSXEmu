/* Original guest fixture; all exports and COM methods use checked dispatch. */
.const
.globl _static_tls_xgameruntime_fixture
.p2align 2
_static_tls_xgameruntime_fixture:
    .long Lxgr_entry-Lxgr_text
Lxgr_text:
    retq
.set init, 48
.set query, 56
.set uninit, 64
.set error_report, 72
.set object_out, 80
.set object_a, 88
.set object_b, 96
.set queue_out, 104
.set queue_a, 112
.set stage, 120
.macro check value
    cmpl $\value, %eax
    jne Lxgr_bad
.endm
.macro got_export name, dst
    movq %rbx, %rcx
    leaq \name(%rip), %rdx
    leaq Lxgr_text(%rip), %r11
    callq *{iat_delta}+8(%r11)
    testq %rax, %rax
    jz Lxgr_bad
    movq %rax, \dst(%rsp)
.endm
.macro guarded
    leaq Lxgr_text(%rip), %r11
    callq *{dispatch_delta}(%r11)
.endm
.macro exp slot
    movq \slot(%rsp), %rax
    guarded
.endm
.macro meth slot
    movq (%rcx), %rax
    movq (\slot*8)(%rax), %rax
    guarded
.endm
.macro initialize flags
    movabsq $0x633600002712, %rcx
    movabsq $0x65f400001edd, %rdx
    movl $\flags, %r8d
    exp init
.endm
.macro query_impl class, iid
    movq $-1, object_out(%rsp)
    leaq \class(%rip), %rcx
    leaq \iid(%rip), %rdx
    leaq object_out(%rsp), %r8
    exp query
.endm
.macro check_null slot
    cmpq $0, \slot(%rsp)
    jne Lxgr_bad
.endm
.macro queue_create object, work, completion
    movq $-1, queue_out(%rsp)
    movq \object(%rsp), %rcx
    movl $\work, %edx
    movl $\completion, %r8d
    leaq queue_out(%rsp), %r9
    meth 12
.endm
Lxgr_entry:
    pushq %rbx
    subq $128, %rsp
    movl $1, stage(%rsp)
    leaq Lxgr_name(%rip), %rcx
    xorl %edx, %edx
    movl $0x800, %r8d
    leaq Lxgr_text(%rip), %r11
    callq *{iat_delta}(%r11)
    testq %rax, %rax
    jz Lxgr_no_dll
    movq %rax, %rbx
    got_export Lxgr_init, init
    got_export Lxgr_query, query
    got_export Lxgr_uninit, uninit
    got_export Lxgr_report, error_report
    movq %rbx, %rcx
    leaq Lxgr_old_init(%rip), %rdx
    leaq Lxgr_text(%rip), %r11
    callq *{iat_delta}+8(%r11)
    testq %rax, %rax
    jnz Lxgr_bad

    movl $2, stage(%rsp)
    query_impl Lxgr_guid, Lxgr_guid
    check 0x800401f0
    check_null object_out
    movl $1, %r9d                  /* unknown options must not be dereferenced */
    initialize 2
    check 0x80004001
    xorq %r9, %r9
    initialize 3
    check 0x80004001
    movabsq $0x0000000000002712, %rcx
    movabsq $0x65f400001edd, %rdx
    movl $2, %r8d
    xorq %r9, %r9
    exp init
    check 0x80004001
    xorq %r9, %r9
    initialize 2
    check 0
    xorq %r9, %r9
    initialize 2
    check 0x800704df

    movl $3, stage(%rsp)
    query_impl Lxgr_unknown, Lxgr_guid
    check 0x80040154
    check_null object_out
    query_impl Lxgr_guid, Lxgr_unknown
    check 0x80004002
    check_null object_out
    movl %eax, %ecx
    leaq Lxgr_message(%rip), %rdx
    exp error_report
    query_impl Lxgr_guid, Lxgr_guid
    check 0
    movq object_out(%rsp), %rcx
    testq %rcx, %rcx
    jz Lxgr_bad
    movq %rcx, object_a(%rsp)
    meth 29
    movq object_a(%rsp), %rcx
    meth 2
    check 0
    query_impl Lxgr_guid, Lxgr_guid  /* startup makes a fresh query for create */
    check 0
    movq object_out(%rsp), %rcx
    testq %rcx, %rcx
    jz Lxgr_bad
    cmpq object_a(%rsp), %rcx
    je Lxgr_bad
    movq %rcx, object_a(%rsp)
    movq object_a(%rsp), %rcx
    leaq Lxgr_iunknown(%rip), %rdx
    leaq object_out(%rsp), %r8
    meth 0
    check 0
    movq object_out(%rsp), %rax
    cmpq object_a(%rsp), %rax
    jne Lxgr_bad
    movq object_a(%rsp), %rcx
    leaq Lxgr_unknown(%rip), %rdx
    leaq object_out(%rsp), %r8
    meth 0
    check 0x80004002
    check_null object_out
    movq object_a(%rsp), %rcx
    meth 1
    check 3
    movq object_a(%rsp), %rcx
    meth 2
    check 2

    movl $4, stage(%rsp)
    queue_create object_a, 4, 1
    check 0x80070057
    check_null queue_out
    queue_create object_a, 1, 0
    check 0x80004001
    check_null queue_out
    queue_create object_a, 1, 1
    check 0
    movq queue_out(%rsp), %rax
    testq %rax, %rax
    jz Lxgr_bad
    movq %rax, queue_a(%rsp)
    movq object_a(%rsp), %rcx
    meth 2
    check 1
    movq object_a(%rsp), %rcx
    meth 2
    check 0
    queue_create object_a, 1, 1     /* stale this rejected without resurrecting it */
    check 0x80070006
    check_null queue_out

    movl $5, stage(%rsp)
    query_impl Lxgr_guid, Lxgr_guid
    check 0
    movq object_out(%rsp), %rcx
    cmpq object_a(%rsp), %rcx
    je Lxgr_bad
    movq %rcx, object_b(%rsp)
    leaq Lxgr_text(%rip), %r11
    cmpl $1, {mode_delta}(%r11)
    jne Lxgr_cleanup
    meth 15                        /* unsupported slot must stop, not return */
    jmp Lxgr_bad
Lxgr_cleanup:
    movq queue_a(%rsp), %rdx
    movabsq $0xfedcba9876543201, %r8 /* only R8B is defined for wait */
    xorq %r9, %r9
    leaq Lxgr_callback(%rip), %rax
    movq $0, 24(%rsp)
    movq %rax, 32(%rsp)             /* callee [rsp+0x28]; must reject callback */
    movq $0, 40(%rsp)
    meth 22
    check 0x80004001
    movq object_b(%rsp), %rcx
    movq queue_a(%rsp), %rdx
    movabsq $0xfedcba9876543201, %r8
    xorq %r9, %r9
    movq $-1, 24(%rsp)              /* poison adjacent offsets */
    movq $0, 32(%rsp)
    movq $-1, 40(%rsp)
    meth 22
    check 0
    movq object_b(%rsp), %rcx
    movq queue_a(%rsp), %rdx
    movl $1, %r8d
    xorl %r9d, %r9d
    meth 16
    testb %al, %al
    jnz Lxgr_bad
    cmpl $0, %gs:0x68
    jne Lxgr_bad
    movq object_b(%rsp), %rcx
    movq queue_a(%rsp), %rdx
    meth 17
    movq object_b(%rsp), %rcx
    movq queue_a(%rsp), %rdx
    movl $1, %r8d
    xorl %r9d, %r9d
    meth 16
    testb %al, %al
    jnz Lxgr_bad
    cmpl $6, %gs:0x68
    jne Lxgr_bad

    movl $6, stage(%rsp)
    queue_create object_b, 1, 1
    check 0
    movq queue_out(%rsp), %rax
    cmpq queue_a(%rsp), %rax
    je Lxgr_bad
    movq %rax, queue_a(%rsp)
    movq object_b(%rsp), %rcx
    movq %rax, %rdx
    movabsq $0xfedcba9876543200, %r8 /* also exercise wait=false */
    xorq %r9, %r9
    movq $0, 32(%rsp)
    meth 22
    check 0
    exp uninit                     /* terminate did not close this queue */
    query_impl Lxgr_guid, Lxgr_guid
    check 0x800401f0
    check_null object_out
    xorq %r9, %r9
    initialize 2
    check 0
    queue_create object_b, 1, 1
    check 0x80070006
    check_null queue_out
    movq object_b(%rsp), %rcx
    meth 2                         /* old COM references remain releasable */
    check 0
    query_impl Lxgr_guid, Lxgr_guid
    check 0
    movq object_out(%rsp), %rcx
    movq %rcx, object_b(%rsp)
    movq queue_a(%rsp), %rdx
    movl $1, %r8d
    xorl %r9d, %r9d
    meth 16
    testb %al, %al
    jnz Lxgr_bad
    cmpl $6, %gs:0x68
    jne Lxgr_bad
    movq object_b(%rsp), %rcx
    meth 2
    check 0
    exp uninit
    movq %rbx, %rcx
    leaq Lxgr_text(%rip), %r11
    callq *{iat_delta}+16(%r11)
    check 1
    movl $77, %eax
    jmp Lxgr_return
Lxgr_no_dll:
    movl $76, %eax
    jmp Lxgr_return
Lxgr_bad:
    movl stage(%rsp), %eax
    addl $90, %eax
Lxgr_return:
    addq $128, %rsp
    popq %rbx
    retq
Lxgr_callback:
    ud2
.p2align 2
Lxgr_guid:
    .byte 0xcb,0x7d,0x3b,0x07,0xcf,0x1f,0x30,0x40,0x94,0xbe,0xe3,0xc9,0xeb,0x62,0x34,0x28
Lxgr_iunknown:
    .byte 0,0,0,0,0,0,0,0,0xc0,0,0,0,0,0,0,0x46
Lxgr_unknown:
    .space 16, 0x55
Lxgr_name:
    .short 120,103,97,109,101,114,117,110,116,105,109,101,46,100,108,108,0
Lxgr_init: .asciz "InitializeApiImplEx2"
Lxgr_query: .asciz "QueryApiImpl"
Lxgr_uninit: .asciz "UninitializeApiImpl"
Lxgr_report: .asciz "XErrorReport"
Lxgr_old_init: .asciz "InitializeApiImpl"
Lxgr_message: .asciz "owned runtime fixture"
    .org Lxgr_text + {capacity}, 0xcc
