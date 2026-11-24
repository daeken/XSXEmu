/* Owned Win64 fixture. All indirect transfers go through guest GuardCF. */
.const
.globl _static_tls_dstorage_fixture
.p2align 2
_static_tls_dstorage_fixture:
    .long Lds_entry-Lds_code
    .long Lds_unsupported-Lds_code
Lds_code:
    retq
.macro ds_dispatch
    leaq Lds_code(%rip),%r11
    callq *{dispatch_delta}(%r11)
.endm
.macro ds_create
    leaq Lds_code(%rip),%r11
    movq {iat_delta}(%r11),%rax
    ds_dispatch
.endm
.macro ds_method slot
    movq 0x28(%rsp),%rcx
    movq (%rcx),%rax
    movq (8*\slot)(%rax),%rax
    ds_dispatch
.endm
Lds_entry:
    subq $0x48,%rsp
    leaq Lds_factory_iid(%rip),%rcx
    xorl %edx,%edx
    ds_create
    cmpl $0x80004003,%eax
    jne Lds_bad
    movq $-1,0x28(%rsp)
    xorl %ecx,%ecx
    leaq 0x28(%rsp),%rdx
    ds_create
    cmpl $0x80004003,%eax
    jne Lds_bad
    cmpq $0,0x28(%rsp)
    jne Lds_bad
    movq $-1,0x28(%rsp)
    leaq Lds_wrong_iid(%rip),%rcx
    leaq 0x28(%rsp),%rdx
    ds_create
    cmpl $0x80004002,%eax
    jne Lds_bad
    cmpq $0,0x28(%rsp)
    jne Lds_bad
    leaq Lds_factory_iid(%rip),%rcx
    leaq 0x28(%rsp),%rdx
    ds_create
    testl %eax,%eax
    jne Lds_bad
    cmpq $0,0x28(%rsp)
    je Lds_bad
    leaq Lds_factory_iid(%rip),%rcx
    leaq 0x30(%rsp),%rdx
    ds_create
    testl %eax,%eax
    jne Lds_bad
    movq 0x28(%rsp),%rax
    cmpq %rax,0x30(%rsp)
    jne Lds_bad
    ds_method 1
    cmpl $3,%eax
    jne Lds_bad
    leaq Lds_unknown_iid(%rip),%rdx
    leaq 0x30(%rsp),%r8
    ds_method 0
    testl %eax,%eax
    jne Lds_bad
    movq 0x28(%rsp),%rax
    cmpq %rax,0x30(%rsp)
    jne Lds_bad
    leaq Lds_wrong_iid(%rip),%rdx
    leaq 0x30(%rsp),%r8
    ds_method 0
    cmpl $0x80004002,%eax
    jne Lds_bad
    cmpq $0,0x30(%rsp)
    jne Lds_bad
    leaq Lds_factory_iid(%rip),%rdx
    xorl %r8d,%r8d
    ds_method 0
    cmpl $0x80004003,%eax
    jne Lds_bad
    movl $-1,%edx
    ds_method 8
    cmpl $0x80070057,%eax
    jne Lds_bad
    movl $0x02000000,%edx
    ds_method 8
    testl %eax,%eax
    jne Lds_bad
    movl $0x02000000,%edx
    ds_method 8
    testl %eax,%eax
    jne Lds_bad
    xorl %edx,%edx
    ds_method 8
    cmpl $0x80070057,%eax
    jne Lds_bad
    ds_method 2
    cmpl $3,%eax
    jne Lds_bad
    ds_method 2
    cmpl $2,%eax
    jne Lds_bad
    ds_method 2
    cmpl $1,%eax
    jne Lds_bad
    ds_method 2
    testl %eax,%eax
    jne Lds_bad
    leaq Lds_factory_iid(%rip),%rcx
    leaq 0x28(%rsp),%rdx
    ds_create
    testl %eax,%eax
    jne Lds_bad
    movl $0x02000000,%edx
    ds_method 8
    testl %eax,%eax
    jne Lds_bad
    ds_method 2
    testl %eax,%eax
    jne Lds_bad
    movl $54,%eax
    addq $0x48,%rsp
    retq
Lds_unsupported:
    subq $0x48,%rsp
    leaq Lds_factory_iid(%rip),%rcx
    leaq 0x28(%rsp),%rdx
    ds_create
    testl %eax,%eax
    jne Lds_bad
    ds_method 10
Lds_bad:
    movl $99,%eax
    addq $0x48,%rsp
    retq
.p2align 3
Lds_factory_iid:
    .long 0x62959d11
    .short 0xd45f, 0x4884
    .byte 0xa0,0xa3,0xf7,0x86,0x2e,0xa2,0x43,0xae
Lds_unknown_iid:
    .long 0
    .short 0,0
    .byte 0xc0,0,0,0,0,0,0,0x46
Lds_wrong_iid:
    .fill 16,1,0xff
.fill {capacity}-(.-Lds_code),1,0xcc
