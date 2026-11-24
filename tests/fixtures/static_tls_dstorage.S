/* Owned Win64 fixture. All indirect transfers go through guest GuardCF. */
.const
.globl _static_tls_dstorage_fixture
.p2align 2
_static_tls_dstorage_fixture:
    .long Lds_entry-Lds_code
    .long Lds_unsupported-Lds_code
    .long Lds_open-Lds_code
    .long Lds_file_unsupported-Lds_code
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

.macro ds_open pth
    leaq \pth(%rip),%rdx
    leaq Lds_file_iid(%rip),%r8
    leaq 0x30(%rsp),%r9
    ds_method 4
.endm
.macro ds_file_method slot
    movq 0x30(%rsp),%rcx
    movq (%rcx),%rax
    movq (8*\slot)(%rax),%rax
    ds_dispatch
.endm
Lds_open:
    subq $0x48,%rsp
    leaq Lds_factory_iid(%rip),%rcx
    leaq 0x28(%rsp),%rdx
    ds_create
    testl %eax,%eax
    jne Lds_bad
    leaq Lds_path(%rip),%rdx
    leaq Lds_file_iid(%rip),%r8
    xorl %r9d,%r9d
    ds_method 4
    cmpl $0x80004003,%eax
    jne Lds_bad
    leaq Lds_path(%rip),%rdx
    leaq Lds_factory_iid(%rip),%r8
    leaq 0x30(%rsp),%r9
    movq $-1,0x30(%rsp)
    ds_method 4
    cmpl $0x80004002,%eax
    jne Lds_bad
    cmpq $0,0x30(%rsp)
    jne Lds_bad
    ds_open Lds_path
    cmpl $0x8007000f,%eax
    je Lds_unmounted
    testl %eax,%eax
    jne Lds_bad
    cmpq $0,0x30(%rsp)
    je Lds_bad
    ds_method 2
    testl %eax,%eax
    jne Lds_bad
    ds_file_method 1
    cmpl $2,%eax
    jne Lds_bad
    leaq Lds_unknown_iid(%rip),%rdx
    leaq 0x38(%rsp),%r8
    ds_file_method 0
    testl %eax,%eax
    jne Lds_bad
    movq 0x30(%rsp),%rax
    cmpq %rax,0x38(%rsp)
    jne Lds_bad
    ds_file_method 2
    cmpl $2,%eax
    jne Lds_bad
    ds_file_method 2
    cmpl $1,%eax
    jne Lds_bad
    ds_file_method 2
    testl %eax,%eax
    jne Lds_bad
    leaq Lds_factory_iid(%rip),%rcx
    leaq 0x28(%rsp),%rdx
    ds_create
    testl %eax,%eax
    jne Lds_bad
    ds_open Lds_missing
    cmpl $0x80070002,%eax
    jne Lds_bad
    ds_open Lds_dir
    cmpl $0x80070005,%eax
    jne Lds_bad
    ds_open Lds_link
    cmpl $0x80070005,%eax
    jne Lds_bad
    ds_open Lds_escape
    cmpl $0x8007007b,%eax
    jne Lds_bad
    ds_open Lds_outside
    cmpl $0x8007007b,%eax
    jne Lds_bad
    cmpq $0,0x30(%rsp)
    jne Lds_bad
    ds_method 2
    testl %eax,%eax
    jne Lds_bad
    movl $55,%eax
    addq $0x48,%rsp
    retq
Lds_unmounted:
    cmpq $0,0x30(%rsp)
    jne Lds_bad
    movl $56,%eax
    addq $0x48,%rsp
    retq
Lds_file_unsupported:
    subq $0x48,%rsp
    leaq Lds_factory_iid(%rip),%rcx
    leaq 0x28(%rsp),%rdx
    ds_create
    testl %eax,%eax
    jne Lds_bad
    ds_open Lds_path
    testl %eax,%eax
    jne Lds_bad
    ds_file_method 3
    jmp Lds_bad
Lds_file_iid:
    .long 0x43704f9f
    .short 0x27c6,0x4a9f
    .byte 0x88,0x15,0xd1,0x65,0x27,0x89,0x4d,0xf4
Lds_path:
    .short 71,58,92,111,119,110,101,100,46,100,97,116,0
Lds_missing:
    .short 71,58,92,110,111,112,101,0
Lds_dir:
    .short 71,58,92,0
Lds_link:
    .short 71,58,92,108,105,110,107,0
Lds_escape:
    .short 71,58,92,46,46,92,111,119,110,101,100,46,100,97,116,0
Lds_outside:
    .short 67,58,92,111,119,110,101,100,46,100,97,116,0
.fill {capacity}-(.-Lds_code),1,0xcc
