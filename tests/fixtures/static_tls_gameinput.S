/* Owned GameInput v0 probe. All interface calls use normal GuardCF dispatch. */
.const
.globl _static_tls_gameinput_fixture
.p2align 2
_static_tls_gameinput_fixture:
    .long Lgi_entry-Lgi_code
    .long Lgi_unsupported-Lgi_code
Lgi_code:
    retq
.macro gi_create
    leaq Lgi_code(%rip),%r11
    movq {iat_delta}(%r11),%rax
    callq *{dispatch_delta}(%r11)
.endm
.macro gi_method slot
    movq 0x50(%rsp),%rcx
    movq (%rcx),%rax
    movq (8*\slot)(%rax),%rax
    leaq Lgi_code(%rip),%r11
    callq *{dispatch_delta}(%r11)
.endm
Lgi_entry:
    subq $0x78,%rsp
    movl $0x324567ab,%gs:0x68
    xorl %ecx,%ecx
    gi_create
    cmpl $0x80004003,%eax
    jne Lgi_bad
    leaq 0x50(%rsp),%rcx
    gi_create
    testl %eax,%eax
    jne Lgi_bad
    cmpq $0,0x50(%rsp)
    je Lgi_bad
    gi_method 1
    cmpl $2,%eax
    jne Lgi_bad
    gi_method 2
    cmpl $1,%eax
    jne Lgi_bad
    leaq Lgi_iid(%rip),%rdx
    leaq 0x58(%rsp),%r8
    gi_method 0
    testl %eax,%eax
    jne Lgi_bad
    movq 0x50(%rsp),%rax
    cmpq %rax,0x58(%rsp)
    jne Lgi_bad
    gi_method 2
    cmpl $1,%eax
    jne Lgi_bad
    leaq Lgi_bad_iid(%rip),%rdx
    leaq 0x58(%rsp),%r8
    gi_method 0
    cmpl $0x80004002,%eax
    jne Lgi_bad
    cmpq $0,0x58(%rsp)
    jne Lgi_bad
    gi_method 3
    movq %rax,0x58(%rsp)
    gi_method 3
    cmpq 0x58(%rsp),%rax
    jb Lgi_bad
    movq $0,0x68(%rsp) /* callback delivery count */
    xorl %edx,%edx
    movl $0x40000,%r8d
    movl $1,%r9d
    movl $2,0x20(%rsp)
    leaq 0x68(%rsp),%rax
    movq %rax,0x28(%rsp)
    leaq Lgi_callback(%rip),%rax
    movq %rax,0x30(%rsp)
    leaq 0x60(%rsp),%rax
    movq %rax,0x38(%rsp)
    gi_method 9
    testl %eax,%eax
    jne Lgi_bad
    cmpq $0,0x60(%rsp)
    je Lgi_bad
    movq 0x60(%rsp),%rdx
    gi_method 12
    movq 0x60(%rsp),%rdx
    movq $-1,%r8
    gi_method 13
    cmpb $1,%al
    jne Lgi_bad
    movq 0x60(%rsp),%rdx
    movq $-1,%r8
    gi_method 13
    testb %al,%al
    jne Lgi_bad
    cmpq $0,0x68(%rsp)
    jne Lgi_bad
    movq $-1,0x58(%rsp)
    movl $0x40000,%edx
    xorl %r8d,%r8d
    leaq 0x58(%rsp),%r9
    gi_method 4
    cmpl $0x838a0003,%eax
    jne Lgi_bad
    cmpq $0,0x58(%rsp)
    jne Lgi_bad
    .irp SLOT,5,6
        movq $-1,0x58(%rsp)
        xorl %edx,%edx
        movl $0x40000,%r8d
        xorl %r9d,%r9d
        leaq 0x58(%rsp),%rax
        movq %rax,0x20(%rsp)
        gi_method \SLOT
        cmpl $0x838a0003,%eax
        jne Lgi_bad
        cmpq $0,0x58(%rsp)
        jne Lgi_bad
    .endr
    movq $-1,0x58(%rsp)
    leaq Lgi_bad_iid(%rip),%rdx
    leaq 0x58(%rsp),%r8
    gi_method 16
    cmpl $0x838a0002,%eax
    jne Lgi_bad
    cmpq $0,0x58(%rsp)
    jne Lgi_bad
    gi_method 2
    testl %eax,%eax
    jne Lgi_bad
    cmpl $0x324567ab,%gs:0x68
    jne Lgi_bad
    movl $53,%eax
    addq $0x78,%rsp
    retq
Lgi_unsupported:
    subq $0x78,%rsp
    leaq 0x50(%rsp),%rcx
    gi_create
    testl %eax,%eax
    jne Lgi_bad
    gi_method 7
Lgi_bad:
    movl $99,%eax
    addq $0x78,%rsp
    retq
Lgi_callback:
    ud2 /* There is no device, so this must never run. */
.p2align 2
Lgi_iid:
    .long 0x11be2a7e
    .short 0x4254,0x445a
    .byte 0x9c,9,0xff,0xc4,0x0f,0,0x69,0x18
Lgi_bad_iid:
    .fill 32,1,0xee
.fill {capacity}-(.-Lgi_code),1,0xcc
