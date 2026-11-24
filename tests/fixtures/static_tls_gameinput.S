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
.macro gi_method slot, object=0x50
    movq \object(%rsp),%rcx
    movq (%rcx),%rax
    movq (8*\slot)(%rax),%rax
    leaq Lgi_code(%rip),%r11
    callq *{dispatch_delta}(%r11)
.endm
.macro gi_register kind, enumeration, callback
    xorl %edx,%edx
    movl $\kind,%r8d
    movl $1,%r9d
    movl $\enumeration,0x20(%rsp)
    leaq 0x68(%rsp),%rax
    movq %rax,0x28(%rsp)
    .if \callback
        leaq Lgi_callback(%rip),%rax
    .else
        xorl %eax,%eax
    .endif
    movq %rax,0x30(%rsp)
    leaq 0x60(%rsp),%rax
    movq %rax,0x38(%rsp)
    gi_method 9
.endm
Lgi_entry:
    subq $0x78,%rsp
    movl $0x324567ab,%gs:0x68
    xorl %ecx,%ecx
    gi_create
    cmpl $0x80004003,%eax
    jne Lgi_bad
    movq $-1,0x50(%rsp)
    movq $0x1234,0x58(%rsp)
    leaq 0x50(%rsp),%rcx
    gi_create
    testl %eax,%eax
    jne Lgi_bad
    cmpq $0,0x50(%rsp)
    je Lgi_bad
    cmpq $0x1234,0x58(%rsp)
    jne Lgi_bad
    /* The relocated vtable and every target must be inside the exact
       synthetic guest facade relative to the #1 guest entry. */
    leaq Lgi_code(%rip),%r11
    movq {iat_delta}(%r11),%rax
    movq 0x50(%rsp),%r10
    movq (%r10),%r10
    leaq 0x4280(%rax),%r11
    cmpq %r11,%r10
    jne Lgi_bad
    addq $16,%rax
    xorl %edx,%edx
Lgi_vtable:
    cmpq %rax,(%r10,%rdx,8)
    jne Lgi_bad
    addq $16,%rax
    incq %rdx
    cmpq $22,%rdx
    jne Lgi_vtable
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
    leaq Lgi_unknown(%rip),%rdx
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
    movq $0x1234,0x60(%rsp)
    leaq Lgi_bad_iid(%rip),%rdx
    leaq 0x58(%rsp),%r8
    gi_method 0
    cmpl $0x80004002,%eax
    jne Lgi_bad
    cmpq $0,0x58(%rsp)
    jne Lgi_bad
    cmpq $0x1234,0x60(%rsp)
    jne Lgi_bad
    movq $0x1234,0x58(%rsp)
    movq $0x5678,0x68(%rsp)
    /* Fifth-argument enum and seventh-argument callback reject bad
       values and clear exactly the eighth-argument 64-bit output. */
    .irp TEST,0,1
        movq $-1,0x60(%rsp)
        gi_register 0x40000, (2-\TEST), \TEST
        cmpl $0x80070057,%eax
        jne Lgi_bad
        cmpq $0,0x60(%rsp)
        jne Lgi_bad
    .endr
    movq $-1,0x60(%rsp)
    gi_register 0x40000, 2, 1
    testl %eax,%eax
    jne Lgi_bad
    cmpq $1,0x60(%rsp)
    jne Lgi_bad
    cmpq $0x1234,0x58(%rsp)
    jne Lgi_bad
    cmpq $0x5678,0x68(%rsp)
    jne Lgi_bad
    leaq 0x70(%rsp),%rcx
    gi_create
    testl %eax,%eax
    jne Lgi_bad
    movq 0x70(%rsp),%rax
    cmpq 0x50(%rsp),%rax
    je Lgi_bad
    movq 0x60(%rsp),%rdx
    movq $-1,%r8
    gi_method 13,0x70
    testb %al,%al
    jne Lgi_bad
    gi_method 2,0x70
    testl %eax,%eax
    jne Lgi_bad
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
    gi_register 0x10, 2, 1
    testl %eax,%eax
    jne Lgi_bad
    cmpq $2,0x60(%rsp)
    jne Lgi_bad
    movl $1,%edx
    movq $-1,%r8
    gi_method 13
    testb %al,%al
    jne Lgi_bad
    movq 0x60(%rsp),%rdx
    movq $-1,%r8
    gi_method 13
    cmpb $1,%al
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
Lgi_unknown:
    .quad 0,0x46000000000000c0
Lgi_bad_iid:
    .fill 32,1,0xee
.fill {capacity}-(.-Lgi_code),1,0xcc
