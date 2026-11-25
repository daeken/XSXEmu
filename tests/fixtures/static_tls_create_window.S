/* Owned Win64 PE code. Covers 12-argument IAT -> host ABI and nested callback. */
.const
.globl _static_tls_create_window_fixture
.p2align 2
_static_tls_create_window_fixture:
    .long Lwin_entry-Lwin_text
    .long Lwin_callback-Lwin_text
Lwin_text:
    retq
Lwin_class: .asciz "OwnedWindow"
Lwin_title: .asciz "XSXEmu owned window test"
.p2align 4
Lwin_callback:
    testq %rcx,%rcx
    jz Lwin_bad
    testq %r8,%r8
    jnz Lwin_bad
    cmpq $0,0(%r9)
    jne Lwin_bad
    cmpl $480,32(%r9)
    jne Lwin_bad
    cmpl $640,36(%r9)
    jne Lwin_bad
    cmpl $0x80000000,40(%r9)
    jne Lwin_bad
    cmpl $0x80000000,44(%r9)
    jne Lwin_bad
    cmpl $0xcf0000,48(%r9)
    jne Lwin_bad
    leaq Lwin_text(%rip), %r11
    movq %r11,%rax
    subq ${text},%rax
    cmpq %rax,8(%r9)
    jne Lwin_bad
    movq 64(%r9),%rax
    cmpb $'O', (%rax)
    jne Lwin_bad
    movq 56(%r9),%rax
    cmpb $'X', (%rax)
    jne Lwin_bad
    movq %gs:0x30,%rax
    cmpq %rax,{mode_delta}+16(%r11)
    jne Lwin_bad
    movq %gs:0x58,%rax
    cmpq %rax,{mode_delta}+24(%r11)
    jne Lwin_bad
    cmpl $0x81,%edx
    jne Lwin_wm_create
    cmpl $0x12345678,%gs:0x68
    jne Lwin_bad
    movl $0x23456789,%gs:0x68
    movq %rcx,{mode_delta}+8(%r11) /* provisional HWND */
    cmpl $-1,{mode_delta}(%r11)
    jne 1f
    xorl %eax,%eax                /* WM_NCCREATE veto: no WM_CREATE */
    retq
1:
    incl {mode_delta}(%r11)
    jmp *{iat_delta}+16(%r11)       /* nested DefWindowProcA */
Lwin_wm_create:
    cmpl $1,%edx
    jne Lwin_bad
    cmpl $0x23456789,%gs:0x68
    jne Lwin_bad
    movl $0x34567890,%gs:0x68
    incl {mode_delta}(%r11)
    cmpl $2,{mode_delta}(%r11)
    jne 1f
    movq $-1,%rax                 /* veto first creation after WM_NCCREATE */
    retq
1:
    jmp *{iat_delta}+16(%r11)

.macro create_window width
    movl $0x12345678,%gs:0x68
    leaq Lwin_text(%rip), %r11
    leaq Lwin_class(%rip), %rdx
    leaq Lwin_title(%rip), %r8
    xorl %ecx,%ecx
    movl $0xcf0000,%r9d
    movq $0x80000000,%rax
    movq %rax,32(%rsp)
    movq %rax,40(%rsp)
    movq $\width,48(%rsp)
    movq $480,56(%rsp)
    movq $0,64(%rsp)
    movq $0,72(%rsp)
    movq %r11,%rax
    subq ${text},%rax
    movq %rax,80(%rsp)
    movq $0,88(%rsp)
    callq *{iat_delta}+8(%r11)
.endm
Lwin_entry:
    subq $184,%rsp
    xorps %xmm0,%xmm0
    movups %xmm0,96(%rsp)
    movups %xmm0,112(%rsp)
    movups %xmm0,128(%rsp)
    movups %xmm0,144(%rsp)
    movups %xmm0,160(%rsp)
    movl $0x50,96(%rsp)
    movl $3,100(%rsp)
    leaq Lwin_callback(%rip),%rax
    movq %rax,104(%rsp)
    leaq Lwin_text(%rip),%r11
    movq %gs:0x30,%rax
    movq %rax,{mode_delta}+16(%r11)
    movq %gs:0x58,%rax
    movq %rax,{mode_delta}+24(%r11)
    testq %rax,%rax
    jz Lwin_bad
    movl $0,{mode_delta}(%r11)
    movq %r11,%rax
    subq ${text},%rax
    movq %rax,120(%rsp)
    movq $6,144(%rsp)
    leaq Lwin_class(%rip),%rax
    movq %rax,160(%rsp)
    leaq 96(%rsp),%rcx
    callq *{iat_delta}(%r11)
    testw %ax,%ax
    jz Lwin_bad

    create_window 0
    testq %rax,%rax
    jnz Lwin_bad
    cmpl $50,%gs:0x68
    jne Lwin_bad
    leaq Lwin_text(%rip),%r11
    cmpl $1,{mode_delta}+4(%r11)
    jne 1f
    create_window 640
    testq %rax,%rax
    jnz Lwin_bad
    cmpl $87,%gs:0x68            /* active CFG denies WndProc */
    jne Lwin_bad
    leaq Lwin_text(%rip),%r11
    cmpl $0,{mode_delta}(%r11)
    jne Lwin_bad
    jmp Lwin_success
1:
    movl $16,176(%rsp)           /* at capacity if any veto leaks */
Lwin_rollback_loop:
    movl $-1,{mode_delta}(%r11)
    create_window 640
    testq %rax,%rax
    jnz Lwin_bad
    cmpl $1223,%gs:0x68
    jne Lwin_bad
    leaq Lwin_text(%rip),%r11
    cmpl $-1,{mode_delta}(%r11)
    jne Lwin_bad
    movl $0,{mode_delta}(%r11)
    create_window 640
    testq %rax,%rax
    jnz Lwin_bad
    cmpl $1223,%gs:0x68
    jne Lwin_bad
    leaq Lwin_text(%rip),%r11
    decl 176(%rsp)
    jne Lwin_rollback_loop
    create_window 640
    testq %rax,%rax
    jz Lwin_bad
    cmpl $0x34567890,%gs:0x68
    jne Lwin_bad
    leaq Lwin_text(%rip),%r11
    cmpl $4,{mode_delta}(%r11)
    jne Lwin_bad
    cmpq {mode_delta}+8(%r11),%rax /* returned HWND matches callback */
    jne Lwin_bad
    movq %gs:0x30,%rax
    cmpq %rax,{mode_delta}+16(%r11)
    jne Lwin_bad
    movq %gs:0x58,%rax
    cmpq %rax,{mode_delta}+24(%r11)
    jne Lwin_bad
Lwin_success:
    movl $54,%eax
    addq $184,%rsp
    retq
Lwin_bad:
    ud2
    .org Lwin_text+{capacity},0xcc
