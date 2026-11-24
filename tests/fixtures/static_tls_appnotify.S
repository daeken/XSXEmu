/* Owned Win64 probe. Guest callback/context tokens are intentionally unmapped. */
.const
.globl _static_tls_appnotify_fixture
.p2align 2
_static_tls_appnotify_fixture:
    .long Lappnotify_entry-Lappnotify_text
Lappnotify_text:
    retq
.macro appnotify_import offset
    leaq Lappnotify_text(%rip), %r11
    callq *{iat_delta}+\offset(%r11)
    cmpl $0x8e77aacc, %gs:0x68
    jne Lappnotify_bad
.endm
.macro appnotify_register offset, out, callback=0x123456789abc
    movabsq $\callback,%rcx
    movabsq $0x23456789abcd,%rdx
    leaq \out(%rsp),%r8
    appnotify_import \offset
.endm
Lappnotify_entry:
    subq $56,%rsp
    movl $0x8e77aacc, %gs:0x68
    movq $-1,32(%rsp)
    appnotify_register 0,32,0
    cmpl $87,%eax
    jne Lappnotify_bad
    cmpq $0,32(%rsp)
    jne Lappnotify_bad
    appnotify_register 0,32
    testl %eax,%eax
    jne Lappnotify_bad
    appnotify_register 16,40
    testl %eax,%eax
    jne Lappnotify_bad
    movq 32(%rsp),%rax
    testq %rax,%rax
    jz Lappnotify_bad
    cmpq $0,40(%rsp)
    je Lappnotify_bad
    cmpq 40(%rsp),%rax
    je Lappnotify_bad
    movq %rax,%rcx
    appnotify_import 8
    movq 40(%rsp),%rcx
    appnotify_import 24
    appnotify_register 0,48
    testl %eax,%eax
    jne Lappnotify_bad
    movq 48(%rsp),%rcx
    cmpq 32(%rsp),%rcx
    je Lappnotify_bad
    cmpq 40(%rsp),%rcx
    je Lappnotify_bad
    appnotify_import 8
    movl $51,%eax
    addq $56,%rsp
    retq
Lappnotify_bad:
    ud2
    .org Lappnotify_text + {capacity}, 0xcc
