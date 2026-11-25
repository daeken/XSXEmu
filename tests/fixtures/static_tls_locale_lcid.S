/* Owned Win64 probe: bounded locale-name lookup through the TLS lane. */
.const
.globl _static_tls_locale_lcid_fixture
.p2align 2
_static_tls_locale_lcid_fixture:
    .long Llcid_entry-Llcid_text
Llcid_text:
    retq

.macro check_lcid name, flags, result, error
    leaq Llcid_text(%rip), %r11
    .ifc \name, null
        xorl %ecx, %ecx
    .else
        leaq \name(%rip), %rcx
    .endif
    movl $\flags, %edx
    callq *{iat_delta}(%r11)
    cmpl $\result, %eax
    jne Llcid_bad
    cmpl $\error, %gs:0x68
    jne Llcid_bad
.endm

Llcid_entry:
    subq $40, %rsp
    movl $0x13579bdf, %gs:0x68
    check_lcid Llcid_enus, 0, 0x409, 0x13579bdf
    check_lcid null, 0, 0x409, 0x13579bdf
    check_lcid Llcid_system, 0, 0x409, 0x13579bdf
    check_lcid Llcid_invariant, 0, 0x7f, 0x13579bdf
    check_lcid Llcid_en, 0, 0x409, 0x13579bdf
    check_lcid Llcid_en, 0x08000000, 9, 0x13579bdf
    check_lcid Llcid_enus, 1, 0, 87
    check_lcid Llcid_unknown, 0, 0, 87
    check_lcid Llcid_long, 0, 0, 87
    addq $40, %rsp
    movl $52, %eax
    retq
Llcid_bad:
    ud2

.p2align 1
Llcid_enus:
    .short 69, 110, 45, 117, 83, 0 /* En-uS */
Llcid_system:
    .short 33, 120, 45, 115, 121, 115, 45, 100, 101, 102, 97, 117, 108, 116, 45, 108, 111, 99, 97, 108, 101, 0
Llcid_invariant:
    .short 0
Llcid_en:
    .short 101, 110, 0
Llcid_unknown:
    .short 101, 110, 45, 71, 66, 0 /* en-GB is not installed in this guest. */
Llcid_long:
    .rept 85
        .short 65
    .endr
    .org Llcid_text + {capacity}, 0xcc
