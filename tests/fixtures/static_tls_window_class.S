/* Owned Win64 fixture; no host windows or Xbox SDK inputs. */
.const
.globl _static_tls_window_class_fixture
.p2align 2
_static_tls_window_class_fixture:
    .long Lwc_entry-Lwc_text
Lwc_text:
    retq                        /* TLS callback */
Lwc_callback:
    ud2                         /* Registration must never call this. */

.macro register_class error
    movl $0x8e77aacc, %gs:0x68
    leaq Lwc_text(%rip), %r11
    callq *{iat_delta}(%r11)
    .if \error
    testw %ax, %ax
    jne Lwc_bad
    cmpl $\error, %gs:0x68
    jne Lwc_bad
    .else
    testw %ax, %ax
    je Lwc_bad
    cmpl $0x8e77aacc, %gs:0x68
    jne Lwc_bad
    .endif
.endm
.macro register_struct error
    leaq 32(%rsp), %rcx
    register_class \error
.endm

Lwc_entry:
    subq $392, %rsp
    xorps %xmm0, %xmm0
    movups %xmm0, 32(%rsp)
    movups %xmm0, 48(%rsp)
    movups %xmm0, 64(%rsp)
    movups %xmm0, 80(%rsp)
    movups %xmm0, 96(%rsp)
    movl $0x50, 32(%rsp)
    movl $3, 36(%rsp)
    leaq Lwc_callback(%rip), %rax
    movq %rax, 40(%rsp)
    leaq Lwc_text(%rip), %rax
    subq ${text}, %rax
    movq %rax, 56(%rsp)
    movq $6, 80(%rsp)
    leaq 112(%rsp), %rdx
    movq %rdx, 96(%rsp)
    movl $0x656e774f, 112(%rsp) /* "Owned" */
    movw $0x0064, 116(%rsp)

    xorl %ecx, %ecx
    register_class 87
    movl $0x123456, %ecx       /* Unmapped struct. */
    register_class 998
    movl $0x48, 32(%rsp)
    register_struct 87
    movl $0x50, 32(%rsp)
    incq 56(%rsp)              /* Image interior, not a module handle. */
    register_struct 87
    decq 56(%rsp)
    movq $0, 40(%rsp)
    register_struct 87
    leaq Lwc_text(%rip), %rax
    leaq {iat_delta}(%rax), %rax /* Mapped data, not executable code. */
    movq %rax, 40(%rsp)
    register_struct 87
    leaq Lwc_callback(%rip), %rax
    movq %rax, 40(%rsp)
    movq $7, 80(%rsp)
    register_struct 50
    movq $6, 80(%rsp)
    movq $0x123456, 96(%rsp)   /* Unmapped name. */
    register_struct 998
    leaq 112(%rsp), %rax
    movq %rax, 96(%rsp)
    leaq 112(%rsp), %rdx
    movl $256, %ecx
Lwc_fill:
    movb $65, (%rdx)
    incq %rdx
    decl %ecx
    jne Lwc_fill
    register_struct 87       /* No NUL within 256 bytes. */
    movl $0x656e774f, 112(%rsp)
    movw $0x0064, 116(%rsp)
    register_struct 0
    movw %ax, 368(%rsp)

    movb $'B', 112(%rsp)      /* Change the caller's buffer after commit. */
    movl $0x454e574f, 120(%rsp) /* "OWNED" in different buffer and case. */
    movw $0x0044, 124(%rsp)
    leaq 120(%rsp), %rax
    movq %rax, 96(%rsp)
    register_struct 1410      /* Original name is still owned by registry. */
    leaq 112(%rsp), %rax
    movq %rax, 96(%rsp)
    register_struct 0         /* Modified name is not in the registry. */
    cmpw 368(%rsp), %ax
    je Lwc_bad
    movl $53, %eax
    addq $392, %rsp
    retq
Lwc_bad:
    ud2
    .org Lwc_text + {capacity}, 0xcc
