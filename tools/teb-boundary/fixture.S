/* Only the private libSystem setter and owned assembly run with guest GS.
 * Host Rust and libSystem (except the setter and the signal trampoline under
 * experiment) are reached only with the original pthread GS restored. */
.text

.macro check_host ctx
    movq %gs:0, %r10
    cmpq {HOST0}(\ctx), %r10
    jne Lbad_switch
    movq %gs:0x30, %r10
    cmpq {HOST30}(\ctx), %r10
    jne Lbad_switch
.endm

.macro check_guest ctx, error, tls, fail
    movq %gs:0x30, %r10
    cmpq {GUEST_BASE}(\ctx), %r10
    jne \fail
    cmpl $\error, %gs:0x68
    jne \fail
    movq %gs:0x58, %r10
    cmpq {TLS_VECTOR}(\ctx), %r10
    jne \fail
    movq 8(%r10), %r10
    movabsq $\tls, %r11
    cmpq %r11, (%r10)
    jne \fail
.endm

/* Fixed-arity Win64 wrapper frame, aligned at each call. The setter has
 * SysV ABI: preserve Win64's extra nonvolatiles (RDI, RSI, XMM6..15) and
 * spill the position-dependent argument registers before crossing ABIs.
 * 0..31 is outgoing home space, 32..55 are outgoing args 5..7.
 * Incoming args 5..7 are at frame size + 40/48/56, past the return address
 * and incoming home space. Return channels used here: RAX and XMM0. */
.set FRAME, 376
.macro save_win64
    subq $FRAME, %rsp
    movaps %xmm0, 64(%rsp)
    movaps %xmm1, 80(%rsp)
    movaps %xmm2, 96(%rsp)
    movaps %xmm3, 112(%rsp)
    movq %rcx, 128(%rsp)
    movq %rdx, 136(%rsp)
    movq %r8,  144(%rsp)
    movq %r9,  152(%rsp)
    movaps %xmm6,  160(%rsp)
    movaps %xmm7,  176(%rsp)
    movaps %xmm8,  192(%rsp)
    movaps %xmm9,  208(%rsp)
    movaps %xmm10, 224(%rsp)
    movaps %xmm11, 240(%rsp)
    movaps %xmm12, 256(%rsp)
    movaps %xmm13, 272(%rsp)
    movaps %xmm14, 288(%rsp)
    movaps %xmm15, 304(%rsp)
    movq %rdi, 320(%rsp)
    movq %rsi, 328(%rsp)
.endm

.macro switch_to field
    movq 336(%rsp), %rax
    movq \field(%rax), %rdi
    callq __thread_set_tsd_base
.endm

.macro forward target
    movq FRAME+40(%rsp), %rax
    movq %rax, 32(%rsp)
    movq FRAME+48(%rsp), %rax
    movq %rax, 40(%rsp)
    movq 336(%rsp), %rax
    movq %rax, 48(%rsp)
    movq 128(%rsp), %rcx
    movq 136(%rsp), %rdx
    movq 144(%rsp), %r8
    movq 152(%rsp), %r9
    movaps 64(%rsp), %xmm0
    movaps 80(%rsp), %xmm1
    movaps 96(%rsp), %xmm2
    movaps 112(%rsp), %xmm3
    callq \target
.endm

.macro save_return
    movq %rax, 344(%rsp)
    movaps %xmm0, 352(%rsp)
.endm

.macro return_win64
    movq 344(%rsp), %rax
    movaps 352(%rsp), %xmm0
    movaps 160(%rsp), %xmm6
    movaps 176(%rsp), %xmm7
    movaps 192(%rsp), %xmm8
    movaps 208(%rsp), %xmm9
    movaps 224(%rsp), %xmm10
    movaps 240(%rsp), %xmm11
    movaps 256(%rsp), %xmm12
    movaps 272(%rsp), %xmm13
    movaps 288(%rsp), %xmm14
    movaps 304(%rsp), %xmm15
    movq 320(%rsp), %rdi
    movq 328(%rsp), %rsi
    addq $FRAME, %rsp
    retq
.endm

/* Six Win64 arguments in; hand the trusted fixture context to Rust as #7. */
Lenter_provider:
    save_win64
    movq %gs:0x80, %rax
    movq %rax, 336(%rsp)
    switch_to {HOST_BASE}
    movq 336(%rsp), %rax
    check_host %rax
    forward _rust_provider
    save_return
    switch_to {GUEST_BASE}
    return_win64

.globl _enter_callback
_enter_callback:
    save_win64
    movq FRAME+56(%rsp), %rax
    movq %rax, 336(%rsp)
    switch_to {GUEST_BASE}
    forward Lguest_callback
    save_return
    switch_to {HOST_BASE}
    movq 336(%rsp), %rax
    check_host %rax
    return_win64

/* SysV entry. Keep ctx in a common nonvolatile across intentional switches. */
.globl _run_boundary
_run_boundary:
    pushq %r12
    subq $48, %rsp
    movq %rdi, %r12
    movq {GUEST_BASE}(%r12), %rdi
    callq __thread_set_tsd_base
    movq %r12, %rcx
    callq Lguest_entry
    movq %rax, 40(%rsp)
    movq {HOST_BASE}(%r12), %rdi
    callq __thread_set_tsd_base
    check_host %r12
    movq 40(%rsp), %rax
    addq $48, %rsp
    popq %r12
    retq

/* Win64 guest entry; ctx in RCX. Allocates home + two outgoing stack args.
 * RDI, RSI and two nonvolatile XMMs are callee-saved here and seeded to
 * check the provider's Win64 preservation across the SysV setter. */
Lguest_entry:
    pushq %r12
    pushq %rdi
    pushq %rsi
    subq $80, %rsp
    movaps %xmm6, 48(%rsp)
    movaps %xmm15, 64(%rsp)
    movq %rcx, %r12
    check_guest %r12, {ERROR_IN}, {TLS_IN}, Lbefore_failed
    cmpq %gs:0x80, %r12
    jne Lbefore_failed
    movl $0x21212121, %edi
    movl $0x42424242, %esi
    pcmpeqd %xmm6, %xmm6
    movl $0x13579bdf, %eax
    movd %eax, %xmm15
    pshufd $0, %xmm15, %xmm15
    movabsq ${P_INT}, %rcx
    movabsq ${P_DOUBLE}, %rax
    movq %rax, %xmm1
    movabsq ${P_INT3}, %r8
    movl ${P_FLOAT}, %eax
    movd %eax, %xmm3
    movabsq ${P_STACK_INT}, %rax
    movq %rax, 32(%rsp)
    movabsq ${P_STACK_DOUBLE}, %rax
    movq %rax, 40(%rsp)
    callq Lenter_provider
    movabsq ${P_OK}, %r10
    cmpq %r10, %rax
    jne Lguest_done
    check_guest %r12, {ERROR_OUT}, {TLS_OUT}, Lafter_failed
    cmpq $0x21212121, %rdi
    jne Lnonvolatile_failed
    cmpq $0x42424242, %rsi
    jne Lnonvolatile_failed
    pcmpeqd %xmm0, %xmm0
    pcmpeqb %xmm6, %xmm0
    pmovmskb %xmm0, %ecx
    cmpl $0xffff, %ecx
    jne Lnonvolatile_failed
    movl $0x13579bdf, %ecx
    movd %ecx, %xmm0
    pshufd $0, %xmm0, %xmm0
    pcmpeqb %xmm15, %xmm0
    pmovmskb %xmm0, %ecx
    cmpl $0xffff, %ecx
    jne Lnonvolatile_failed
Lguest_done:
    movaps 48(%rsp), %xmm6
    movaps 64(%rsp), %xmm15
    addq $80, %rsp
    popq %rsi
    popq %rdi
    popq %r12
    retq
Lbefore_failed:
    movl $0x201, %eax
    jmp Lguest_done
Lafter_failed:
    movl $0x202, %eax
    jmp Lguest_done
Lnonvolatile_failed:
    movl $0x203, %eax
    jmp Lguest_done

/* Win64 leaf. Read both stack args, exercise home space, inspect guest TLS
 * and last-error, then change them and return an exact SIMD bit pattern. */
Lguest_callback:
    movq 56(%rsp), %rax
    check_guest %rax, {ERROR_IN}, {TLS_IN}, Lcallback_failed
    movq %rdx, 8(%rsp)
    movq %xmm0, %rax
    movabsq ${C_DOUBLE}, %r11
    cmpq %r11, %rax
    jne Lcallback_failed
    movabsq ${C_INT}, %r11
    cmpq %r11, 8(%rsp)
    jne Lcallback_failed
    movd %xmm2, %eax
    cmpl ${C_FLOAT}, %eax
    jne Lcallback_failed
    movabsq ${C_INT4}, %r11
    cmpq %r11, %r9
    jne Lcallback_failed
    movabsq ${C_STACK_DOUBLE}, %r11
    cmpq %r11, 40(%rsp)
    jne Lcallback_failed
    movabsq ${C_STACK_INT}, %r11
    cmpq %r11, 48(%rsp)
    jne Lcallback_failed
    movabsq ${TLS_OUT}, %r11
    movq %r11, (%r10)
    movl ${ERROR_OUT}, %gs:0x68
    movabsq ${C_OK}, %rax
    movq %rax, %xmm0
    retq
Lcallback_failed:
    pxor %xmm0, %xmm0
    retq

Lbad_switch:
    /* Never return to Rust with unexpected GS. The outer runner isolates
     * a failure and reports the child's status (or timeout). */
    ud2

/* Async observer. The handler never switches GS or calls any host code.
 * If the platform trampoline fails before/after us, the child may fail. */
.globl _signal_handler
_signal_handler:
    movq %gs:0, %rax
    movq %rax, _SIGNAL_SAMPLE+{HANDLER0}(%rip)
    movq %gs:0x30, %rax
    movq %rax, _SIGNAL_SAMPLE+{HANDLER30}(%rip)
    movq $1, _SIGNAL_SAMPLE+{SEEN}(%rip)
    retq

.globl _signal_window
_signal_window:
    pushq %r12
    pushq %r13
    subq $8, %rsp
    movq %rdi, %r12
    movq %rdx, %r13
    testq %rsi, %rsi
    jz Lparked
    movq {GUEST_BASE}(%r12), %rdi
    callq __thread_set_tsd_base
    movq %gs:0x30, %rax
    cmpq {GUEST_BASE}(%r12), %rax
    jne Lbad_switch
Lparked:
    movq $1, _SIGNAL_SAMPLE+{PARKED}(%rip)
Lwait_signal:
    pause
    cmpq $0, _SIGNAL_SAMPLE+{SEEN}(%rip)
    je Lwait_signal
    movq %gs:0, %rax
    movq %rax, 0(%r13)
    movq %gs:0x30, %rax
    movq %rax, 8(%r13)
    movq {HOST_BASE}(%r12), %rdi
    callq __thread_set_tsd_base
    check_host %r12
    addq $8, %rsp
    popq %r13
    popq %r12
    retq
