/* Original synthetic guest. No host APIs run with the synthetic TEB active
 * (except the libSystem thunk needed to restore the private probe's base). */
.text
.globl _observe_guest
_observe_guest:
    movl %edi, %edi
    movq %gs:0x30, %rax
    movq %rax, 0(%rsi)
    movq %gs:0x58, %rax
    movq %rax, 8(%rsi)
    movq (%rax,%rdi,8), %rax
    movq (%rax), %rdx
    movq %rdx, 16(%rsi)
    notq %rdx
    movq %rdx, 8(%rax)
    movl $0x55aa1234, %gs:0x68
    retq

.globl _observe_private
_observe_private:
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    subq $8, %rsp
    movq %rsi, %r12
    movl %edx, %r13d
    movq %rcx, %r14
    movq %r8, %r15
    callq __thread_set_tsd_base
    movl %r13d, %edi
    movq %r14, %rsi
    callq _observe_guest
    movq %r12, %rdi
    callq __thread_set_tsd_base
    movq %gs:0, %rax
    movq %rax, 0(%r15)
    movq %gs:0x30, %rax
    movq %rax, 8(%r15)
    addq $8, %rsp
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    retq
