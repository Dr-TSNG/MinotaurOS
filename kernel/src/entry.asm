.section .text.entry
.globl _start
_start:
    call setup_stack
    call rust_main
