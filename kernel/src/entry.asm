.equ SV39_MODE, 8

.section .text.entry
.globl _start
_start:
    # 设置引导页表
    la t0, boot_page_table
    li t1, SV39_MODE << 60
    srli t0, t0, 12
    or t0, t0, t1
    csrw satp, t0
    sfence.vma
    # 跳转到主函数
    call pspace_main

.section .rodata
.align 12
boot_page_table:
    # 0x0000_0000_8000_0000 -> 0x0000_0000_8000_0000
    # 0xffff_ffff_8000_0000 -> 0x0000_0000_8000_0000
    .quad 0
    .quad 0
    .quad (0x80000 << 10) | 0xcf # VRWXAD
    .zero 8 * 507
    .quad (0x80000 << 10) | 0xcf # VRWXAD
    .zero 8 * 253
