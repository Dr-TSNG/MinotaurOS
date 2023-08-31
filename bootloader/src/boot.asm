.section .text.entry
.globl _start
_start:
# RustSBI: a0 = hartid
# 先将 hartid 复制到 tp，这样可以确定当前使用的核
# 查看 trap 上下文切换，只有 tp 没有被使用过
# 然后为每一个核分配初始栈空间（注意是栈顶）
# 这里左移 16 位，可以查看指令 la 的相关说明
    mv tp, a0
    add t0, a0, 1
    slli t0, t0, 16
    la sp, boot_stack
    add sp, sp, t0
    call boot_entry

.section .bss.stack
.globl boot_stack
boot_stack:
    .space 4096 * 16 * 2
    .globl boot_stack_top
boot_stack_top:
