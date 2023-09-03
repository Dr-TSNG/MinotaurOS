.attribute arch, "rv64gc"
.altmacro
.macro SAVE_GP n
    sd x\n, \n*8(sp)
.endm
.macro LOAD_GP n
    ld x\n, \n*8(sp)
.endm
.macro SAVE_FP n, m
    fsd f\n, \m*8(sp)
.endm
.macro LOAD_FP n, m
    fld f\n, \m*8(sp)
.endm

.section .text
.align 2
__trap_from_user:
    # 交换 sp 和 sscratch，切换到内核栈，同时将用户栈保存到 sscratch
    # 将 sp 指向 &TrapContext
    csrrw sp, sscratch, sp

    # 保存除 x0/sp 以外的通用寄存器
    sd x1, 1*8(sp)
    .set n, 3
    .rept 27
        SAVE_GP %n
        .set n, n+1
    .endr

    # 保存浮点寄存器
    .set n, 0
    .set m, 32
    .rept 32
        SAVE_FP %n, %m
        .set n, n+1
        .set m, m+1
    .endr

    # 保存 fcsr/sstatus/sepc
    csrr t0, fcsr
    csrr t1, sstatus
    csrr t2, sepc
    sd t0, 64*8(sp)
    sd t1, 65*8(sp)
    sd t2, 66*8(sp)

    # 保存用户栈指针
    csrr t2, sscratch
    sd t2, 2*8(sp)

    # 恢复内核 callee-saved 寄存器
    ld ra, 70*8(sp)
    ld s0, 71*8(sp)
    ld s1, 72*8(sp)
    ld s2, 73*8(sp)
    ld s3, 74*8(sp)
    ld s4, 75*8(sp)
    ld s5, 76*8(sp)
    ld s6, 77*8(sp)
    ld s7, 78*8(sp)
    ld s8, 79*8(sp)
    ld s9, 80*8(sp)
    ld s10, 81*8(sp)
    ld s11, 82*8(sp)

    # 恢复内核栈指针和 tp(hart)
    ld tp, 67*8(sp)
    ld fp, 68*8(sp)
    ld sp, 69*8(sp)

    # 返回内核调用函数
    ret

__restore_to_user:
    # 将内核栈保存到 sscratch
    csrw sscratch, a0

    # 保存内核 callee-saved 寄存器
    sd ra, 70*8(a0)
    sd s0, 71*8(a0)
    sd s1, 72*8(a0)
    sd s2, 73*8(a0)
    sd s3, 74*8(a0)
    sd s4, 75*8(a0)
    sd s5, 76*8(a0)
    sd s6, 77*8(a0)
    sd s7, 78*8(a0)
    sd s8, 79*8(a0)
    sd s9, 80*8(a0)
    sd s10, 81*8(a0)
    sd s11, 82*8(a0)

    # 保存内核栈指针和 tp(hart)
    sd tp, 67*8(a0)
    sd fp, 68*8(a0)
    sd sp, 69*8(a0)

    # 现在 sp 指向 &TrapContext
    mv sp, a0

    # 恢复 fcsr/sstatus/sepc
    ld t0, 64*8(sp)
    ld t1, 65*8(sp)
    ld t2, 66*8(sp)
    csrr t0, fcsr
    csrr t1, sstatus
    csrr t2, sepc

    # 恢复除 x0/sp 以外的通用寄存器
    ld x1, 1*8(sp)
    .set n, 3
    .rept 29
        LOAD_GP %n
        .set n, n+1
    .endr

    # 恢复浮点寄存器
    .set n, 0
    .set m, 32
    .rept 32
        LOAD_FP %n, %m
        .set n, n+1
        .set m, m+1
    .endr

    # 恢复用户栈指针
    ld sp, 2*8(sp)
    sret

__trap_from_kernel:
    addi sp, sp, -16*8
    sd ra, 0*8(sp)
    sd a0, 1*8(sp)
    sd a1, 2*8(sp)
    sd a2, 3*8(sp)
    sd a3, 4*8(sp)
    sd a4, 5*8(sp)
    sd a5, 6*8(sp)
    sd a6, 7*8(sp)
    sd a7, 8*8(sp)
    sd t0, 9*8(sp)
    sd t1, 10*8(sp)
    sd t2, 11*8(sp)
    sd t3, 12*8(sp)
    sd t4, 13*8(sp)
    sd t5, 14*8(sp)
    sd t6, 15*8(sp)
    call trap_from_kernel
    ld ra, 0*8(sp)
    ld a0, 1*8(sp)
    ld a1, 2*8(sp)
    ld a2, 3*8(sp)
    ld a3, 4*8(sp)
    ld a4, 5*8(sp)
    ld a5, 6*8(sp)
    ld a6, 7*8(sp)
    ld a7, 8*8(sp)
    ld t0, 9*8(sp)
    ld t1, 10*8(sp)
    ld t2, 11*8(sp)
    ld t3, 12*8(sp)
    ld t4, 13*8(sp)
    ld t5, 14*8(sp)
    ld t6, 15*8(sp)
    addi sp, sp, 16*8
    sret
