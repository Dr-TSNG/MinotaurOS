use riscv::register::sstatus::Sstatus;

#[derive(Clone, Debug)]
#[repr(C)]
struct TrapContext {
    /*  0 */ pub user_x: [usize; 32],
    /* 32 */ pub user_f: [usize; 32],
    /* 64 */ pub fcsr: usize,
    /* 65 */ pub sstatus: Sstatus,
    /* 66 */ pub sepc: usize,
    /* 67 */ pub kernel_tp: usize,
    /* 68 */ pub kernel_fp: usize,
    /* 69 */ pub kernel_sp: usize,
    /* 70 */ pub kernel_ra: usize,
    /* 71 */ pub kernel_s: [usize; 12],
}
