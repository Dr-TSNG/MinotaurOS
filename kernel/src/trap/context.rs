use riscv::register::sstatus;
use riscv::register::sstatus::{SPP, Sstatus};

#[derive(Clone, Debug)]
#[repr(C)]
pub struct TrapContext {
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

impl TrapContext {
    pub fn new(entry: usize, sp: usize) -> Self {
        let mut sstatus = sstatus::read();
        sstatus.set_spp(SPP::User);
        sstatus.set_sie(false);
        sstatus.set_spie(false);
        let mut ctx = Self {
            user_x: [0; 32],
            user_f: [0; 32],
            fcsr: 0,
            sstatus,
            sepc: entry,
            kernel_tp: 0,
            kernel_fp: 0,
            kernel_sp: 0,
            kernel_ra: 0,
            kernel_s: [0; 12],
        };
        ctx.set_sp(sp);
        ctx
    }

    pub fn get_sp(&self) -> usize {
        self.user_x[2]
    }

    pub fn set_sp(&mut self, sp: usize) {
        self.user_x[2] = sp;
    }
}
