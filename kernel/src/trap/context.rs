use core::arch::asm;
use core::mem::size_of;
use bitflags::bitflags;
use riscv::register::sstatus;
use riscv::register::sstatus::{FS, SPP, Sstatus};

#[derive(Clone, Debug)]
#[repr(C)]
pub struct TrapContext {
    /*  0 */ pub user_x: [usize; 32],
    /* 32 */ pub fctx: FloatContext,
    /* 65 */ pub sstatus: Sstatus,
    /* 66 */ pub kernel_tp: usize,
    /* 67 */ pub kernel_fp: usize,
    /* 68 */ pub kernel_sp: usize,
    /* 69 */ pub kernel_ra: usize,
    /* 70 */ pub kernel_s: [usize; 12],
}

#[derive(Clone, Debug)]
#[repr(C)]
pub struct FloatContext {
    /* 32 */ pub user_f: [f64; 32],
    /* 64 */ pub fcsr: u32,
    /* 64 */ status: FloatStatus,
}

bitflags! {
    #[repr(transparent)]
    #[derive(Clone, Debug)]
    struct FloatStatus: u32 {
        const IS_DIRTY      = 1 << 0; // 当前寄存器是否被修改
        const TRAP_RELOAD   = 1 << 1; // 是否需要恢复
        const EVER_MODIFIED = 1 << 2; // 是否曾经修改过寄存器
    }
}

// 浮点寄存器状态机
// 1. 从用户态陷入内核态时，如果浮点寄存器在此次运行期间被修改过，标记为脏
// 2. 从内核态返回用户态时，恢复浮点寄存器
// 3. 切换线程时，如果浮点寄存器自线程诞生以来有被修改过，保存到上下文，标记为需要恢复
// 4. 当信号发生并准备切换 pc 到用户态 handler 时，如果浮点寄存器自线程诞生以来有被修改过，保存到上下文
// 5. sigreturn 时，如果浮点寄存器在此次运行期间被修改过，标记为需要恢复
impl TrapContext {
    pub fn new(entry: usize, sp: usize) -> Self {
        let mut sstatus = sstatus::read();
        sstatus.set_spp(SPP::User);
        sstatus.set_sie(false);
        sstatus.set_spie(false);
        sstatus.set_fs(FS::Clean);
        let mut ctx = Self {
            user_x: [0; 32],
            fctx: FloatContext::new(),
            sstatus,
            kernel_tp: 0,
            kernel_fp: 0,
            kernel_sp: 0,
            kernel_ra: 0,
            kernel_s: [0; 12],
        };
        ctx.set_pc(entry);
        ctx.set_sp(sp);
        ctx
    }

    pub fn get_pc(&self) -> usize {
        self.user_x[0]
    }

    pub fn set_pc(&mut self, sepc: usize) {
        self.user_x[0] = sepc;
    }

    pub fn get_sp(&self) -> usize {
        self.user_x[2]
    }

    pub fn set_sp(&mut self, sp: usize) {
        self.user_x[2] = sp;
    }
}

impl FloatContext {
    fn new() -> Self {
        debug_assert_eq!(size_of::<Self>(), 33 * size_of::<usize>());
        Self {
            user_f: [0f64; 32],
            fcsr: FS::Clean as u32,
            status: FloatStatus::empty(),
        }
    }

    pub fn trap_in(&mut self, sstatus: Sstatus) {
        if sstatus.fs() == FS::Dirty {
            self.status |= FloatStatus::IS_DIRTY;
            self.status |= FloatStatus::EVER_MODIFIED;
        }
    }

    pub fn trap_out(&mut self) {
        self.restore();
    }

    pub fn sched_out(&mut self) {
        if self.status.contains(FloatStatus::EVER_MODIFIED) {
            self.save();
            self.status.insert(FloatStatus::TRAP_RELOAD);
        }
    }

    pub fn signal_enter(&mut self) {
        if self.status.contains(FloatStatus::EVER_MODIFIED) {
            self.save();
        }
    }

    pub fn signal_exit(&mut self, saved: &[f64; 32]) {
        if self.status.contains(FloatStatus::IS_DIRTY) {
            self.user_f.copy_from_slice(saved);
            self.status.insert(FloatStatus::TRAP_RELOAD);
        }
    }

    fn save(&mut self) {
        if !self.status.contains(FloatStatus::IS_DIRTY) {
            return;
        }
        self.status.remove(FloatStatus::IS_DIRTY);
        unsafe {
            asm! {
            "fsd  f0,  0*8({0})",
            "fsd  f1,  1*8({0})",
            "fsd  f2,  2*8({0})",
            "fsd  f3,  3*8({0})",
            "fsd  f4,  4*8({0})",
            "fsd  f5,  5*8({0})",
            "fsd  f6,  6*8({0})",
            "fsd  f7,  7*8({0})",
            "fsd  f8,  8*8({0})",
            "fsd  f9,  9*8({0})",
            "fsd f10, 10*8({0})",
            "fsd f11, 11*8({0})",
            "fsd f12, 12*8({0})",
            "fsd f13, 13*8({0})",
            "fsd f14, 14*8({0})",
            "fsd f15, 15*8({0})",
            "fsd f16, 16*8({0})",
            "fsd f17, 17*8({0})",
            "fsd f18, 18*8({0})",
            "fsd f19, 19*8({0})",
            "fsd f20, 20*8({0})",
            "fsd f21, 21*8({0})",
            "fsd f22, 22*8({0})",
            "fsd f23, 23*8({0})",
            "fsd f24, 24*8({0})",
            "fsd f25, 25*8({0})",
            "fsd f26, 26*8({0})",
            "fsd f27, 27*8({0})",
            "fsd f28, 28*8({0})",
            "fsd f29, 29*8({0})",
            "fsd f30, 30*8({0})",
            "fsd f31, 31*8({0})",
            "csrr {1}, fcsr",
            in(reg) self,
            out(reg) self.fcsr,
            }
        }
    }

    fn restore(&mut self) {
        if !self.status.contains(FloatStatus::TRAP_RELOAD) {
            return;
        }
        self.status.remove(FloatStatus::TRAP_RELOAD);
        unsafe {
            asm! {
            "fld  f0,  0*8({0})",
            "fld  f1,  1*8({0})",
            "fld  f2,  2*8({0})",
            "fld  f3,  3*8({0})",
            "fld  f4,  4*8({0})",
            "fld  f5,  5*8({0})",
            "fld  f6,  6*8({0})",
            "fld  f7,  7*8({0})",
            "fld  f8,  8*8({0})",
            "fld  f9,  9*8({0})",
            "fld f10, 10*8({0})",
            "fld f11, 11*8({0})",
            "fld f12, 12*8({0})",
            "fld f13, 13*8({0})",
            "fld f14, 14*8({0})",
            "fld f15, 15*8({0})",
            "fld f16, 16*8({0})",
            "fld f17, 17*8({0})",
            "fld f18, 18*8({0})",
            "fld f19, 19*8({0})",
            "fld f20, 20*8({0})",
            "fld f21, 21*8({0})",
            "fld f22, 22*8({0})",
            "fld f23, 23*8({0})",
            "fld f24, 24*8({0})",
            "fld f25, 25*8({0})",
            "fld f26, 26*8({0})",
            "fld f27, 27*8({0})",
            "fld f28, 28*8({0})",
            "fld f29, 29*8({0})",
            "fld f30, 30*8({0})",
            "fld f31, 31*8({0})",
            "csrw fcsr, {1}",
            in(reg) self,
            in(reg) self.fcsr,
            }
        }
    }
}
