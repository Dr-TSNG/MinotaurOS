pub mod context;
mod kernel;
pub mod user;

use crate::trap::context::TrapContext;
use core::arch::global_asm;
use riscv::register::stvec;
use riscv::register::stvec::TrapMode;

global_asm!(include_str!("trap.asm"));

extern "C" {
    fn __trap_from_kernel();
    fn __trap_from_user();
    fn __restore_to_user(ctx: *mut TrapContext);
}

pub fn init() {
    set_kernel_trap_entry();
}

fn set_kernel_trap_entry() {
    unsafe {
        stvec::write(__trap_from_kernel as usize, TrapMode::Direct);
    }
}

fn set_user_trap_entry() {
    unsafe {
        stvec::write(__trap_from_user as usize, TrapMode::Direct);
    }
}
