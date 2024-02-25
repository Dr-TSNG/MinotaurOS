pub mod context;

use core::arch::global_asm;
use log::debug;
use riscv::register::{scause, sepc, stval, stvec};
use riscv::register::scause::{Exception, Trap};
use riscv::register::stvec::TrapMode;

global_asm!(include_str!("trap.asm"));

extern {
    fn __trap_from_kernel();
    fn __trap_from_user();
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

#[no_mangle]
pub fn trap_from_kernel() {
    let stval = stval::read();
    let sepc = sepc::read();
    let trap = scause::read().cause();
    debug!("Trap {:?} from kernel at {:#x} for {:#x}", trap, sepc, stval);
    match trap {
        Trap::Exception(Exception::StoreFault) => {
            todo!("page fault handler")
        }
        _ => {
            panic!("Fatal");
        }
    }
}
