use log::debug;
use riscv::register::{scause, sepc, stval};
use riscv::register::scause::{Exception, Trap};
use crate::processor::current_thread;
use crate::trap::{__restore_to_user, set_kernel_trap_entry, set_user_trap_entry};

pub fn trap_return() {
    set_user_trap_entry();
    debug!("Trap return to user");
    unsafe {
        current_thread().inner().rusage.trap_out();
        __restore_to_user(&mut current_thread().inner().trap_ctx);
        current_thread().inner().rusage.trap_in();
    }
}

pub async fn trap_from_user() {
    set_kernel_trap_entry();
    let stval = stval::read();
    let sepc = sepc::read();
    let trap = scause::read().cause();
    debug!("Trap {:?} from user at {:#x} for {:#x}", trap, sepc, stval);
    match trap {
        Trap::Exception(Exception::StoreFault) => {
            todo!("page fault handler")
        }
        _ => {
            panic!("Fatal");
        }
    }
}
