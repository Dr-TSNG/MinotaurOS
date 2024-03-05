use log::debug;
use riscv::register::{scause, sepc, stval};
use riscv::register::scause::{Exception, Trap};

#[no_mangle]
fn trap_from_kernel() {
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
