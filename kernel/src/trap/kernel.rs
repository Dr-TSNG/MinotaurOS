use log::{debug, error};
use riscv::register::{scause, sepc, stval};
use riscv::register::scause::{Exception, Trap};
use crate::arch::VirtAddr;
use crate::mm::addr_space::ASPerms;
use crate::processor::hart::local_hart;

#[no_mangle]
fn trap_from_kernel() {
    let stval = stval::read();
    let sepc = sepc::read();
    let trap = scause::read().cause();
    debug!("Trap {:?} from kernel at {:#x} for {:#x}", trap, sepc, stval);
    match trap {
        | Trap::Exception(Exception::LoadFault)
        | Trap::Exception(Exception::LoadPageFault) => {
            handle_page_fault(VirtAddr(stval), ASPerms::R);
        }
        Trap::Exception(Exception::StoreFault)
        | Trap::Exception(Exception::StorePageFault) => {
            handle_page_fault(VirtAddr(stval), ASPerms::W);
        }
        Trap::Exception(Exception::InstructionFault)
        | Trap::Exception(Exception::InstructionPageFault) => {
            handle_page_fault(VirtAddr(sepc), ASPerms::X);
        }
        _ => {
            panic!("Fatal");
        }
    }
}

fn handle_page_fault(addr: VirtAddr, perform: ASPerms) {
    debug!("Kernel page fault at {:?} for {:?}", addr, perform);
    let thread = local_hart()
        .current_thread()
        .expect("Page fault while running kernel thread");
    let mut proc_inner = thread.process.inner.lock();
    match proc_inner.addr_space.handle_page_fault(addr, perform) {
        Ok(()) => debug!("Page fault resolved"),
        Err(e) => {
            error!("Fatal page fault failed, send SIGSEGV: {:?}", e);
            // current_process().signal(SIGSEGV);
            todo!()
        }
    }
}
