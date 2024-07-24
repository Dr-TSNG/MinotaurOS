use core::arch::asm;
use log::{debug, error};
use riscv::register::{scause, sepc, stval};
use riscv::register::scause::{Exception, Trap};
use crate::arch::VirtAddr;
use crate::mm::addr_space::ASPerms;
use crate::processor::current_thread;
use crate::processor::hart::local_hart;
use crate::result::{Errno, SyscallResult};
use crate::signal::ffi::Signal;

#[no_mangle]
fn trap_from_kernel() -> bool {
    let stval = stval::read();
    let sepc = sepc::read();
    let trap = scause::read().cause();
    debug!("Trap {:?} from kernel at {:#x} for {:#x}", trap, sepc, stval);
    local_hart().ctx.last_kernel_trap = match trap {
        | Trap::Exception(Exception::LoadFault)
        | Trap::Exception(Exception::LoadPageFault) => {
            handle_page_fault(VirtAddr(stval), ASPerms::R)
        }
        Trap::Exception(Exception::StoreFault)
        | Trap::Exception(Exception::StorePageFault) => {
            handle_page_fault(VirtAddr(stval), ASPerms::W)
        }
        Trap::Exception(Exception::InstructionFault)
        | Trap::Exception(Exception::InstructionPageFault) => {
            handle_page_fault(VirtAddr(sepc), ASPerms::X)
        }
        _ => {
            panic!("Fatal");
        }
    };
    local_hart().ctx.page_test
}

fn handle_page_fault(addr: VirtAddr, perform: ASPerms) -> SyscallResult {
    debug!("Kernel page fault at {:?} for {:?}", addr, perform);
    let thread = local_hart()
        .current_thread()
        .expect("Page fault while running kernel thread");
    let res = thread.process.inner.lock().addr_space.handle_page_fault(addr, perform);
    match res {
        Ok(()) => debug!("Page fault resolved"),
        Err(Errno::ENOSPC) => {
            error!("Fatal page fault: Out of memory, kill process");
            thread.process.terminate(-1);
        }
        Err(e) => {
            error!("Page fault failed: {:?}, send SIGSEGV", e);
            current_thread().recv_signal(Signal::SIGSEGV);
        }
    };
    res
}
