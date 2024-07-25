use log::{debug, error, trace};
use riscv::register::{scause, sepc, stval};
use riscv::register::scause::{Exception, Interrupt, Trap};
use crate::arch::VirtAddr;
use crate::driver::BOARD_INFO;
use crate::mm::addr_space::ASPerms;
use crate::processor::current_thread;
use crate::processor::hart::local_hart;
use crate::result::{Errno, SyscallResult};
use crate::sched::time::set_next_trigger;
use crate::sched::timer::query_timer;
use crate::signal::ffi::Signal;

#[no_mangle]
fn trap_from_kernel() -> bool {
    local_hart().on_kintr = true;
    let stval = stval::read();
    let sepc = sepc::read();
    let trap = scause::read().cause();
    trace!("Trap {:?} from kernel at {:#x} for {:#x}", trap, sepc, stval);
    match trap {
        | Trap::Exception(Exception::LoadFault)
        | Trap::Exception(Exception::LoadPageFault) => {
            local_hart().last_page_fault = handle_page_fault(VirtAddr(stval), ASPerms::R);
        }
        Trap::Exception(Exception::StoreFault)
        | Trap::Exception(Exception::StorePageFault) => {
            local_hart().last_page_fault = handle_page_fault(VirtAddr(stval), ASPerms::W);
        }
        Trap::Exception(Exception::InstructionFault)
        | Trap::Exception(Exception::InstructionPageFault) => {
            local_hart().last_page_fault = handle_page_fault(VirtAddr(sepc), ASPerms::X);
        }
        Trap::Interrupt(Interrupt::SupervisorTimer) => {
            local_hart().timer_during_sys += 1;
            query_timer();
            set_next_trigger();
        }
        Trap::Interrupt(Interrupt::SupervisorExternal) => {
            BOARD_INFO.plic.handle_irq(local_hart().id);
        }
        _ => {
            panic!("Fatal");
        }
    }
    local_hart().on_kintr = false;
    local_hart().on_page_test
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
