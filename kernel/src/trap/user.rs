use log::{debug, error};
use riscv::register::{scause, sepc, stval};
use riscv::register::scause::{Exception, Interrupt, Trap};
use crate::arch::VirtAddr;
use crate::mm::addr_space::ASPerms;
use crate::processor::{current_process, current_thread, current_trap_ctx};
use crate::sched::time::set_next_trigger;
use crate::sched::yield_now;
use crate::syscall::syscall;
use crate::trap::{__restore_to_user, set_kernel_trap_entry, set_user_trap_entry};

pub fn trap_return() {
    set_user_trap_entry();
    debug!("Trap return to user");
    unsafe {
        current_thread().inner().rusage.trap_out();
        __restore_to_user(current_trap_ctx());
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
        Trap::Exception(Exception::UserEnvCall) => {
            let ctx = current_trap_ctx();
            // syscall 完成后，需要跳转到下一条指令
            ctx.sepc += 4;
            let result = syscall(
                ctx.user_x[17],
                [
                    ctx.user_x[10],
                    ctx.user_x[11],
                    ctx.user_x[12],
                    ctx.user_x[13],
                    ctx.user_x[14],
                    ctx.user_x[15],
                ],
            ).await;
            ctx.user_x[10] = result.unwrap_or_else(|err| -(err as isize) as usize)
        }
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
        Trap::Interrupt(Interrupt::SupervisorTimer) => {
            debug!("Timer interrupt");
            set_next_trigger();
            yield_now().await;
        }
        _ => {
            panic!("Fatal");
        }
    }
}

fn handle_page_fault(addr: VirtAddr, perform: ASPerms) {
    debug!("User page fault at {:?} for {:?}", addr, perform);
    let mut proc_inner = current_process().inner.lock();
    match proc_inner.addr_space.handle_page_fault(addr, perform) {
        Ok(()) => debug!("Page fault resolved"),
        Err(e) => {
            error!("Fatal page fault failed, send SIGSEGV: {:?}", e);
            // current_process().signal(SIGSEGV);
            todo!()
        }
    }
}
