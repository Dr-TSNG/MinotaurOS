use core::mem::size_of;
use log::{debug, error, info, trace};
use riscv::register::{scause, sepc, stval};
use riscv::register::scause::{Exception, Interrupt, Trap};
use crate::arch::VirtAddr;
use crate::config::TRAMPOLINE_BASE;
use crate::mm::addr_space::ASPerms;
use crate::processor::{current_process, current_thread, current_trap_ctx};
use crate::sched::time::set_next_trigger;
use crate::sched::yield_now;
use crate::signal::ffi::UContext;
use crate::signal::SignalHandler;
use crate::syscall::syscall;
use crate::trap::{__restore_to_user, set_kernel_trap_entry, set_user_trap_entry};

pub fn trap_return() {
    set_user_trap_entry();
    trace!("Trap return to user");

    check_signal();

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

fn check_signal() {
    if let Some(poll) = current_thread().signals.poll() {
        info!("Handle signal {:?}", poll.signal);
        match poll.handler {
            SignalHandler::Kernel(f) => f(poll.signal),
            SignalHandler::User(sig_action) => {
                let trap_ctx = current_trap_ctx();
                let ucontext = UContext::new(poll.blocked_before, trap_ctx.clone());
                let mut user_sp = VirtAddr(trap_ctx.get_sp());
                if let Err(e) = current_process()
                    .inner.lock().addr_space
                    .user_slice_w(user_sp, size_of::<UContext>()) {
                    todo!("Stack Overflow: {:?}", e)
                }
                user_sp = user_sp - size_of::<UContext>();
                unsafe { user_sp.as_ptr().cast::<UContext>().write(ucontext); }

                trap_ctx.sepc = sig_action.sa_handler;
                trap_ctx.user_x[10] = poll.signal as usize;
                trap_ctx.user_x[12] = user_sp.0;
                trap_ctx.user_x[1] = match sig_action.sa_restorer {
                    0 => TRAMPOLINE_BASE.0,
                    _ => sig_action.sa_restorer,
                }
            }
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
