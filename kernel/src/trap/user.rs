use core::mem::size_of;
use log::{debug, error, info, trace};
use riscv::register::{scause, sepc, stval};
use riscv::register::scause::{Exception, Interrupt, Trap};
use riscv::register::sstatus::FS;
use crate::arch::VirtAddr;
use crate::config::TRAMPOLINE_BASE;
use crate::driver::BOARD_INFO;
use crate::mm::addr_space::ASPerms;
use crate::mm::protect::user_slice_w;
use crate::processor::{current_process, current_thread, current_trap_ctx};
use crate::processor::hart::local_hart;
use crate::result::Errno;
use crate::sched::time::set_next_trigger;
use crate::sched::timer::query_timer;
use crate::sched::yield_now;
use crate::signal::ffi::{SigActionFlags, Signal, UContext};
use crate::signal::SignalHandler;
use crate::syscall::syscall;
use crate::trap::{__restore_to_user, set_kernel_trap_entry, set_user_trap_entry};

pub fn trap_return() {
    local_hart().disable_kintr();
    set_user_trap_entry();
    current_thread().event_bus.reset();
    let inner = current_thread().inner();
    let trap_ctx = &mut inner.trap_ctx;
    inner.sys_can_restart = false;

    // if local_hart().ctx.timer_during_sys > 1 {
    //     warn!(
    //         "Timer interrupt in kernel: {}, syscall: {:?}",
    //         local_hart().ctx.timer_during_sys,
    //         local_hart().ctx.last_syscall,
    //     );
    // }

    local_hart().ctx.timer_during_sys = 0;
    trace!("Trap return to user, pc: {:#x}", trap_ctx.get_pc());

    unsafe {
        inner.rusage.trap_out();

        trap_ctx.fctx.trap_out();
        trap_ctx.sstatus.set_fs(FS::Clean);
        __restore_to_user(trap_ctx);
        trap_ctx.fctx.trap_in(trap_ctx.sstatus);

        inner.rusage.trap_in();
    }
}

pub async fn trap_from_user() {
    set_kernel_trap_entry();
    let stval = stval::read();
    let sepc = sepc::read();
    let trap = scause::read().cause();
    local_hart().enable_kintr();
    trace!("Trap {:?} from user at {:#x} for {:#x}", trap, sepc, stval);

    match trap {
        Trap::Exception(Exception::UserEnvCall) => {
            let ctx = current_trap_ctx();
            // syscall 完成后，需要跳转到下一条指令
            ctx.set_pc(ctx.get_pc() + 4);
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
            current_thread().inner().sys_last_a0 = ctx.user_x[10];
            ctx.user_x[10] = result.unwrap_or_else(|err| -(err as isize) as usize);
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
            handle_page_fault(VirtAddr(stval), ASPerms::X);
        }
        Trap::Exception(Exception::Breakpoint) => {
            error!("Breakpoint at {:#x}", stval);
            current_thread().recv_signal(Signal::SIGTRAP);
        }
        Trap::Interrupt(Interrupt::SupervisorTimer) => {
            query_timer();
            set_next_trigger();
            yield_now().await;
        }
        Trap::Interrupt(Interrupt::SupervisorExternal) => {
            BOARD_INFO.plic.handle_irq(local_hart().id);
        }
        _ => {
            error!("Unhandled trap: {:?}", trap);
            current_thread().recv_signal(Signal::SIGSEGV);
        }
    }
}

pub fn check_signal() {
    while let Some(poll) = current_thread().signals.poll() {
        let trap_ctx = current_trap_ctx();
        info!("Handle signal {:?} at {:#x}", poll.signal, trap_ctx.get_pc());
        match poll.handler {
            SignalHandler::Kernel(f) => {
                f(poll.signal);
                current_thread().signals.set_mask(poll.blocked_before);
            }
            SignalHandler::User(sig_action) => {
                debug!("Switch pc to {:#x}", sig_action.sa_handler);
                // 重启系统调用
                if current_thread().inner().sys_can_restart
                    && sig_action.sa_flags.contains(SigActionFlags::SA_RESTART) {
                    info!("Restart syscall after signal");
                    trap_ctx.user_x[10] = current_thread().inner().sys_last_a0;
                    trap_ctx.set_pc(trap_ctx.get_pc() - 4);
                }
                trap_ctx.fctx.signal_enter();
                let ucontext = UContext::new(poll.blocked_before, trap_ctx);
                let user_sp = trap_ctx.get_sp() - size_of::<UContext>();
                if let Err(e) = user_slice_w(user_sp, size_of::<UContext>()) {
                    todo!("Stack Overflow: {:?}", e)
                }
                unsafe { (user_sp as *mut UContext).write(ucontext); }

                trap_ctx.set_pc(sig_action.sa_handler);
                trap_ctx.set_sp(user_sp);
                trap_ctx.user_x[10] = poll.signal as usize;
                trap_ctx.user_x[12] = user_sp;
                trap_ctx.user_x[1] = match sig_action.sa_flags.contains(SigActionFlags::SA_RESTORER) {
                    true => sig_action.sa_restorer,
                    false => TRAMPOLINE_BASE.0,
                };
            }
        }
    }
}

fn handle_page_fault(addr: VirtAddr, perform: ASPerms) {
    debug!("User page fault at {:?} for {}", addr, perform);
    let res = current_process().inner.lock()
        .addr_space.lock()
        .handle_page_fault(addr, perform);
    match res {
        Ok(()) => debug!("Page fault resolved"),
        Err(Errno::ENOSPC) => {
            error!("Fatal page fault: Out of memory, kill process");
            current_process().terminate(Errno::ENOSPC as u32 + 128);
        }
        Err(e) => {
            info!("Failed to resolve page fault, send SIGSEGV: {:?}", e);
            current_thread().recv_signal(Signal::SIGSEGV);
        }
    }
}

#[cfg(feature = "tombstone")]
pub fn dump_tombstone(signal: Signal) {
    if signal != Signal::SIGSEGV {
        return;
    }
    error!("═════ Thread {} terminated with signal {:?} ═════", current_thread().tid.0, signal);
    error!("Registers:");
    let ctx = current_trap_ctx();
    error!("  pc: {:#x}", ctx.get_pc());
    error!("  sp: {:#x}", ctx.get_sp());
    error!("  ra: {:#x}", ctx.user_x[1]);
    error!("Backtrace:");
    error!("todo");
    error!("═════ End of stack trace ═════");
}

#[cfg(not(feature = "tombstone"))]
pub fn dump_tombstone(_signal: Signal) {
    // do nothing
}
