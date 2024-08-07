use log::debug;
use crate::arch::VirtAddr;
use crate::mm::protect::{user_transmute_r, user_transmute_w};
use crate::process::thread::event_bus::Event;
use crate::processor::{current_thread, current_trap_ctx};
use crate::result::{Errno, SyscallResult};
use crate::signal::ffi::{SIG_DFL, SIG_IGN, SigAction, Signal, SigSet, SigSetOp, UContext};
use crate::signal::SignalHandler;

pub async fn sys_rt_sigsuspend(mask: usize) -> SyscallResult<usize> {
    let mask = *user_transmute_r::<SigSet>(mask)?.ok_or(Errno::EINVAL)?;
    debug!("[sigsuspend] mask: {:?}", mask);
    let mask_bak = current_thread().signals.get_mask();
    current_thread().signals.set_mask(mask);
    current_thread().event_bus.wait(Event::all()).await;
    // todo: 立即恢复 mask 是否正确？
    current_thread().signals.set_mask(mask_bak);
    Err(Errno::EINTR)
}

pub fn sys_rt_sigaction(sig: i32, act: usize, oact: usize) -> SyscallResult<usize> {
    let signal = Signal::try_from(sig as usize).map_err(|_| Errno::EINVAL)?;
    debug!("[sigaction] signal: {:?} new: {}", signal, act != 0);
    if signal == Signal::SIGKILL || signal == Signal::SIGSTOP {
        return Err(Errno::EINVAL);
    }
    
    if let Some(oact) = user_transmute_w::<SigAction>(oact)? {
        let sig_action = match current_thread().signals.get_handler(signal) {
            SignalHandler::User(sig_action) => sig_action,
            SignalHandler::Kernel(_) => SigAction::default(),
        };
        *oact  = sig_action;
    }

    if let Some(act) = user_transmute_r::<SigAction>(act)? {
        let new_handler = match act.sa_handler {
            SIG_DFL => SignalHandler::kernel(signal),
            SIG_IGN => SignalHandler::Kernel(SignalHandler::k_ignore),
            _ => SignalHandler::User(*act),
        };
        current_thread().signals.set_handler(signal, new_handler);
    }

    Ok(0)
}

pub fn sys_rt_sigprocmask(how: i32, nset: usize, oset: usize) -> SyscallResult<usize> {
    let mut mask = current_thread().signals.get_mask();

    if let Some(oset) = user_transmute_w::<SigSet>(oset)? {
        *oset = mask;
    }

    if let Some(nset) = user_transmute_r::<SigSet>(nset)? {
        let how = SigSetOp::try_from(how).map_err(|_| Errno::EINVAL)?;
        debug!("[sigprocmask] how: {:?} nset: {:?} oset: {:?}", how, nset, mask);
        match how {
            SigSetOp::BLOCK => mask.insert(*nset),
            SigSetOp::SETMASK => mask = *nset,
            SigSetOp::UNBLOCK => mask.remove(*nset),
        }
        current_thread().signals.set_mask(mask);
    }

    Ok(0)
}

pub fn sys_rt_sigtimedwait(_uset: usize, _uinfo: usize, _uts: usize) -> SyscallResult<usize> {
    // TODO: implement sys_rt_sigtimedwait
    Ok(0)
}

pub fn sys_rt_sigreturn() -> SyscallResult<usize> {
    let trap_ctx = current_trap_ctx();
    let user_sp = VirtAddr(trap_ctx.get_sp());
    let ucontext = unsafe { user_sp.as_ptr().cast::<UContext>().read() };
    current_thread().signals.set_mask(ucontext.uc_sigmask);
    trap_ctx.user_x = ucontext.uc_mcontext;
    trap_ctx.fctx.signal_exit(&ucontext.uc_fcontext);
    debug!("[sigreturn] return to user for {:#x?}", trap_ctx.get_pc());
    Ok(trap_ctx.user_x[10])
}
