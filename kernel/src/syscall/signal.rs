use core::mem::size_of;
use crate::arch::VirtAddr;
use crate::processor::{current_process, current_thread, current_trap_ctx};
use crate::result::{Errno, SyscallResult};
use crate::signal::ffi::{SIG_DFL, SIG_IGN, SigAction, Signal, SigSet, SigSetOp, UContext};
use crate::signal::SignalHandler;

pub async fn sys_rt_sigsuspend(mask: usize) -> SyscallResult<usize> {
    let mask = current_process().inner.lock().addr_space.user_slice_r(VirtAddr(mask), size_of::<SigSet>())?;
    let mask = unsafe { mask.as_ptr().cast::<SigSet>().read() };
    let mask_bak = current_thread().signals.get_mask();
    current_thread().signals.set_mask(mask);
    current_thread().signals.suspend().await;
    // todo: 立即恢复 mask 是否正确？
    current_thread().signals.set_mask(mask_bak);
    Err(Errno::EINTR)
}

pub fn sys_rt_sigaction(sig: i32, act: usize, oact: usize) -> SyscallResult<usize> {
    let signal = Signal::try_from(sig as usize).map_err(|_| Errno::EINVAL)?;
    let proc_inner = current_process().inner.lock();

    if oact != 0 {
        let oact = proc_inner.addr_space.user_slice_w(VirtAddr(oact), size_of::<SigAction>())?;
        let sig_action = match current_thread().signals.get_handler(signal) {
            SignalHandler::User(sig_action) => sig_action,
            SignalHandler::Kernel(_) => SigAction::default(),
        };
        unsafe { oact.as_mut_ptr().cast::<SigAction>().write(sig_action); }
    }

    if act != 0 {
        let act = proc_inner.addr_space.user_slice_r(VirtAddr(act), size_of::<SigAction>())?;
        let sig_action = unsafe { act.as_ptr().cast::<SigAction>().read() };
        let new_handler = match sig_action.sa_handler {
            SIG_DFL => SignalHandler::kernel(signal),
            SIG_IGN => SignalHandler::Kernel(SignalHandler::k_ignore),
            _ => SignalHandler::User(sig_action),
        };
        current_thread().signals.set_handler(signal, new_handler);
    }

    Ok(0)
}

pub fn sys_rt_sigprocmask(how: i32, nset: usize, oset: usize) -> SyscallResult<usize> {
    let proc_inner = current_process().inner.lock();
    let mut mask = current_thread().signals.get_mask();

    if oset != 0 {
        let oset = proc_inner.addr_space.user_slice_w(VirtAddr(oset), size_of::<SigSet>())?;
        unsafe { oset.as_mut_ptr().cast::<SigSet>().write(mask); }
    }

    if nset != 0 {
        let nset = proc_inner.addr_space.user_slice_r(VirtAddr(nset), size_of::<SigSet>())?;
        let nset = unsafe { nset.as_ptr().cast::<SigSet>().read() };
        match SigSetOp::try_from(how).map_err(|_| Errno::EINVAL)? {
            SigSetOp::BLOCK => mask.insert(nset),
            SigSetOp::SETMASK => mask = nset,
            SigSetOp::UNBLOCK => mask.remove(nset),
        }
        current_thread().signals.set_mask(mask);
    }

    Ok(0)
}

pub fn sys_rt_sigreturn() -> SyscallResult<usize> {
    let trap_ctx = current_trap_ctx();
    let user_sp = VirtAddr(trap_ctx.get_sp());
    let ucontext = unsafe { user_sp.as_ptr().cast::<UContext>().read() };
    current_thread().signals.set_mask(ucontext.uc_sigmask);
    trap_ctx.user_x = ucontext.uc_mcontext;
    Ok(0)
}
