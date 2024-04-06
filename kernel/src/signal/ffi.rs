use core::mem::size_of;
use bitflags::bitflags;
use num_enum::TryFromPrimitive;
use crate::trap::context::TrapContext;

#[derive(Debug, PartialEq, Eq, Clone, Copy, TryFromPrimitive)]
#[repr(usize)]
pub enum Signal {
    None = 0,
    SIGHUP = 1,
    SIGINT = 2,
    SIGQUIT = 3,
    SIGILL = 4,
    SIGTRAP = 5,
    SIGABRT = 6,
    SIGBUS = 7,
    SIGFPE = 8,
    SIGKILL = 9,
    SIGUSR1 = 10,
    SIGSEGV = 11,
    SIGUSR2 = 12,
    SIGPIPE = 13,
    SIGALRM = 14,
    SIGTERM = 15,
    SIGSTKFLT = 16,
    SIGCHLD = 17,
    SIGCONT = 18,
    SIGSTOP = 19,
    SIGTSTP = 20,
    SIGTTIN = 21,
    SIGTTOU = 22,
    SIGURG = 23,
    SIGXCPU = 24,
    SIGXFSZ = 25,
    SIGVTALRM = 26,
    SIGPROF = 27,
    SIGWINCH = 28,
    SIGIO = 29,
    SIGPWR = 30,
    SIGSYS = 31,
}

pub const SIG_MAX: usize = 32;
pub const SIG_ERR: usize = usize::MAX;
pub const SIG_DFL: usize = 0;
pub const SIG_IGN: usize = 1;

impl Signal {
    const fn sigset_val(&self) -> u64 {
        1 << (*self as u32 - 1)
    }
}

bitflags! {
    #[derive(Default)]
    pub struct SigSet: u64 {
        const SIGHUP    = Signal::SIGHUP.sigset_val();
        const SIGINT    = Signal::SIGINT.sigset_val();
        const SIGQUIT   = Signal::SIGQUIT.sigset_val();
        const SIGILL    = Signal::SIGILL.sigset_val();
        const SIGTRAP   = Signal::SIGTRAP.sigset_val();
        const SIGABRT   = Signal::SIGABRT.sigset_val();
        const SIGBUS    = Signal::SIGBUS.sigset_val();
        const SIGFPE    = Signal::SIGFPE.sigset_val();
        const SIGKILL   = Signal::SIGKILL.sigset_val();
        const SIGUSR1   = Signal::SIGUSR1.sigset_val();
        const SIGSEGV   = Signal::SIGSEGV.sigset_val();
        const SIGUSR2   = Signal::SIGUSR2.sigset_val();
        const SIGPIPE   = Signal::SIGPIPE.sigset_val();
        const SIGALRM   = Signal::SIGALRM.sigset_val();
        const SIGTERM   = Signal::SIGTERM.sigset_val();
        const SIGSTKFLT = Signal::SIGSTKFLT.sigset_val();
        const SIGCHLD   = Signal::SIGCHLD.sigset_val();
        const SIGCONT   = Signal::SIGCONT.sigset_val();
        const SIGSTOP   = Signal::SIGSTOP.sigset_val();
        const SIGTSTP   = Signal::SIGTSTP.sigset_val();
        const SIGTTIN   = Signal::SIGTTIN.sigset_val();
        const SIGTTOU   = Signal::SIGTTOU.sigset_val();
        const SIGURG    = Signal::SIGURG.sigset_val();
        const SIGXCPU   = Signal::SIGXCPU.sigset_val();
        const SIGXFSZ   = Signal::SIGXFSZ.sigset_val();
        const SIGVTALRM = Signal::SIGVTALRM.sigset_val();
        const SIGPROF   = Signal::SIGPROF.sigset_val();
        const SIGWINCH  = Signal::SIGWINCH.sigset_val();
        const SIGIO     = Signal::SIGIO.sigset_val();
        const SIGPWR    = Signal::SIGPWR.sigset_val();
        const SIGSYS    = Signal::SIGSYS.sigset_val();
    }
}

impl From<Signal> for SigSet {
    fn from(value: Signal) -> Self {
        unsafe { Self::from_bits_unchecked(value.sigset_val()) }
    }
}

#[derive(TryFromPrimitive)]
#[repr(i32)]
pub enum SigSetOp {
    BLOCK = 0,
    UNBLOCK = 1,
    SETMASK = 2,
}

#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct SigAction {
    pub sa_handler: usize,
    pub sa_flags: u32,
    pub sa_restorer: usize,
    pub sa_mask: SigSet,
}

#[repr(C)]
pub struct UContext {
    pub uc_flags: usize,
    pub uc_link: usize,
    pub uc_stack: SignalStack,
    pub uc_sigmask: SigSet,
    _unused: [u8; 1024 / 8 - size_of::<SigSet>()],
    pub uc_mcontext: [usize; 32],
}

#[repr(C)]
#[derive(Default)]
pub struct SignalStack {
    ss_sp: usize,
    ss_flags: i32,
    ss_size: usize,
}

impl UContext {
    pub fn new(sigmask: SigSet, trap_ctx: TrapContext) -> Self {
        Self {
            uc_flags: 0,
            uc_link: 0,
            uc_stack: SignalStack::default(),
            uc_sigmask: sigmask,
            _unused: [0; 120],
            uc_mcontext: trap_ctx.user_x,
        }
    }    
}
