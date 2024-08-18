use bitflags::bitflags;
use num_enum::TryFromPrimitive;
use zerocopy::{AsBytes, FromBytes, FromZeroes};
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
    SIGRTMIN = 32,
    SIGCANCEL = 33,
    SIG34 = 34,
    SIG35 = 35,
    SIG36 = 36,
    SIG37 = 37,
    SIG38 = 38,
    SIG39 = 39,
    SIG40 = 40,
    SIG41 = 41,
    SIG42 = 42,
    SIG43 = 43,
    SIG44 = 44,
    SIG45 = 45,
    SIG46 = 46,
    SIG47 = 47,
    SIG48 = 48,
    SIG49 = 49,
    SIG50 = 50,
    SIG51 = 51,
    SIG52 = 52,
    SIG53 = 53,
    SIG54 = 54,
    SIG55 = 55,
    SIG56 = 56,
    SIG57 = 57,
    SIG58 = 58,
    SIG59 = 59,
    SIG60 = 60,
    SIG61 = 61,
    SIG62 = 62,
}

pub const SIG_MAX: usize = 63;
pub const SIG_DFL: usize = 0;
pub const SIG_IGN: usize = 1;

impl Signal {
    const fn sigset_val(&self) -> u64 {
        1 << (*self as u32 - 1)
    }
}

#[repr(transparent)]
#[derive(Copy, Clone, Default, Debug, AsBytes, FromZeroes, FromBytes)]
pub struct SigSet(u64);

bitflags! {
    impl SigSet: u64 {
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
        const SIGRTMIN  = Signal::SIGRTMIN.sigset_val();
        const SIGCANCEL = Signal::SIGCANCEL.sigset_val();
    }
}

impl From<Signal> for SigSet {
    fn from(value: Signal) -> Self {
        Self::from_bits_retain(value.sigset_val())
    }
}

#[derive(Debug, TryFromPrimitive)]
#[repr(i32)]
pub enum SigSetOp {
    BLOCK = 0,
    UNBLOCK = 1,
    SETMASK = 2,
}

#[derive(Clone, Copy, Default, AsBytes, FromZeroes, FromBytes)]
#[repr(C)]
pub struct SigAction {
    pub sa_handler: usize,
    pub sa_flags: SigActionFlags,
    _pad: u32,
    pub sa_restorer: usize,
    pub sa_mask: SigSet,
}

#[repr(transparent)]
#[derive(Copy, Clone, Default, AsBytes, FromZeroes, FromBytes)]
pub struct SigActionFlags(u32);

bitflags! {
    impl SigActionFlags: u32 {
        const SA_NOCLDSTOP = 1;
        const SA_NOCLDWAIT = 2;
        const SA_SIGINFO   = 4;
        const SA_RESTORER  = 0x04000000;
        const SA_ONSTACK   = 0x08000000;
        const SA_RESTART   = 0x10000000;
        const SA_NODEFER   = 0x40000000;
        const SA_RESETHAND = 0x80000000;
    }
}

#[repr(C)]
pub struct UContext {
    pub uc_flags: usize,
    pub uc_link: usize,
    pub uc_stack: SignalStack,
    pub uc_sigmask: SigSet,
    _unused: [u8; 128],
    pub uc_mcontext: [usize; 32],
    pub uc_fcontext: [f64; 32],
}

#[repr(C)]
#[derive(Default)]
pub struct SignalStack {
    ss_sp: usize,
    ss_flags: i32,
    ss_size: usize,
}

impl UContext {
    pub fn new(sigmask: SigSet, trap_ctx: &TrapContext) -> Self {
        Self {
            uc_flags: 0,
            uc_link: 0,
            uc_stack: SignalStack::default(),
            uc_sigmask: sigmask,
            _unused: [0; 128],
            uc_mcontext: trap_ctx.user_x,
            uc_fcontext: trap_ctx.fctx.user_f,
        }
    }
}
