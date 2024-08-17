use core::sync::atomic::AtomicU32;

pub mod dw_apb_uart;
pub mod ns16550a;

static CHAR_TTY_COUNTER: AtomicU32 = AtomicU32::new(0);
