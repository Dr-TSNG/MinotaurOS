use alloc::fmt;
use core::fmt::Arguments;
use crate::driver::tty::DEFAULT_TTY;
use crate::sync::block_on;

static mut PREINIT_BUF: [u8; 4096] = [0; 4096];
static mut PREINIT_BUF_LEN: usize = 0;

pub fn print(args: Arguments) {
    let fmt = fmt::format(args);
    let bytes = fmt.as_bytes();
    if DEFAULT_TTY.is_initialized() {
        unsafe {
            if PREINIT_BUF_LEN > 0 {
                let preinit_buf = &PREINIT_BUF[..PREINIT_BUF_LEN];
                let _ = block_on(DEFAULT_TTY.write(preinit_buf));
                PREINIT_BUF_LEN = 0;
            }
        }
        let _ = block_on(DEFAULT_TTY.write(bytes));
    } else {
        unsafe {
            PREINIT_BUF[PREINIT_BUF_LEN..PREINIT_BUF_LEN + bytes.len()].copy_from_slice(bytes);
            PREINIT_BUF_LEN += bytes.len();
        }
    }
}

#[macro_export]
macro_rules! print {
    ($fmt: expr $(, $($arg: tt)+)?) => {
        $crate::debug::console::print(format_args!($fmt $(, $($arg)+)?));
    }
}

#[macro_export]
macro_rules! println {
    ($fmt: expr $(, $($arg: tt)+)?) => {
        $crate::debug::console::print(format_args!(concat!($fmt, "\n") $(, $($arg)+)?));
    }
}
