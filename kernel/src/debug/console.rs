use alloc::fmt;
use core::fmt::Arguments;
use crate::fs::devfs::tty::TTY;
use crate::fs::file::File;
use crate::sync::block_on;

pub fn print(args: Arguments) {
    let fmt = fmt::format(args);
    let _ = block_on(TTY.write(fmt.as_bytes()));
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
