use core::fmt::{Arguments, Write};
use spin::Mutex;
use crate::board;

pub trait Console: Write {
    fn try_init() {}
    fn try_init_late() {}
}

static CONSOLE: Mutex<board::ConsoleImpl> = Mutex::new(board::ConsoleImpl);

pub fn try_init() {
    board::ConsoleImpl::try_init();
}

pub fn try_init_late() {
    board::ConsoleImpl::try_init_late();
}

pub fn print(args: Arguments) {
    CONSOLE.lock().write_fmt(args).unwrap();
}

#[macro_export]
macro_rules! print {
    ($fmt: literal $(, $($arg: tt)+)?) => {
        $crate::debug::console::print(format_args!($fmt $(, $($arg)+)?));
    }
}

#[macro_export]
macro_rules! println {
    ($fmt: literal $(, $($arg: tt)+)?) => {
        $crate::debug::console::print(format_args!(concat!($fmt, "\n") $(, $($arg)+)?));
    }
}
