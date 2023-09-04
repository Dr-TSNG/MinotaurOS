use core::fmt::{self, Write};
use spin::Mutex;
use crate::arch::rv64;

struct Stdout;

impl Write for Stdout {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        rv64::sbi::console_write(s).unwrap();
        Ok(())
    }
}

static STDOUT: Mutex<Stdout> = Mutex::new(Stdout);

pub fn print(args: fmt::Arguments) {
    STDOUT.lock().write_fmt(args).unwrap();
}

#[macro_export]
macro_rules! print {
    ($fmt: literal $(, $($arg: tt)+)?) => {
        $crate::arch::console::print(format_args!($fmt $(, $($arg)+)?));
    }
}

#[macro_export]
macro_rules! println {
    ($fmt: literal $(, $($arg: tt)+)?) => {
        $crate::arch::console::print(format_args!(concat!($fmt, "\n") $(, $($arg)+)?));
    }
}
