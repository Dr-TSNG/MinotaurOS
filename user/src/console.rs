use core::fmt::{self};
use crate::syscall::{sys_read, sys_write};

const STDIN: i32 = 0;
const STDOUT: i32 = 1;

pub fn print(args: fmt::Arguments) {
    let fmt = alloc::fmt::format(args);
    sys_write(STDOUT, fmt.as_bytes());
}

#[macro_export]
macro_rules! print {
    ($fmt: literal $(, $($arg: tt)+)?) => {
        $crate::console::print(format_args!($fmt $(, $($arg)+)?));
    }
}

#[macro_export]
macro_rules! println {
    ($fmt: literal $(, $($arg: tt)+)?) => {
        $crate::console::print(format_args!(concat!($fmt, "\n") $(, $($arg)+)?));
    }
}

pub fn getchar() -> u8 {
    let mut c = [0u8; 1];
    sys_read(STDIN, &mut c);
    c[0]
}
