use crate::fs::devfs::tty::DEFAULT_TTY;
use alloc::collections::VecDeque;
use alloc::fmt;
use alloc::string::String;
use alloc::sync::Arc;
use core::fmt::Arguments;
use lazy_static::lazy_static;

use crate::sync::block_on;
use crate::sync::mutex::Mutex;

const MAX_LINES: usize = 80;

#[derive(Default)]
pub struct DiagMessage {
    pub start: usize,
    pub current: usize,
    pub buf: VecDeque<Arc<String>>,
}

lazy_static! {
    pub static ref DMESG: Mutex<DiagMessage> = Mutex::default();
}

pub fn print(args: Arguments) {
    let fmt = fmt::format(args);
    DMESG.lock().apply_mut(|dmesg| {
        dmesg.buf.push_back(Arc::new(fmt));
        if dmesg.buf.len() > MAX_LINES {
            dmesg.start += 1;
            dmesg.buf.pop_front();
        }
    });
    if DEFAULT_TTY.is_initialized() {
        dmesg_flush_tty();
    }
}

pub fn dmesg_flush_tty() {
    let mut dmesg = DMESG.lock();
    while dmesg.current < dmesg.start + dmesg.buf.len() {
        let bytes = dmesg.buf[dmesg.current - dmesg.start].as_bytes();
        let _ = block_on(DEFAULT_TTY.write(bytes));
        dmesg.current += 1;
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
