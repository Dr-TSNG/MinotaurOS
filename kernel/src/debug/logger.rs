use log::{Level, LevelFilter, Metadata, Record};
use crate::processor::hart::local_hart;
use crate::sched::time::cpu_time;

#[cfg(feature = "error")]
const LOG_LEVEL: LevelFilter = LevelFilter::Error;
#[cfg(feature = "warn")]
const LOG_LEVEL: LevelFilter = LevelFilter::Warn;
#[cfg(feature = "info")]
const LOG_LEVEL: LevelFilter = LevelFilter::Info;
#[cfg(feature = "debug")]
const LOG_LEVEL: LevelFilter = LevelFilter::Debug;
#[cfg(feature = "trace")]
const LOG_LEVEL: LevelFilter = LevelFilter::Trace;
#[cfg(not(any(feature = "error", feature = "warn", feature = "info", feature = "debug", feature = "trace")))]
const LOG_LEVEL: LevelFilter = LevelFilter::Off;

#[macro_export]
#[cfg(feature = "nocolor")]
macro_rules! with_color {
    ($color_code: expr, $fmt: expr $(, $($arg: tt)+)?) => {
        use crate::println;
        println!($fmt, $($($arg)+)?);
    }
}

#[macro_export]
#[cfg(not(feature = "nocolor"))]
macro_rules! with_color {
    ($color_code: expr, $fmt: expr $(, $($arg: tt)+)?) => {
        use crate::println;
        println!(
            concat!("\x1b[{}m", $fmt, "\x1b[0m"),
            $color_code,
            $($($arg)+)?
        );
    }
}

struct SimpleLogger;

impl log::Log for SimpleLogger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }
    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            match local_hart().current_thread() {
                Some(thread) => {
                    with_color!(
                        level_color(record.level()),
                        "[{:6?}] [{:5}] [HART {}] [{}, {}] | {}",
                        cpu_time(),
                        record.level(),
                        local_hart().id,
                        thread.process.pid.0,
                        thread.tid.0,
                        record.args()
                    );
                }
                None => {
                    with_color!(
                        level_color(record.level()),
                        "[{:6?}] [{:5}] [HART {}] kernel | {}",
                        cpu_time(),
                        record.level(),
                        local_hart().id,
                        record.args(),
                    );
                }
            }
        }
    }
    fn flush(&self) {}
}

static LOGGER: SimpleLogger = SimpleLogger;

pub fn init() {
    log::set_logger(&LOGGER)
        .map(|()| log::set_max_level(LOG_LEVEL))
        .unwrap();
}

fn level_color(level: Level) -> u8 {
    match level {
        Level::Error => 31,
        Level::Warn => 93,
        Level::Info => 34,
        Level::Debug => 32,
        Level::Trace => 90,
    }
}

#[allow(unused)]
pub const STRACE_COLOR_CODE: u8 = 35; // Purple

#[macro_export]
#[cfg(feature = "strace")]
macro_rules! strace {
    ($fmt: literal $(, $($arg: tt)+)?) => {{
        use crate::{
            with_color,
            processor::{current_process, current_thread},
            processor::hart::local_hart,
            sched::time::cpu_time,
        };
        with_color!(
            crate::debug::logger::STRACE_COLOR_CODE,
            concat!("[{:6?}] [SCALL] [HART {}] [{}, {}] | ", $fmt),
            cpu_time(),
            local_hart().id,
            current_process().pid.0,
            current_thread().tid.0
            $(, $($arg)+)?,
        );
    }}
}

#[macro_export]
#[cfg(not(feature = "strace"))]
macro_rules! strace {
    ($fmt: literal $(, $($arg: tt)+)?) => {};
}
