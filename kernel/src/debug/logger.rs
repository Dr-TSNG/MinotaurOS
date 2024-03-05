use log::{Level, LevelFilter, Metadata, Record};
use crate::processor::hart::local_hart;

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

struct SimpleLogger;

impl log::Log for SimpleLogger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }
    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            match local_hart().current_thread() {
                Some(thread) => {
                    println!(
                        "\x1b[{}m[{:5}] tid {} | {}\x1b[0m",
                        level_color(record.level()),
                        record.level(),
                        thread.tid.0,
                        record.args()
                    );
                }
                None => {
                    println!(
                        "\x1b[{}m[{:5}] kernel | {}\x1b[0m",
                        level_color(record.level()),
                        record.level(),
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
