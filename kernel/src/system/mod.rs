pub mod ffi;

use crate::config::MAX_PID_DEFAULT;
use crate::sync::mutex::Mutex;

pub static PID_MAX: Mutex<usize> = Mutex::new(MAX_PID_DEFAULT);
