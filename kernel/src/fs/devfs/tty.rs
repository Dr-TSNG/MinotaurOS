use alloc::sync::Arc;
use crate::fs::file::File;
use crate::sync::once::LateInit;

pub static DEFAULT_TTY: LateInit<Arc<dyn File>> = LateInit::new();
