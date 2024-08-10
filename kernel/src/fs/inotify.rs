use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use async_trait::async_trait;
use crate::fs::ffi::{InotifyEvent, OpenFlags};
use crate::fs::file::{File, FileMeta};
use crate::result::SyscallResult;
use crate::sync::mutex::Mutex;

// inotify 用文件名加入监视
pub struct InotifyFile {
    metadata: FileMeta,
    names: Mutex<Vec<String>>,
    events: Arc<Mutex<Vec<InotifyEvent>>>,
}

#[async_trait]
impl File for InotifyFile {
    fn metadata(&self) -> &FileMeta {
        &self.metadata
    }

    async fn read(&self, buf: &mut [u8]) -> SyscallResult<isize> {
        todo!()
    }
}

impl InotifyFile {
    pub fn new() -> Self {
        Self {
            metadata: FileMeta::new(None, OpenFlags::O_RDWR),
            names: Mutex::new(Vec::new()),
            events: Arc::new(Mutex::new(Vec::new())),
        }
    }
}
