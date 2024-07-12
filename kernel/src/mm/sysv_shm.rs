use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use crate::mm::allocator::{alloc_user_frames, IdAllocator, UserFrameTracker};
use crate::result::SyscallResult;

#[derive(Default)]
pub struct SysVShm {
    ids: IdAllocator,
    shm: BTreeMap<usize, Vec<Arc<UserFrameTracker>>>,
}

impl SysVShm {
    pub fn alloc(&mut self, pages: usize) -> SyscallResult<usize> {
        let id = self.ids.alloc();
        let mut shm = vec![];
        for _ in 0..pages {
            let frame = alloc_user_frames(1)?;
            shm.push(Arc::new(frame));
        }
        self.shm.insert(id, shm);
        Ok(id)
    }

    pub fn get(&self, id: usize) -> Option<Vec<Arc<UserFrameTracker>>> {
        self.shm.get(&id).cloned()
    }
}
